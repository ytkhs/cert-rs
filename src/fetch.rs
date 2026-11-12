use std::io::ErrorKind;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, OtherError,
    SignatureScheme,
};

use crate::target::{Resolve, lookup_resolve};

pub struct Options {
    pub skip_verify: bool,
    pub timeout: Duration,
    pub resolve: Vec<Resolve>,
}

pub struct Fetched {
    pub chain: Vec<CertificateDer<'static>>,
    pub ip: String,
    /// Why the verifier rejected `chain`; only `fetch_keeping_rejected` sets it.
    pub rejection: Option<String>,
}

pub fn fetch(host: &str, port: &str, opts: &Options) -> Result<Fetched, String> {
    let config = client_config(opts.skip_verify)?;
    fetch_with_config(host, port, opts, config)
}

pub fn fetch_with_config(
    host: &str,
    port: &str,
    opts: &Options,
    config: Arc<ClientConfig>,
) -> Result<Fetched, String> {
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| format!("invalid server name {host:?}: {e}"))?;
    let addrs = resolve_addrs(host, port, opts)?;
    // The deadline starts after resolution: std offers no way to bound getaddrinfo.
    // A zero or unrepresentable timeout means no limit.
    let deadline = if opts.timeout.is_zero() {
        None
    } else {
        Instant::now().checked_add(opts.timeout)
    };
    fetch_from_addrs(
        &format!("{host}:{port}"),
        server_name,
        &addrs,
        deadline,
        config,
    )
}

fn resolve_addrs(host: &str, port: &str, opts: &Options) -> Result<Vec<SocketAddr>, String> {
    let port_num: u16 = port.parse().map_err(|_| format!("invalid port {port:?}"))?;
    if let Some(ip) = lookup_resolve(&opts.resolve, host, port) {
        return Ok(vec![SocketAddr::new(ip, port_num)]);
    }
    let addrs: Vec<SocketAddr> = (host, port_num)
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve {host}: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("no addresses found for {host}"));
    }
    Ok(addrs)
}

fn fetch_from_addrs(
    target: &str,
    server_name: ServerName<'static>,
    addrs: &[SocketAddr],
    deadline: Option<Instant>,
    config: Arc<ClientConfig>,
) -> Result<Fetched, String> {
    let mut stream = connect(target, addrs, deadline)?;
    let mut conn = ClientConnection::new(config, server_name)
        .map_err(|e| format!("failed to start TLS session: {e}"))?;
    // Not complete_io: it keeps reading until the handshake ends, so a peer that
    // trickles bytes would never give control back to check the deadline.
    // Not is_handshaking() alone: in TLS 1.3 it turns false while the client
    // Finished is still buffered, so the server would never see it.
    while conn.is_handshaking() || conn.wants_write() {
        let remaining =
            remaining(deadline).map_err(|_| format!("TLS handshake with {target} timed out"))?;
        stream
            .set_read_timeout(remaining)
            .and_then(|_| stream.set_write_timeout(remaining))
            .map_err(|e| format!("failed to set socket timeout: {e}"))?;
        let io_err = |e: std::io::Error| match e.kind() {
            ErrorKind::WouldBlock | ErrorKind::TimedOut => {
                format!("TLS handshake with {target} timed out")
            }
            _ => format!("TLS handshake with {target} failed: {e}"),
        };
        if conn.wants_write() {
            conn.write_tls(&mut stream).map_err(io_err)?;
        } else if conn.wants_read() {
            if conn.read_tls(&mut stream).map_err(io_err)? == 0 {
                return Err(format!(
                    "TLS handshake with {target} failed: connection closed"
                ));
            }
            if let Err(e) = conn.process_new_packets() {
                let _ = conn.write_tls(&mut stream);
                return Err(format!(
                    "TLS handshake with {target} failed: {}",
                    describe(&e)
                ));
            }
        } else {
            return Err(format!("TLS handshake with {target} stalled"));
        }
    }

    let chain = conn
        .peer_certificates()
        .ok_or_else(|| format!("{target} presented no certificates"))?
        .iter()
        .map(|c| c.clone().into_owned())
        .collect();
    let ip = stream
        .peer_addr()
        .map_err(|e| format!("failed to get peer address: {e}"))?
        .ip()
        .to_string();
    Ok(Fetched {
        chain,
        ip,
        rejection: None,
    })
}

struct Expired;

/// `Ok(None)` means there is no deadline.
fn remaining(deadline: Option<Instant>) -> Result<Option<Duration>, Expired> {
    let Some(deadline) = deadline else {
        return Ok(None);
    };
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err(Expired)
    } else {
        Ok(Some(left))
    }
}

/// Splits the remaining time evenly over the untried addresses.
fn connect(
    target: &str,
    addrs: &[SocketAddr],
    deadline: Option<Instant>,
) -> Result<TcpStream, String> {
    let mut last_err = None;
    for (i, addr) in addrs.iter().enumerate() {
        let attempt = match remaining(deadline) {
            Ok(Some(left)) => {
                // connect_timeout rejects a zero duration.
                let per_attempt = (left / (addrs.len() - i) as u32).max(Duration::from_nanos(1));
                TcpStream::connect_timeout(addr, per_attempt)
            }
            Ok(None) => TcpStream::connect(addr),
            Err(Expired) => {
                return Err(match last_err {
                    Some(e) => format!("connecting to {target} timed out ({e})"),
                    None => format!("connecting to {target} timed out"),
                });
            }
        };
        match attempt {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(format!("failed to connect to {addr}: {e}")),
        }
    }
    Err(last_err.unwrap_or_else(|| format!("no addresses found for {target}")))
}

/// rustls prints a wrapped platform error with Debug, burying the OS's own
/// message in `Other(OtherError("..."))`; this unwraps it.
pub fn describe(e: &rustls::Error) -> String {
    match e {
        rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(inner))) => {
            format!("invalid peer certificate: {inner}")
        }
        _ => e.to_string(),
    }
}

/// The roots the OS trusts. Roots that fail to load are skipped.
pub fn native_roots() -> Vec<CertificateDer<'static>> {
    rustls_native_certs::load_native_certs().certs
}

/// The OS verifier, plus a second check that the server sent every
/// intermediate. Without `roots` only the OS verifier runs.
pub fn server_verifier(
    roots: &[CertificateDer<'static>],
) -> Result<Arc<dyn ServerCertVerifier>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let platform: Arc<dyn ServerCertVerifier> = Arc::new(
        rustls_platform_verifier::Verifier::new(provider.clone())
            .map_err(|e| format!("failed to load platform verifier: {e}"))?,
    );
    require_sent_chain(platform, roots)
}

/// Wraps `platform` with the sent-chain check against `roots`; returns
/// `platform` unchanged when no root is usable.
pub fn require_sent_chain(
    platform: Arc<dyn ServerCertVerifier>,
    roots: &[CertificateDer<'static>],
) -> Result<Arc<dyn ServerCertVerifier>, String> {
    let mut store = rustls::RootCertStore::empty();
    store.add_parsable_certificates(roots.iter().cloned());
    if store.is_empty() {
        return Ok(platform);
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let sent_only = WebPkiServerVerifier::builder_with_provider(Arc::new(store), provider)
        .build()
        .map_err(|e| format!("failed to build certificate verifier: {e}"))?;
    Ok(Arc::new(RequireSentChain {
        platform,
        sent_only,
    }))
}

/// The issuer of the last certificate the server sent is neither among the
/// sent certificates nor a trusted root.
#[derive(Debug)]
struct IssuerNotSent;

impl std::fmt::Display for IssuerNotSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "the server did not send an intermediate certificate \
             (this OS fetched it, but clients that do not fetch will fail)",
        )
    }
}

impl std::error::Error for IssuerNotSent {}

/// Some OS verifiers (macOS, Windows) fetch intermediates the server left out
/// and pass, hiding a mistake that breaks clients which do not fetch. webpki
/// never fetches, so running it on the sent chain alone exposes the gap.
/// Only its UnknownIssuer counts: on anything else the OS verifier, which
/// also checks revocation, has the final say.
#[derive(Debug)]
struct RequireSentChain {
    platform: Arc<dyn ServerCertVerifier>,
    sent_only: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for RequireSentChain {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verified = self.platform.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        match self.sent_only.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Err(rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer)) => {
                Err(rustls::Error::InvalidCertificate(CertificateError::Other(
                    OtherError(Arc::new(IssuerNotSent)),
                )))
            }
            _ => Ok(verified),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.platform.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.platform.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.platform.supported_verify_schemes()
    }
}

/// Like `fetch_with_config` with `verifier`, except that a rejected chain is
/// still returned, with the reason in `rejection`. The chain and the reason
/// come from the same connection, so they always describe the same server.
pub fn fetch_keeping_rejected(
    host: &str,
    port: &str,
    opts: &Options,
    verifier: Arc<dyn ServerCertVerifier>,
) -> Result<Fetched, String> {
    // One config per connection: the recorded rejection belongs to this handshake only.
    let keeper = Arc::new(KeepRejected {
        inner: verifier,
        rejection: Mutex::new(None),
    });
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("failed to configure TLS: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(keeper.clone())
        .with_no_client_auth();
    let mut fetched = fetch_with_config(host, port, opts, Arc::new(config))?;
    let rejection = keeper
        .rejection
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    fetched.rejection =
        rejection.map(|e| format!("TLS handshake with {host}:{port} failed: {}", describe(&e)));
    Ok(fetched)
}

/// Accepts what `inner` rejects and remembers why. Handshake signatures are
/// still checked by `inner`, so the peer must hold the certificate's key.
#[derive(Debug)]
struct KeepRejected {
    inner: Arc<dyn ServerCertVerifier>,
    rejection: Mutex<Option<rustls::Error>>,
}

impl ServerCertVerifier for KeepRejected {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => Ok(verified),
            Err(e) => {
                *self.rejection.lock().unwrap_or_else(|e| e.into_inner()) = Some(e);
                Ok(ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// `skip_verify` false loads the OS roots on every call; `config_with_verifier`
/// reuses a verifier built once.
pub fn client_config(skip_verify: bool) -> Result<Arc<ClientConfig>, String> {
    if skip_verify {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(AcceptAnyCert {
            algorithms: provider.signature_verification_algorithms,
        });
        config_with_verifier(verifier)
    } else {
        config_with_verifier(server_verifier(&native_roots())?)
    }
}

pub fn config_with_verifier(
    verifier: Arc<dyn ServerCertVerifier>,
) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("failed to configure TLS: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[derive(Debug)]
struct AcceptAnyCert {
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn silent_listener() -> (SocketAddr, TcpListener) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        (listener.local_addr().unwrap(), listener)
    }

    #[test]
    fn deadline_spans_all_addresses() {
        let (a, _keep_a) = silent_listener();
        let (b, _keep_b) = silent_listener();
        let config = client_config(true).unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        let started = Instant::now();
        let result = fetch_from_addrs(
            "localhost",
            name,
            &[a, b],
            Some(started + Duration::from_secs(1)),
            config,
        );
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_millis(1800));
    }

    #[derive(Debug)]
    struct Message;

    impl std::fmt::Display for Message {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("certificate is expired")
        }
    }

    impl std::error::Error for Message {}

    #[test]
    fn describe_unwraps_platform_errors() {
        let e = rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(
            Message,
        ))));
        assert_eq!(
            describe(&e),
            "invalid peer certificate: certificate is expired"
        );
    }

    #[test]
    fn describe_keeps_other_errors_as_rustls_prints_them() {
        let e = rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer);
        assert_eq!(describe(&e), e.to_string());
    }

    #[test]
    fn expired_deadline_fails_without_connecting() {
        let (a, _keep) = silent_listener();
        let err = connect("localhost", &[a], Some(Instant::now())).unwrap_err();
        assert_eq!(err, "connecting to localhost timed out");
    }
}
