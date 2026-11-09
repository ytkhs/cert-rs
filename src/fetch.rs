use std::io::ErrorKind;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};
use rustls_platform_verifier::BuilderVerifierExt;

use crate::target::{Resolve, lookup_resolve};

pub struct Options {
    pub skip_verify: bool,
    pub timeout: Duration,
    pub resolve: Vec<Resolve>,
}

pub struct Fetched {
    pub chain: Vec<CertificateDer<'static>>,
    pub ip: String,
}

#[derive(Debug)]
pub struct FetchError {
    pub message: String,
    /// The verifier rejected the server's certificates; the handshake itself was sound.
    pub cert_rejected: bool,
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<String> for FetchError {
    fn from(message: String) -> Self {
        FetchError {
            message,
            cert_rejected: false,
        }
    }
}

pub fn fetch(host: &str, port: &str, opts: &Options) -> Result<Fetched, FetchError> {
    let config = client_config(opts.skip_verify)?;
    fetch_with_config(host, port, opts, config)
}

pub fn fetch_with_config(
    host: &str,
    port: &str,
    opts: &Options,
    config: Arc<ClientConfig>,
) -> Result<Fetched, FetchError> {
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
) -> Result<Fetched, FetchError> {
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
                return Err(
                    format!("TLS handshake with {target} failed: connection closed").into(),
                );
            }
            if let Err(e) = conn.process_new_packets() {
                let _ = conn.write_tls(&mut stream);
                return Err(FetchError {
                    message: format!("TLS handshake with {target} failed: {e}"),
                    cert_rejected: matches!(e, rustls::Error::InvalidCertificate(_)),
                });
            }
        } else {
            return Err(format!("TLS handshake with {target} stalled").into());
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
    Ok(Fetched { chain, ip })
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

pub fn client_config(skip_verify: bool) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("failed to configure TLS: {e}"))?;
    let config = if skip_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert {
                algorithms: provider.signature_verification_algorithms,
            }))
            .with_no_client_auth()
    } else {
        builder
            .with_platform_verifier()
            .map_err(|e| format!("failed to load platform verifier: {e}"))?
            .with_no_client_auth()
    };
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

    #[test]
    fn expired_deadline_fails_without_connecting() {
        let (a, _keep) = silent_listener();
        let err = connect("localhost", &[a], Some(Instant::now())).unwrap_err();
        assert_eq!(err, "connecting to localhost timed out");
    }
}
