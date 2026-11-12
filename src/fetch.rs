use std::io;
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

use crate::error::{ErrorKind, Failure};
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
    pub rejection: Option<Failure>,
    /// As openssl names them: `TLSv1.3`, `TLSv1.2`.
    pub tls_version: Option<String>,
    /// The IANA name, such as `TLS13_AES_256_GCM_SHA384`.
    pub cipher_suite: Option<String>,
}

pub fn fetch(host: &str, port: &str, opts: &Options) -> Result<Fetched, Failure> {
    let config = client_config(opts.skip_verify).map_err(internal)?;
    fetch_with_config(host, port, opts, config)
}

pub fn fetch_with_config(
    host: &str,
    port: &str,
    opts: &Options,
    config: Arc<ClientConfig>,
) -> Result<Fetched, Failure> {
    let server_name = ServerName::try_from(host.to_string()).map_err(|e| {
        Failure::new(
            ErrorKind::InvalidInput,
            format!("invalid server name {host:?}: {e}"),
        )
    })?;
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

fn internal(message: String) -> Failure {
    Failure::new(ErrorKind::Internal, message)
}

fn resolve_addrs(host: &str, port: &str, opts: &Options) -> Result<Vec<SocketAddr>, Failure> {
    let port_num: u16 = port
        .parse()
        .map_err(|_| Failure::new(ErrorKind::InvalidInput, format!("invalid port {port:?}")))?;
    if let Some(ip) = lookup_resolve(&opts.resolve, host, port) {
        return Ok(vec![SocketAddr::new(ip, port_num)]);
    }
    let addrs: Vec<SocketAddr> = (host, port_num)
        .to_socket_addrs()
        .map_err(|e| Failure::new(ErrorKind::Dns, format!("failed to resolve {host}: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(Failure::new(
            ErrorKind::Dns,
            format!("no addresses found for {host}"),
        ));
    }
    Ok(addrs)
}

fn fetch_from_addrs(
    target: &str,
    server_name: ServerName<'static>,
    addrs: &[SocketAddr],
    deadline: Option<Instant>,
    config: Arc<ClientConfig>,
) -> Result<Fetched, Failure> {
    let mut stream = connect(target, addrs, deadline)?;
    let ip = stream.peer_addr().ok().map(|a| a.ip().to_string());
    let mut conn = ClientConnection::new(config, server_name)
        .map_err(|e| internal(format!("failed to start TLS session: {e}")).at(ip.clone()))?;
    handshake(&mut conn, &mut stream, target, deadline).map_err(|f| f.at(ip.clone()))?;

    let chain = conn
        .peer_certificates()
        .ok_or_else(|| {
            Failure::new(
                ErrorKind::HandshakeFailed,
                format!("{target} presented no certificates"),
            )
            .at(ip.clone())
        })?
        .iter()
        .map(|c| c.clone().into_owned())
        .collect();
    let ip = ip.ok_or_else(|| internal(format!("failed to get the peer address of {target}")))?;
    Ok(Fetched {
        chain,
        ip,
        rejection: None,
        tls_version: conn.protocol_version().map(tls_version_name),
        cipher_suite: conn
            .negotiated_cipher_suite()
            .map(|s| format!("{:?}", s.suite())),
    })
}

fn tls_version_name(v: rustls::ProtocolVersion) -> String {
    match v {
        rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".into(),
        rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".into(),
        other => format!("{other:?}"),
    }
}

fn handshake(
    conn: &mut ClientConnection,
    stream: &mut TcpStream,
    target: &str,
    deadline: Option<Instant>,
) -> Result<(), Failure> {
    let failed = |message: String| Failure::new(ErrorKind::HandshakeFailed, message);
    // Not complete_io: it keeps reading until the handshake ends, so a peer that
    // trickles bytes would never give control back to check the deadline.
    // Not is_handshaking() alone: in TLS 1.3 it turns false while the client
    // Finished is still buffered, so the server would never see it.
    while conn.is_handshaking() || conn.wants_write() {
        let remaining = remaining(deadline).map_err(|_| {
            Failure::new(
                ErrorKind::Timeout,
                format!("TLS handshake with {target} timed out"),
            )
        })?;
        stream
            .set_read_timeout(remaining)
            .and_then(|_| stream.set_write_timeout(remaining))
            .map_err(|e| internal(format!("failed to set socket timeout: {e}")))?;
        let io_err = |e: std::io::Error| match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Failure::new(
                ErrorKind::Timeout,
                format!("TLS handshake with {target} timed out"),
            ),
            _ => failed(format!("TLS handshake with {target} failed: {e}")),
        };
        if conn.wants_write() {
            conn.write_tls(stream).map_err(io_err)?;
        } else if conn.wants_read() {
            if conn.read_tls(stream).map_err(io_err)? == 0 {
                return Err(failed(format!(
                    "TLS handshake with {target} failed: connection closed"
                )));
            }
            if let Err(e) = conn.process_new_packets() {
                let _ = conn.write_tls(stream);
                return Err(Failure::new(
                    kind_of(&e),
                    format!("TLS handshake with {target} failed: {}", describe(&e)),
                ));
            }
        } else {
            return Err(failed(format!("TLS handshake with {target} stalled")));
        }
    }
    Ok(())
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
) -> Result<TcpStream, Failure> {
    // Every failed address is reported: the last one alone can hide the
    // cause, such as IPv6 unreachable while IPv4 is refused.
    let mut failures: Vec<String> = Vec::new();
    let mut all_timed_out = true;
    for (i, addr) in addrs.iter().enumerate() {
        let attempt = match remaining(deadline) {
            Ok(Some(left)) => {
                // connect_timeout rejects a zero duration.
                let per_attempt = (left / (addrs.len() - i) as u32).max(Duration::from_nanos(1));
                TcpStream::connect_timeout(addr, per_attempt)
            }
            Ok(None) => TcpStream::connect(addr),
            Err(Expired) => {
                return Err(Failure::new(
                    ErrorKind::Timeout,
                    if failures.is_empty() {
                        format!("connecting to {target} timed out")
                    } else {
                        format!("connecting to {target} timed out ({})", failures.join("; "))
                    },
                ));
            }
        };
        match attempt {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                all_timed_out &= e.kind() == io::ErrorKind::TimedOut;
                failures.push(format!("{addr}: {e}"));
            }
        }
    }
    if failures.is_empty() {
        return Err(Failure::new(
            ErrorKind::Dns,
            format!("no addresses found for {target}"),
        ));
    }
    let kind = if all_timed_out {
        ErrorKind::Timeout
    } else {
        ErrorKind::Connect
    };
    Err(Failure::new(
        kind,
        format!("failed to connect to {target} ({})", failures.join("; ")),
    ))
}

/// Classifies a TLS failure from the error itself, never from its wording.
pub fn kind_of(e: &rustls::Error) -> ErrorKind {
    use rustls::{AlertDescription, CertificateError as C, Error, PeerIncompatible};
    match e {
        Error::InvalidCertificate(c) => match c {
            C::Other(OtherError(inner)) => {
                if inner.downcast_ref::<IssuerNotSent>().is_some() {
                    ErrorKind::MissingIntermediate
                } else if inner.downcast_ref::<SentIntermediateOutOfDate>().is_some() {
                    ErrorKind::SentIntermediateOutOfDate
                } else {
                    os_status_kind(&inner.to_string())
                }
            }
            C::NotValidForName | C::NotValidForNameContext { .. } => ErrorKind::NameMismatch,
            C::UnknownIssuer => ErrorKind::Untrusted,
            C::Revoked => ErrorKind::Revoked,
            C::Expired | C::ExpiredContext { .. } => ErrorKind::Expired,
            C::NotValidYet | C::NotValidYetContext { .. } => ErrorKind::NotYetValid,
            C::UnsupportedSignatureAlgorithmContext { .. }
            | C::UnsupportedSignatureAlgorithmForPublicKeyContext { .. } => {
                ErrorKind::WeakSignature
            }
            _ => ErrorKind::CertificateInvalid,
        },
        Error::InvalidMessage(rustls::InvalidMessage::InvalidContentType) => ErrorKind::NotTls,
        Error::AlertReceived(
            AlertDescription::HandshakeFailure
            | AlertDescription::ProtocolVersion
            | AlertDescription::InsufficientSecurity,
        )
        | Error::PeerIncompatible(
            PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig
            | PeerIncompatible::NoCipherSuitesInCommon
            | PeerIncompatible::NoKxGroupsInCommon,
        ) => ErrorKind::HandshakeRefused,
        _ => ErrorKind::HandshakeFailed,
    }
}

/// macOS reports certificate problems as text ending in an OSStatus code.
/// Only codes seen from its verifier are mapped; the rest stay generic.
fn os_status_kind(message: &str) -> ErrorKind {
    match message.rsplit_once(": ").map(|(_, code)| code) {
        Some("-67818") => ErrorKind::Expired,
        Some("-67819") => ErrorKind::NotYetValid,
        Some("-67843") => ErrorKind::Untrusted,
        Some("-67815") => ErrorKind::WeakSignature,
        _ => ErrorKind::CertificateInvalid,
    }
}

/// Plain wording for the TLS failures people actually hit. rustls prints many
/// of these as bare identifiers (`UnknownIssuer`), and a wrapped OS error with
/// Debug, burying its message in `Other(OtherError("..."))`.
pub fn describe(e: &rustls::Error) -> String {
    use rustls::{AlertDescription, CertificateError as C, Error, PeerIncompatible};
    match e {
        Error::InvalidCertificate(c) => match c {
            C::Other(OtherError(inner)) => without_os_status(&inner.to_string()).to_string(),
            C::NotValidForName => "the certificate is not valid for this host name".into(),
            C::UnknownIssuer => "the certificate does not lead to a trusted root \
                (an untrusted CA, or an intermediate that is missing or unusable)"
                .into(),
            C::Revoked => "the certificate has been revoked".into(),
            C::Expired => "the certificate has expired".into(),
            C::NotValidYet => "the certificate is not valid yet".into(),
            C::BadSignature => "a certificate signature is invalid".into(),
            C::BadEncoding => "a certificate is malformed".into(),
            C::UnsupportedSignatureAlgorithmContext { .. }
            | C::UnsupportedSignatureAlgorithmForPublicKeyContext { .. } => {
                "a certificate uses an unsupported signature algorithm".into()
            }
            C::InvalidPurpose | C::InvalidPurposeContext { .. } => {
                "the certificate is not issued for server authentication".into()
            }
            C::UnhandledCriticalExtension => {
                "a certificate has a critical extension that cannot be checked".into()
            }
            C::UnknownRevocationStatus => "the certificate's revocation status is unknown".into(),
            _ => e.to_string(),
        },
        Error::InvalidMessage(rustls::InvalidMessage::HandshakePayloadTooLarge) => {
            "the server sent a handshake message over 64 KiB, the most this tool \
             accepts (a certificate with very many names?)"
                .into()
        }
        Error::InvalidMessage(rustls::InvalidMessage::InvalidContentType) => {
            "the server did not answer with TLS (a plain HTTP or other non-TLS port?)".into()
        }
        Error::AlertReceived(
            alert @ (AlertDescription::HandshakeFailure
            | AlertDescription::ProtocolVersion
            | AlertDescription::InsufficientSecurity),
        ) => format!(
            "the server refused the handshake ({alert:?}); it likely offers only TLS \
             versions or ciphers this tool does not support (TLS 1.1 or older, CBC, \
             DHE, static RSA, RC4 or 3DES)"
        ),
        Error::PeerIncompatible(PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig) => {
            "the server supports only TLS 1.1 or older, which this tool does not".into()
        }
        Error::PeerIncompatible(
            PeerIncompatible::NoCipherSuitesInCommon | PeerIncompatible::NoKxGroupsInCommon,
        ) => "the server offers no cipher this tool supports".into(),
        _ => e.to_string(),
    }
}

/// macOS ends its messages with the numeric OSStatus (`...: -67818`), which
/// means nothing to the reader once the text is there.
fn without_os_status(message: &str) -> &str {
    match message.rsplit_once(": -") {
        Some((text, code)) if !code.is_empty() && code.bytes().all(|b| b.is_ascii_digit()) => text,
        _ => message,
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

/// The sent chain holds an intermediate outside its validity period, typically
/// an old one left in place after renewal, while the OS found a current one.
#[derive(Debug)]
struct SentIntermediateOutOfDate;

impl std::fmt::Display for SentIntermediateOutOfDate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "an intermediate certificate the server sent is expired or not yet valid \
             (this OS used another one, but clients that rely on the sent chain will fail)",
        )
    }
}

impl std::error::Error for SentIntermediateOutOfDate {}

/// Some OS verifiers (macOS, Windows) fetch intermediates the server left out
/// and pass, hiding a mistake that breaks clients which do not fetch. webpki
/// never fetches, so running it on the sent chain alone exposes the gap.
/// Only a missing issuer or an out-of-date certificate counts. The leaf
/// already passed the OS verifier at the same time, so an out-of-date verdict
/// can only be about a sent intermediate. On anything else the OS verifier,
/// which also checks revocation, has the final say, so that differences in
/// how the two read a certificate never turn into errors.
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
            Err(rustls::Error::InvalidCertificate(
                CertificateError::Expired
                | CertificateError::ExpiredContext { .. }
                | CertificateError::NotValidYet
                | CertificateError::NotValidYetContext { .. },
            )) => Err(rustls::Error::InvalidCertificate(CertificateError::Other(
                OtherError(Arc::new(SentIntermediateOutOfDate)),
            ))),
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
) -> Result<Fetched, Failure> {
    // One config per connection: the recorded rejection belongs to this handshake only.
    let keeper = Arc::new(KeepRejected {
        inner: verifier,
        rejection: Mutex::new(None),
    });
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| internal(format!("failed to configure TLS: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(keeper.clone())
        .with_no_client_auth();
    let mut fetched = fetch_with_config(host, port, opts, Arc::new(config))?;
    let rejection = keeper
        .rejection
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    fetched.rejection = rejection.map(|e| {
        Failure::new(
            kind_of(&e),
            format!("TLS handshake with {host}:{port} failed: {}", describe(&e)),
        )
    });
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
        assert_eq!(describe(&e), "certificate is expired");
    }

    #[test]
    fn os_status_code_is_dropped() {
        assert_eq!(
            without_os_status("“a” certificate is expired: -67818"),
            "“a” certificate is expired"
        );
    }

    #[test]
    fn text_without_a_status_code_is_kept() {
        assert_eq!(without_os_status("a: -b"), "a: -b");
        assert_eq!(without_os_status("a: -"), "a: -");
        assert_eq!(without_os_status("plain"), "plain");
    }

    #[test]
    fn describe_spells_out_bare_identifiers() {
        let e = rustls::Error::InvalidCertificate(CertificateError::NotValidForName);
        assert_eq!(
            describe(&e),
            "the certificate is not valid for this host name"
        );
        let e = rustls::Error::InvalidCertificate(CertificateError::Revoked);
        assert_eq!(describe(&e), "the certificate has been revoked");
    }

    #[test]
    fn describe_explains_a_non_tls_port() {
        let e = rustls::Error::InvalidMessage(rustls::InvalidMessage::InvalidContentType);
        assert!(describe(&e).contains("did not answer with TLS"));
    }

    #[test]
    fn describe_explains_an_oversized_handshake() {
        let e = rustls::Error::InvalidMessage(rustls::InvalidMessage::HandshakePayloadTooLarge);
        assert!(describe(&e).contains("over 64 KiB"), "{}", describe(&e));
    }

    #[test]
    fn describe_hints_at_old_tls_on_handshake_failure() {
        let e = rustls::Error::AlertReceived(rustls::AlertDescription::HandshakeFailure);
        assert!(
            describe(&e).contains("TLS 1.1 or older"),
            "{}",
            describe(&e)
        );
    }

    #[test]
    fn describe_keeps_rustls_wording_for_the_rest() {
        let e = rustls::Error::AlertReceived(rustls::AlertDescription::DecodeError);
        assert_eq!(describe(&e), e.to_string());
    }

    #[test]
    fn every_failed_address_is_reported() {
        let closed = |port| SocketAddr::from(([127, 0, 0, 1], port));
        let a = closed(crate_closed_port());
        let b = closed(crate_closed_port());
        let err = connect("localhost:1", &[a, b], None).unwrap_err();
        assert!(
            err.message
                .starts_with("failed to connect to localhost:1 ("),
            "{err}"
        );
        assert!(
            err.message.contains(&a.to_string()) && err.message.contains(&b.to_string()),
            "{err}"
        );
        assert_eq!(err.kind, ErrorKind::Connect);
    }

    fn crate_closed_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn expired_deadline_fails_without_connecting() {
        let (a, _keep) = silent_listener();
        let err = connect("localhost", &[a], Some(Instant::now())).unwrap_err();
        assert_eq!(
            err,
            Failure::new(ErrorKind::Timeout, "connecting to localhost timed out")
        );
    }
}
