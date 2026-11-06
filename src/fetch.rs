use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
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
    let mut stream = connect(host, port, opts)?;
    stream
        .set_read_timeout(Some(opts.timeout))
        .and_then(|_| stream.set_write_timeout(Some(opts.timeout)))
        .map_err(|e| format!("failed to set socket timeout: {e}"))?;

    let mut conn = ClientConnection::new(config, server_name)
        .map_err(|e| format!("failed to start TLS session: {e}"))?;
    while conn.is_handshaking() {
        conn.complete_io(&mut stream)
            .map_err(|e| format!("TLS handshake with {host}:{port} failed: {e}"))?;
    }

    let chain = conn
        .peer_certificates()
        .ok_or_else(|| format!("{host}:{port} presented no certificates"))?
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

fn connect(host: &str, port: &str, opts: &Options) -> Result<TcpStream, String> {
    let port_num: u16 = port.parse().map_err(|_| format!("invalid port {port:?}"))?;
    let addrs: Vec<SocketAddr> = match lookup_resolve(&opts.resolve, host, port) {
        Some(ip) => vec![SocketAddr::new(ip, port_num)],
        None => (host, port_num)
            .to_socket_addrs()
            .map_err(|e| format!("failed to resolve {host}: {e}"))?
            .collect(),
    };

    let mut last_err = None;
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, opts.timeout) {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(format!("failed to connect to {addr}: {e}")),
        }
    }
    Err(last_err.unwrap_or_else(|| format!("no addresses found for {host}")))
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
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}
