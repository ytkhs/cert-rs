mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use cert_rs::fetch::{Options, client_config, fetch, fetch_with_config};
use cert_rs::target::parse_resolve;
use common::{closed_port, make_cert, spawn_silent_listener, spawn_tls_server};
use rustls::pki_types::CertificateDer;

fn opts(skip_verify: bool) -> Options {
    Options {
        skip_verify,
        timeout: Duration::from_secs(5),
        resolve: Vec::new(),
    }
}

fn config_trusting(cert_der: &[u8]) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(cert_der.to_vec())).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    Arc::new(config)
}

#[test]
fn untrusted_without_k_is_error() {
    let (der, key) = make_cert(None, &[], false, &["localhost"]);
    let port = spawn_tls_server(der, key).to_string();
    let err = fetch("localhost", &port, &opts(false)).err().unwrap();
    assert!(err.contains("certificate"), "{err}");
}

#[test]
fn untrusted_with_k_returns_chain() {
    let (der, key) = make_cert(None, &[], false, &["localhost"]);
    let port = spawn_tls_server(der.clone(), key).to_string();
    let fetched = fetch("localhost", &port, &opts(true)).unwrap();
    assert_eq!(fetched.chain[0].as_ref(), der.as_slice());
    assert_eq!(fetched.ip, "127.0.0.1");
}

#[test]
fn trusted_root_succeeds() {
    let (der, key) = make_cert(None, &[], false, &["localhost"]);
    let config = config_trusting(&der);
    let port = spawn_tls_server(der, key).to_string();
    assert!(fetch_with_config("localhost", &port, &opts(false), config).is_ok());
}

#[test]
fn resolve_overrides_dns() {
    let (der, key) = make_cert(None, &[], false, &["cert-test.invalid"]);
    let config = config_trusting(&der);
    let port = spawn_tls_server(der, key).to_string();
    let mut options = opts(false);
    options.resolve = vec![parse_resolve(&format!("cert-test.invalid:{port}:127.0.0.1")).unwrap()];
    let fetched = fetch_with_config("cert-test.invalid", &port, &options, config).unwrap();
    assert_eq!(fetched.ip, "127.0.0.1");
}

#[test]
fn handshake_timeout() {
    let port = spawn_silent_listener().to_string();
    let mut options = opts(true);
    options.timeout = Duration::from_secs(1);
    let started = Instant::now();
    let result = fetch("127.0.0.1", &port, &options);
    assert!(result.is_err());
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn connection_refused() {
    let port = closed_port().to_string();
    assert!(fetch("127.0.0.1", &port, &opts(true)).is_err());
}

#[test]
fn client_config_builds_both_modes() {
    assert!(client_config(false).is_ok());
    assert!(client_config(true).is_ok());
}
