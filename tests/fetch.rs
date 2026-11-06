mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use cert_rs::fetch::{Options, client_config, fetch, fetch_with_config};
use cert_rs::target::parse_resolve;
use common::{
    closed_port, make_cert, spawn_silent_listener, spawn_tls_server, spawn_tls_server_reporting,
};
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
    let (port, completed) = spawn_tls_server_reporting(der, key);
    let fetched = fetch_with_config("localhost", &port.to_string(), &opts(false), config);
    assert!(fetched.is_ok());
    assert!(
        completed.recv_timeout(Duration::from_secs(5)).is_ok(),
        "server never saw the client Finished"
    );
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

/// Sends a TLS record header promising a large handshake record, then one byte every
/// 200 ms, so no single read ever times out.
fn spawn_drip_server() -> u16 {
    use std::io::Write;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                if stream.write_all(&[0x16, 0x03, 0x03, 0x40, 0x00]).is_err() {
                    return;
                }
                loop {
                    std::thread::sleep(Duration::from_millis(200));
                    if stream.write_all(&[0]).is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

#[test]
fn slow_drip_handshake_hits_overall_deadline() {
    let port = spawn_drip_server().to_string();
    let mut options = opts(true);
    options.timeout = Duration::from_secs(1);
    let started = Instant::now();
    let err = fetch("127.0.0.1", &port, &options).err().unwrap();
    assert!(err.contains("timed out"), "{err}");
    assert!(started.elapsed() < Duration::from_millis(1800));
}

#[test]
fn zero_timeout_means_no_limit() {
    let (der, key) = make_cert(None, &[], false, &["localhost"]);
    let port = spawn_tls_server(der, key).to_string();
    let mut options = opts(true);
    options.timeout = Duration::ZERO;
    assert!(fetch("127.0.0.1", &port, &options).is_ok());
}

#[test]
fn huge_timeout_does_not_overflow() {
    let (der, key) = make_cert(None, &[], false, &["localhost"]);
    let port = spawn_tls_server(der, key).to_string();
    let mut options = opts(true);
    options.timeout = Duration::from_secs(u64::MAX);
    assert!(fetch("127.0.0.1", &port, &options).is_ok());
}

#[test]
fn hostname_mismatch_without_k_is_error() {
    let (der, key) = make_cert(None, &[], false, &["other.example.com"]);
    let config = config_trusting(&der);
    let port = spawn_tls_server(der, key).to_string();
    let mut options = opts(false);
    options.resolve = vec![parse_resolve(&format!("www.example.com:{port}:127.0.0.1")).unwrap()];
    let err = fetch_with_config("www.example.com", &port, &options, config)
        .err()
        .unwrap();
    assert!(err.contains("certificate"), "{err}");
}
