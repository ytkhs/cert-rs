#![allow(dead_code)]

use rcgen::{CertificateParams, CustomExtension, DnType, KeyPair};

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        let mut out = vec![0x80 | bytes.len() as u8];
        out.extend(bytes);
        out
    }
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn der_oid(arcs: &[u64]) -> Vec<u8> {
    let mut content = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &arc in &arcs[2..] {
        let mut groups = vec![(arc & 0x7f) as u8];
        let mut rest = arc >> 7;
        while rest > 0 {
            groups.push(0x80 | (rest & 0x7f) as u8);
            rest >>= 7;
        }
        groups.reverse();
        content.extend(groups);
    }
    der_tlv(0x06, &content)
}

fn certificate_policies(policies: &[&[u64]]) -> Vec<u8> {
    let infos: Vec<u8> = policies
        .iter()
        .flat_map(|oid| der_tlv(0x30, &der_oid(oid)))
        .collect();
    der_tlv(0x30, &infos)
}

/// Self-signed; the subject CN is the first SAN.
pub fn make_cert(
    org: Option<&str>,
    policies: &[&[u64]],
    ev_subject_attrs: bool,
    sans: &[&str],
) -> (Vec<u8>, KeyPair) {
    let mut params =
        CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
    if let Some(first) = sans.first() {
        params.distinguished_name.push(DnType::CommonName, *first);
    }
    if let Some(org) = org {
        params
            .distinguished_name
            .push(DnType::OrganizationName, org);
    }
    if ev_subject_attrs {
        for (oid, value) in [
            (&[2, 5, 4, 15][..], "Private Organization"),
            (&[2, 5, 4, 5][..], "12345"),
            (&[1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3][..], "JP"),
        ] {
            params
                .distinguished_name
                .push(DnType::CustomDnType(oid.to_vec()), value);
        }
    }
    if !policies.is_empty() {
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[2, 5, 29, 32],
                certificate_policies(policies),
            ));
    }
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    (cert.der().to_vec(), key)
}

/// Serves TLS handshakes with the given certificate until the test process exits.
pub fn spawn_tls_server(cert_der: Vec<u8>, key: KeyPair) -> u16 {
    spawn_tls_server_reporting(cert_der, key).0
}

/// Like spawn_tls_server, but sends one message per connection whose server-side
/// handshake completed.
pub fn spawn_tls_server_reporting(
    cert_der: Vec<u8>,
    key: KeyPair,
) -> (u16, std::sync::mpsc::Receiver<()>) {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert_der)], key_der)
        .unwrap();
    let config = Arc::new(config);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (completed_tx, completed_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let config = config.clone();
            let completed_tx = completed_tx.clone();
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                let Ok(mut conn) = rustls::ServerConnection::new(config) else {
                    return;
                };
                while conn.is_handshaking() {
                    if conn.complete_io(&mut stream).is_err() {
                        return;
                    }
                }
                let _ = completed_tx.send(());
                // Flush any post-handshake messages so the client sees a clean close.
                let _ = conn.complete_io(&mut stream);
                conn.send_close_notify();
                let _ = conn.complete_io(&mut stream);
            });
        }
    });
    (port, completed_rx)
}

/// Accepts connections but never writes a byte, to exercise handshake timeouts.
pub fn spawn_silent_listener() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            held.push(stream);
        }
    });
    port
}

/// A port that was just bound and released, so connecting to it is refused.
pub fn closed_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

pub struct Issued {
    pub params: CertificateParams,
    pub cert: rcgen::Certificate,
    pub key: KeyPair,
}

impl Issued {
    pub fn der(&self) -> Vec<u8> {
        self.cert.der().to_vec()
    }
}

/// `validity` is ((y, m, d), (y, m, d)) for NotBefore and NotAfter.
/// Signed by `issuer` when given, otherwise self-signed.
pub fn issue(
    cn: &str,
    is_ca: bool,
    validity: ((i32, u8, u8), (i32, u8, u8)),
    issuer: Option<&Issued>,
) -> Issued {
    let mut params = CertificateParams::new(vec![cn.to_string()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, cn);
    if is_ca {
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    }
    let ((y1, m1, d1), (y2, m2, d2)) = validity;
    params.not_before = rcgen::date_time_ymd(y1, m1, d1);
    params.not_after = rcgen::date_time_ymd(y2, m2, d2);
    let key = KeyPair::generate().unwrap();
    let cert = match issuer {
        Some(i) => {
            let issuer = rcgen::Issuer::new(i.params.clone(), &i.key);
            params.clone().signed_by(&key, &issuer).unwrap()
        }
        None => params.clone().self_signed(&key).unwrap(),
    };
    Issued { params, cert, key }
}
