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
