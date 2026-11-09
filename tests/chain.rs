mod common;

use cert_rs::chain::{ChainReport, inspect_chain, parse_chain};
use common::{issue, make_cert};
use jiff::Timestamp;
use rcgen::{CertificateParams, DnType, DnValue, KeyPair};

const VALID: ((i32, u8, u8), (i32, u8, u8)) = ((2026, 1, 1), (2027, 1, 1));

fn now() -> Timestamp {
    "2026-06-01T00:00:00Z".parse().unwrap()
}

fn report_at(ders: &[Vec<u8>], at: Timestamp) -> ChainReport {
    let refs: Vec<&[u8]> = ders.iter().map(|d| d.as_slice()).collect();
    inspect_chain(&refs, &parse_chain(&refs), true, at)
}

fn problems(ders: &[Vec<u8>]) -> Vec<String> {
    report_at(ders, now()).problems
}

#[test]
fn valid_two_cert_chain_has_no_problems() {
    let ca = issue("Example CA", true, VALID, None);
    let leaf = issue("www.example.com", false, VALID, Some(&ca));
    let ders = [leaf.der(), ca.der()];
    assert_eq!(problems(&ders), Vec::<String>::new());
}

#[test]
fn three_cert_chain_including_root_has_no_problems() {
    let root = issue("Example Root", true, VALID, None);
    let inter = issue("Example Intermediate", true, VALID, Some(&root));
    let leaf = issue("www.example.com", false, VALID, Some(&inter));
    let ders = [leaf.der(), inter.der(), root.der()];
    assert!(problems(&ders).is_empty());
}

#[test]
fn issuer_mismatch_is_reported() {
    let (a, _) = make_cert(None, &[], false, &["a.example.com"]);
    let (b, _) = make_cert(None, &[], false, &["b.example.com"]);
    let ders = [a, b];
    assert_eq!(
        problems(&ders),
        vec!["[0] issuer does not match [1] subject".to_string()]
    );
}

#[test]
fn expired_intermediate_is_reported() {
    let root = issue("Example Root", true, VALID, None);
    let inter = issue(
        "Example Intermediate",
        true,
        ((2020, 1, 1), (2026, 1, 1)),
        Some(&root),
    );
    let leaf = issue("www.example.com", false, VALID, Some(&inter));
    let ders = [leaf.der(), inter.der(), root.der()];
    assert_eq!(problems(&ders), vec!["[1] expired".to_string()]);
}

#[test]
fn not_yet_valid_leaf_is_reported() {
    let ca = issue("Example CA", true, VALID, None);
    let leaf = issue(
        "www.example.com",
        false,
        ((2026, 7, 1), (2027, 1, 1)),
        Some(&ca),
    );
    let ders = [leaf.der(), ca.der()];
    assert_eq!(problems(&ders), vec!["[0] not yet valid".to_string()]);
}

#[test]
fn multiple_problems_are_all_listed() {
    let (a, _) = make_cert(None, &[], false, &["a.example.com"]);
    let old = issue("Old", true, ((2020, 1, 1), (2021, 1, 1)), None);
    let ders = [a, old.der()];
    let report = report_at(&ders, now());
    assert_eq!(
        report.problems,
        vec![
            "[0] issuer does not match [1] subject".to_string(),
            "[1] expired".to_string(),
        ]
    );
    assert_eq!(
        report.label(),
        "NG: [0] issuer does not match [1] subject; [1] expired"
    );
}

#[test]
fn label_is_ok_when_no_problems() {
    let report = ChainReport {
        entries: Vec::new(),
        problems: Vec::new(),
    };
    assert_eq!(report.label(), "OK");
}

#[test]
fn single_cert_chain_skips_link_check() {
    let (a, _) = make_cert(None, &[], false, &["a.example.com"]);
    let ders = [a];
    assert!(problems(&ders).is_empty());
}

#[test]
fn unparsable_certificate_is_reported_with_its_position() {
    let root = issue("Example Root", true, VALID, None);
    let leaf = issue("www.example.com", false, VALID, Some(&root));
    let ders = [leaf.der(), root.der(), vec![0u8, 1, 2, 3]];
    let report = report_at(&ders, now());
    assert_eq!(report.problems.len(), 1);
    assert!(
        report.problems[0].starts_with("[2] failed to parse certificate: "),
        "{:?}",
        report.problems
    );
}

#[test]
fn certificates_around_an_unparsable_one_are_still_listed() {
    let root = issue("Example Root", true, VALID, None);
    let leaf = issue("www.example.com", false, VALID, Some(&root));
    let ders = [leaf.der(), vec![0u8, 1, 2, 3], root.der()];
    let report = report_at(&ders, now());
    assert_eq!(report.entries.len(), 3);
    assert_eq!(report.entries[0].subject, "CN=www.example.com");
    assert_eq!(report.entries[1].subject, "");
    assert_eq!(report.entries[1].sha256.len(), 32 * 3 - 1);
    assert_eq!(report.entries[2].subject, "CN=Example Root");
}

#[test]
fn entries_keep_server_order_and_format_fields() {
    let ca = issue("Example CA", true, VALID, None);
    let leaf = issue("www.example.com", false, VALID, Some(&ca));
    let ders = [leaf.der(), ca.der()];
    let entries = report_at(&ders, now()).entries;
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].subject, "CN=www.example.com");
    assert_eq!(entries[0].issuer, "CN=Example CA");
    assert_eq!(entries[1].subject, "CN=Example CA");
    assert_eq!(entries[0].not_before, "2026-01-01 00:00:00 +0000 UTC");
    assert_eq!(entries[0].not_after, "2027-01-01 00:00:00 +0000 UTC");
}

/// Minimal SHA-256, independent of the implementation under test.
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend(((data.len() as u64) * 8).to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [
                t1.wrapping_add(t2),
                v[0],
                v[1],
                v[2],
                v[3].wrapping_add(t1),
                v[4],
                v[5],
                v[6],
            ];
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }
    let mut out = [0u8; 32];
    for (i, x) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&x.to_be_bytes());
    }
    out
}

#[test]
fn sha256_helper_matches_known_vector() {
    let hex: String = sha256(b"abc").iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn sha256_is_uppercase_colon_separated() {
    let (a, _) = make_cert(None, &[], false, &["a.example.com"]);
    let expected = sha256(&a)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let entries = report_at(&[a], now()).entries;
    assert_eq!(entries[0].sha256, expected);
    assert_eq!(entries[0].sha256.len(), 32 * 3 - 1);
}

#[test]
fn validity_bounds_are_inclusive() {
    let cert = issue("www.example.com", false, VALID, None);
    let ders = [cert.der()];
    let not_before: Timestamp = "2026-01-01T00:00:00Z".parse().unwrap();
    let not_after: Timestamp = "2027-01-01T00:00:00Z".parse().unwrap();
    assert!(report_at(&ders, not_before).problems.is_empty());
    assert!(report_at(&ders, not_after).problems.is_empty());
}

#[test]
fn serial_keeps_leading_nibble_zero_of_known_value() {
    let mut params = rcgen::CertificateParams::new(vec!["a.example.com".to_string()]).unwrap();
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&[0x0A, 0x1B, 0x2C]));
    let key = rcgen::KeyPair::generate().unwrap();
    let der = params.self_signed(&key).unwrap().der().to_vec();
    let entries = report_at(&[der], now()).entries;
    assert_eq!(entries[0].serial, "0A1B2C");
}

#[test]
fn serial_with_high_bit_matches_openssl() {
    let mut params = CertificateParams::new(vec!["a.example.com".to_string()]).unwrap();
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&[0x8A, 0x1B]));
    let key = KeyPair::generate().unwrap();
    let der = params.self_signed(&key).unwrap().der().to_vec();
    assert_eq!(report_at(&[der], now()).entries[0].serial, "8A1B");
}

fn ca_named(dn: Vec<(DnType, DnValue)>) -> common::Issued {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    for (ty, value) in dn {
        params.distinguished_name.push(ty, value);
    }
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ((y1, m1, d1), (y2, m2, d2)) = VALID;
    params.not_before = rcgen::date_time_ymd(y1, m1, d1);
    params.not_after = rcgen::date_time_ymd(y2, m2, d2);
    let key = KeyPair::generate().unwrap();
    let cert = params.clone().self_signed(&key).unwrap();
    common::Issued { params, cert, key }
}

fn printable(s: &str) -> DnValue {
    DnValue::PrintableString(s.try_into().unwrap())
}

#[test]
fn names_differing_in_string_type_and_case_match() {
    let signer = ca_named(vec![
        (
            DnType::OrganizationName,
            DnValue::Utf8String("Example Org".into()),
        ),
        (DnType::CommonName, DnValue::Utf8String("Example CA".into())),
    ]);
    let sent = ca_named(vec![
        (DnType::OrganizationName, printable("EXAMPLE  org")),
        (DnType::CommonName, printable("example ca")),
    ]);
    let leaf = issue("www.example.com", false, VALID, Some(&signer));
    assert!(problems(&[leaf.der(), sent.der()]).is_empty());
}

#[test]
fn names_differing_in_value_do_not_match() {
    let signer = ca_named(vec![(DnType::CommonName, printable("Example CA"))]);
    let sent = ca_named(vec![(DnType::CommonName, printable("Example CA 2"))]);
    let leaf = issue("www.example.com", false, VALID, Some(&signer));
    assert_eq!(
        problems(&[leaf.der(), sent.der()]),
        vec!["[0] issuer does not match [1] subject".to_string()]
    );
}
