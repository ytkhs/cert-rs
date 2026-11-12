use jiff::Timestamp;
use jiff::tz::TimeZone;
use std::sync::LazyLock;

use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::OidRegistry;
use x509_parser::oid_registry::asn1_rs::{Any, Tag};
use x509_parser::parse_x509_certificate;
use x509_parser::public_key::PublicKey;
use x509_parser::x509::X509Name;

use crate::chain::{ChainEntry, ChainProblem};
use crate::error::ErrorKind;
use crate::validation::{organization, validation_type};

#[derive(serde::Serialize, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct CertInfo {
    pub domain_name: String,
    pub ip: String,
    pub port: String,
    pub issuer: String,
    pub validation_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub organization: String,
    pub common_name: String,
    pub sans: Option<Vec<String>>,
    pub not_before: String,
    pub not_after: String,
    /// RFC 3339 in UTC, for machines; `not_before` and `not_after` are for people.
    pub not_before_utc: Option<String>,
    pub not_after_utc: Option<String>,
    /// Whole days until NotAfter, rounded down; negative once expired.
    pub days_left: Option<i64>,
    pub error: String,
    pub error_kind: Option<ErrorKind>,
    /// Negotiated on the connection: `TLSv1.3`, and the IANA cipher suite name.
    pub tls_version: Option<String>,
    pub cipher_suite: Option<String>,
    /// `RSA`, `EC`, `Ed25519`, `Ed448` or `DSA`; `curve` is set for `EC` only.
    pub key_type: Option<String>,
    pub key_bits: Option<usize>,
    pub curve: Option<String>,
    /// As OpenSSL names it, such as `sha256WithRSAEncryption`.
    pub signature_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<Vec<ChainEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_check: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_problems: Option<Vec<ChainProblem>>,
}

pub fn format_time(t: Timestamp, utc: bool) -> String {
    if utc {
        format_time_in(t, &TimeZone::UTC)
    } else {
        format_time_in(t, &TimeZone::system())
    }
}

pub fn format_time_in(t: Timestamp, tz: &TimeZone) -> String {
    t.to_zoned(tz.clone())
        .strftime("%Y-%m-%d %H:%M:%S %z %Z")
        .to_string()
}

/// Decodes a DirectoryString, reading T61String as Latin-1 and BMPString as UTF-16BE.
pub(crate) fn attribute_string(value: &Any) -> Option<String> {
    match value.tag() {
        Tag::Utf8String | Tag::PrintableString | Tag::Ia5String | Tag::NumericString => {
            std::str::from_utf8(value.data).ok().map(str::to_owned)
        }
        // T.61 is close enough to Latin-1 that common TLS libraries decode it as such.
        Tag::TeletexString => Some(value.data.iter().map(|&b| char::from(b)).collect()),
        Tag::BmpString => {
            let (pairs, odd) = value.data.as_chunks::<2>();
            if !odd.is_empty() {
                return None;
            }
            let units = pairs.iter().map(|&p| u16::from_be_bytes(p));
            Some(
                char::decode_utf16(units)
                    .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
                    .collect(),
            )
        }
        _ => None,
    }
}

// When several CNs are present, the last one wins.
fn last_common_name(name: &X509Name) -> String {
    name.iter_common_name()
        .last()
        .and_then(|cn| attribute_string(cn.attr_value()))
        .unwrap_or_default()
}

pub(crate) fn to_timestamp(t: x509_parser::time::ASN1Time) -> Result<Timestamp, String> {
    Timestamp::from_second(t.timestamp()).map_err(|e| e.to_string())
}

pub fn cert_info_from_der(
    der: &[u8],
    domain: &str,
    ip: &str,
    port: &str,
    utc: bool,
    now: Timestamp,
) -> Result<CertInfo, String> {
    let (_, cert) = parse_x509_certificate(der).map_err(|e| e.to_string())?;
    cert_info(&cert, domain, ip, port, utc, now)
}

const SECONDS_PER_DAY: i64 = 86_400;

pub fn days_left(not_after: Timestamp, now: Timestamp) -> i64 {
    (not_after.as_second() - now.as_second()).div_euclid(SECONDS_PER_DAY)
}

pub fn cert_info(
    cert: &X509Certificate,
    domain: &str,
    ip: &str,
    port: &str,
    utc: bool,
    now: Timestamp,
) -> Result<CertInfo, String> {
    let vt = validation_type(cert);
    let not_before = to_timestamp(cert.validity().not_before)?;
    let not_after = to_timestamp(cert.validity().not_after)?;
    let key = key_info(cert);

    let dns_names: Vec<String> = match cert.subject_alternative_name() {
        Ok(Some(ext)) => ext
            .value
            .general_names
            .iter()
            .filter_map(|n| match n {
                GeneralName::DNSName(s) => Some(s.to_string()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };

    Ok(CertInfo {
        domain_name: domain.to_string(),
        ip: ip.to_string(),
        port: port.to_string(),
        issuer: last_common_name(cert.issuer()),
        validation_type: vt.to_string(),
        organization: organization(cert, vt),
        common_name: last_common_name(cert.subject()),
        sans: if dns_names.is_empty() {
            None
        } else {
            Some(dns_names)
        },
        not_before: format_time(not_before, utc),
        not_after: format_time(not_after, utc),
        not_before_utc: Some(not_before.to_string()),
        not_after_utc: Some(not_after.to_string()),
        days_left: Some(days_left(not_after, now)),
        error: String::new(),
        error_kind: None,
        tls_version: None,
        cipher_suite: None,
        key_type: key.as_ref().map(|k| k.kind.to_string()),
        key_bits: key.as_ref().and_then(|k| k.bits),
        curve: key.and_then(|k| k.curve),
        signature_algorithm: Some(signature_algorithm(cert)),
        chain: None,
        chain_check: None,
        chain_problems: None,
    })
}

struct KeyInfo {
    kind: &'static str,
    bits: Option<usize>,
    curve: Option<String>,
}

const OID_ED25519: &str = "1.3.101.112";
const OID_ED448: &str = "1.3.101.113";

/// Bits of a big-endian unsigned integer, ignoring leading zero bytes.
/// x509-parser's own `key_size` assumes a leading zero byte and returns 0 otherwise.
fn bit_length(bytes: &[u8]) -> usize {
    match bytes.iter().position(|&b| b != 0) {
        Some(i) => (bytes.len() - i - 1) * 8 + (8 - bytes[i].leading_zeros() as usize),
        None => 0,
    }
}

/// Named curve and its size; the size from the point's byte length would
/// round P-521 up to 528.
fn curve(oid: &str) -> Option<(&'static str, usize)> {
    match oid {
        "1.2.840.10045.3.1.7" => Some(("P-256", 256)),
        "1.3.132.0.34" => Some(("P-384", 384)),
        "1.3.132.0.35" => Some(("P-521", 521)),
        _ => None,
    }
}

fn key_info(cert: &X509Certificate) -> Option<KeyInfo> {
    let spki = cert.public_key();
    let algorithm = spki.algorithm.algorithm.to_id_string();
    match algorithm.as_str() {
        OID_ED25519 => {
            return Some(KeyInfo {
                kind: "Ed25519",
                bits: Some(256),
                curve: None,
            });
        }
        OID_ED448 => {
            return Some(KeyInfo {
                kind: "Ed448",
                bits: Some(456),
                curve: None,
            });
        }
        _ => {}
    }
    match spki.parsed().ok()? {
        PublicKey::RSA(rsa) => Some(KeyInfo {
            kind: "RSA",
            bits: Some(bit_length(rsa.modulus)),
            curve: None,
        }),
        PublicKey::EC(point) => {
            let curve_oid = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|oid| oid.to_id_string());
            let point_bits = point.key_size();
            let (curve, bits) = match curve_oid.as_deref().and_then(curve) {
                Some((name, bits)) => (Some(name.to_string()), Some(bits)),
                None => (curve_oid, (point_bits > 0).then_some(point_bits)),
            };
            Some(KeyInfo {
                kind: "EC",
                bits,
                curve,
            })
        }
        PublicKey::DSA(y) => Some(KeyInfo {
            kind: "DSA",
            bits: Some(bit_length(y)),
            curve: None,
        }),
        _ => None,
    }
}

static OIDS: LazyLock<OidRegistry<'static>> =
    LazyLock::new(|| OidRegistry::default().with_crypto().with_x509());

/// Unknown algorithms fall back to the dotted OID.
fn signature_algorithm(cert: &X509Certificate) -> String {
    let oid = &cert.signature_algorithm.algorithm;
    OIDS.get(oid)
        .map(|e| e.sn().to_string())
        .unwrap_or_else(|| oid.to_id_string())
}

pub fn error_info(domain: &str, kind: ErrorKind, err: impl std::fmt::Display) -> CertInfo {
    CertInfo {
        domain_name: domain.to_string(),
        error: err.to_string(),
        error_kind: Some(kind),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_length_ignores_leading_zero_bytes() {
        assert_eq!(bit_length(&[0x00, 0x80, 0x00]), 16);
        assert_eq!(bit_length(&[0x80, 0x00]), 16);
        assert_eq!(bit_length(&[0x01, 0x00]), 9);
        assert_eq!(bit_length(&[0x00]), 0);
    }

    fn key_of(alg: &'static rcgen::SignatureAlgorithm) -> (Option<KeyInfo>, String) {
        let key = rcgen::KeyPair::generate_for(alg).unwrap();
        let params = rcgen::CertificateParams::new(vec!["a.example.com".to_string()]).unwrap();
        let der = params.self_signed(&key).unwrap().der().to_vec();
        let (_, cert) = parse_x509_certificate(&der).unwrap();
        (key_info(&cert), signature_algorithm(&cert))
    }

    #[test]
    fn ec_keys_report_the_named_curve() {
        let (key, sig) = key_of(&rcgen::PKCS_ECDSA_P256_SHA256);
        let key = key.unwrap();
        assert_eq!(
            (key.kind, key.bits, key.curve.as_deref()),
            ("EC", Some(256), Some("P-256"))
        );
        assert_eq!(sig, "ecdsa-with-SHA256");
        let key = key_of(&rcgen::PKCS_ECDSA_P384_SHA384).0.unwrap();
        assert_eq!((key.bits, key.curve.as_deref()), (Some(384), Some("P-384")));
    }

    #[test]
    fn ed25519_is_recognized() {
        let key = key_of(&rcgen::PKCS_ED25519).0.unwrap();
        assert_eq!(
            (key.kind, key.bits, key.curve),
            ("Ed25519", Some(256), None)
        );
    }

    fn decode(tag: Tag, data: &[u8]) -> Option<String> {
        attribute_string(&Any::from_tag_and_data(tag, data))
    }

    #[test]
    fn plain_string_types_pass_through() {
        for tag in [
            Tag::Utf8String,
            Tag::PrintableString,
            Tag::Ia5String,
            Tag::NumericString,
        ] {
            assert_eq!(decode(tag, b"abc 123").as_deref(), Some("abc 123"));
        }
    }

    #[test]
    fn teletex_is_latin1() {
        assert_eq!(
            decode(Tag::TeletexString, b"Caf\xe9").as_deref(),
            Some("Caf\u{e9}")
        );
    }

    #[test]
    fn bmp_is_utf16be() {
        let data = [0x00, 0x41, 0x6a, 0x2a];
        assert_eq!(decode(Tag::BmpString, &data).as_deref(), Some("A\u{6a2a}"));
    }

    #[test]
    fn bmp_with_odd_length_is_rejected() {
        assert_eq!(decode(Tag::BmpString, &[0x00, 0x41, 0x00]), None);
    }

    #[test]
    fn unsupported_tag_is_rejected() {
        assert_eq!(decode(Tag::UniversalString, &[0, 0, 0, 0x41]), None);
    }
}
