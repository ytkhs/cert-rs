use jiff::Timestamp;
use jiff::tz::TimeZone;
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::asn1_rs::{Any, Tag};
use x509_parser::parse_x509_certificate;
use x509_parser::x509::X509Name;

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
    pub error: String,
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
            if value.data.len() % 2 != 0 {
                return None;
            }
            let units = value
                .data
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]));
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

fn to_timestamp(t: x509_parser::time::ASN1Time) -> Result<Timestamp, String> {
    Timestamp::from_second(t.timestamp()).map_err(|e| e.to_string())
}

pub fn cert_info_from_der(
    der: &[u8],
    domain: &str,
    ip: &str,
    port: &str,
    utc: bool,
) -> Result<CertInfo, String> {
    let (_, cert) = parse_x509_certificate(der).map_err(|e| e.to_string())?;
    let vt = validation_type(&cert);

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
        organization: organization(&cert, vt),
        common_name: last_common_name(cert.subject()),
        sans: if dns_names.is_empty() {
            None
        } else {
            Some(dns_names)
        },
        not_before: format_time(to_timestamp(cert.validity().not_before)?, utc),
        not_after: format_time(to_timestamp(cert.validity().not_after)?, utc),
        error: String::new(),
    })
}

pub fn error_info(domain: &str, err: impl std::fmt::Display) -> CertInfo {
    CertInfo {
        domain_name: domain.to_string(),
        error: err.to_string(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
