use jiff::Timestamp;
use ring::digest::{SHA256, digest};
use serde::Serialize;
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::asn1_rs::Any;
use x509_parser::parse_x509_certificate;
use x509_parser::prelude::FromDer;
use x509_parser::x509::{AttributeTypeAndValue, RelativeDistinguishedName, X509Name};

use crate::cert::{attribute_string, format_time, to_timestamp};

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChainEntry {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub serial: String,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ChainReport {
    pub entries: Vec<ChainEntry>,
    pub problems: Vec<String>,
}

impl ChainReport {
    pub fn label(&self) -> String {
        if self.problems.is_empty() {
            "OK".to_string()
        } else {
            format!("NG: {}", self.problems.join("; "))
        }
    }
}

/// Subjects of the roots the OS trusts, to tell a leaf issued straight from a
/// root apart from one whose intermediate was left out.
#[derive(Clone, Debug, Default)]
pub struct TrustAnchors {
    subjects: Vec<Vec<u8>>,
}

impl TrustAnchors {
    /// A root missing from `ders` only risks a false NG.
    pub fn from_ders<'a>(ders: impl IntoIterator<Item = &'a [u8]>) -> Self {
        let subjects = ders
            .into_iter()
            .filter_map(|der| parse_x509_certificate(der).ok())
            .map(|(_, cert)| cert.subject().as_raw().to_vec())
            .collect();
        TrustAnchors { subjects }
    }

    fn contains(&self, name: &X509Name) -> bool {
        self.subjects.iter().any(|raw| {
            X509Name::from_der(raw).is_ok_and(|(_, subject)| names_match(name, &subject))
        })
    }
}

pub type Parsed<'a> = Result<X509Certificate<'a>, String>;

pub fn parse_chain<'a>(ders: &[&'a [u8]]) -> Vec<Parsed<'a>> {
    ders.iter()
        .map(|der| {
            parse_x509_certificate(der)
                .map(|(_, cert)| cert)
                .map_err(|e| e.to_string())
        })
        .collect()
}

fn hex_upper(bytes: &[u8], sep: &str) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(sep)
}

/// Formats the serial as openssl does: the integer's value, so DER sign padding
/// is dropped and a negative serial gets a minus sign.
fn serial_hex(raw: &[u8]) -> String {
    let negative = raw.first().is_some_and(|b| b & 0x80 != 0);
    let mut magnitude = raw.to_vec();
    if negative {
        for b in magnitude.iter_mut() {
            *b = !*b;
        }
        for b in magnitude.iter_mut().rev() {
            let (sum, carry) = b.overflowing_add(1);
            *b = sum;
            if !carry {
                break;
            }
        }
    }
    let first = magnitude
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(magnitude.len().saturating_sub(1));
    let hex = hex_upper(&magnitude[first..], "");
    if negative { format!("-{hex}") } else { hex }
}

/// RFC 4518 reduced to what certificates use in practice: decoded text,
/// whitespace runs folded to one space, case ignored.
fn normalized(value: &Any) -> Option<String> {
    attribute_string(value).map(|s| {
        s.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
    })
}

fn attributes_match(a: &AttributeTypeAndValue, b: &AttributeTypeAndValue) -> bool {
    if a.attr_type() != b.attr_type() {
        return false;
    }
    let (va, vb) = (a.attr_value(), b.attr_value());
    if va.tag() == vb.tag() && va.data == vb.data {
        return true;
    }
    matches!((normalized(va), normalized(vb)), (Some(x), Some(y)) if x == y)
}

// A multi-valued RDN is a set, so its attributes may come in any order.
fn rdns_match(a: &RelativeDistinguishedName, b: &RelativeDistinguishedName) -> bool {
    let (a, b): (Vec<_>, Vec<_>) = (a.iter().collect(), b.iter().collect());
    a.len() == b.len() && a.iter().all(|x| b.iter().any(|y| attributes_match(x, y)))
}

/// Name matching per RFC 5280 7.1, so differing string types or letter case still match.
fn names_match(a: &X509Name, b: &X509Name) -> bool {
    a.as_raw() == b.as_raw()
        || (a.iter().count() == b.iter().count()
            && a.iter().zip(b.iter()).all(|(x, y)| rdns_match(x, y)))
}

/// `certs` must be `parse_chain(ders)`; it is passed in so the caller can reuse the leaf.
pub fn inspect_chain(
    ders: &[&[u8]],
    certs: &[Parsed<'_>],
    anchors: &TrustAnchors,
    utc: bool,
    now: Timestamp,
) -> ChainReport {
    let mut problems = Vec::new();
    let mut entries = Vec::new();
    for (i, (der, cert)) in ders.iter().zip(certs).enumerate() {
        let sha256 = hex_upper(digest(&SHA256, der).as_ref(), ":");
        let cert = match cert {
            Ok(cert) => cert,
            Err(e) => {
                problems.push(format!("[{i}] failed to parse certificate: {e}"));
                entries.push(ChainEntry {
                    subject: String::new(),
                    issuer: String::new(),
                    not_before: String::new(),
                    not_after: String::new(),
                    serial: String::new(),
                    sha256,
                });
                continue;
            }
        };
        let validity = cert.validity();
        let mut time = |t| match to_timestamp(t) {
            Ok(t) => format_time(t, utc),
            Err(e) => {
                problems.push(format!("[{i}] invalid certificate time: {e}"));
                String::new()
            }
        };
        entries.push(ChainEntry {
            subject: cert.subject().to_string(),
            issuer: cert.issuer().to_string(),
            not_before: time(validity.not_before),
            not_after: time(validity.not_after),
            serial: serial_hex(cert.raw_serial()),
            sha256,
        });
    }

    for (i, pair) in certs.windows(2).enumerate() {
        // An unparsed side was already reported above.
        if let [Ok(child), Ok(parent)] = pair
            && !names_match(child.issuer(), parent.subject())
        {
            problems.push(format!("[{i}] issuer does not match [{}] subject", i + 1));
        }
    }

    // A lone certificate that someone else issued means the intermediate was
    // left out, unless a trusted root issued it directly (as private CAs may).
    // Whether verification passed cannot tell: some platform verifiers fetch
    // the missing intermediate themselves. Longer chains may legitimately stop
    // before the root, so they are not judged.
    if let [Ok(leaf)] = certs
        && !names_match(leaf.issuer(), leaf.subject())
        && !anchors.contains(leaf.issuer())
    {
        problems.push("[0] issuer certificate not sent".to_string());
    }

    let now = now.as_second();
    for (i, cert) in certs.iter().enumerate() {
        let Ok(cert) = cert else { continue };
        let validity = cert.validity();
        if now < validity.not_before.timestamp() {
            problems.push(format!("[{i}] not yet valid"));
        } else if now > validity.not_after.timestamp() {
            problems.push(format!("[{i}] expired"));
        }
    }

    ChainReport { entries, problems }
}

#[cfg(test)]
mod tests {
    use super::serial_hex;

    #[test]
    fn serial_drops_sign_padding() {
        assert_eq!(serial_hex(&[0x00, 0x8A, 0x1B]), "8A1B");
    }

    #[test]
    fn serial_drops_nonconforming_leading_zeros() {
        assert_eq!(serial_hex(&[0x00, 0x00, 0x05]), "05");
    }

    #[test]
    fn serial_zero_is_a_single_byte() {
        assert_eq!(serial_hex(&[0x00]), "00");
    }

    #[test]
    fn negative_serial_gets_minus_sign() {
        assert_eq!(serial_hex(&[0xFF]), "-01");
        assert_eq!(serial_hex(&[0x80]), "-80");
        assert_eq!(serial_hex(&[0xFE, 0x00]), "-0200");
    }
}
