use jiff::Timestamp;
use ring::digest::{SHA256, digest};
use serde::Serialize;
use x509_parser::certificate::X509Certificate;
use x509_parser::parse_x509_certificate;

use crate::cert::format_time;

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

fn parse(der: &[u8]) -> Result<X509Certificate<'_>, String> {
    parse_x509_certificate(der)
        .map(|(_, cert)| cert)
        .map_err(|e| format!("failed to parse certificate: {e}"))
}

fn hex_upper(bytes: &[u8], sep: &str) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(sep)
}

fn timestamp(secs: i64) -> Result<Timestamp, String> {
    Timestamp::from_second(secs).map_err(|e| format!("invalid certificate time: {e}"))
}

pub fn chain_entries(ders: &[&[u8]], utc: bool) -> Result<Vec<ChainEntry>, String> {
    ders.iter()
        .map(|der| {
            let cert = parse(der)?;
            let validity = cert.validity();
            Ok(ChainEntry {
                subject: cert.subject().to_string(),
                issuer: cert.issuer().to_string(),
                not_before: format_time(timestamp(validity.not_before.timestamp())?, utc),
                not_after: format_time(timestamp(validity.not_after.timestamp())?, utc),
                serial: hex_upper(&cert.tbs_certificate.serial.to_bytes_be(), ""),
                sha256: hex_upper(digest(&SHA256, der).as_ref(), ":"),
            })
        })
        .collect()
}

pub fn check_chain(ders: &[&[u8]], now: Timestamp) -> Result<Vec<String>, String> {
    let certs = ders
        .iter()
        .map(|der| parse(der))
        .collect::<Result<Vec<_>, _>>()?;
    let mut problems = Vec::new();
    for (i, pair) in certs.windows(2).enumerate() {
        if pair[0].issuer().as_raw() != pair[1].subject().as_raw() {
            problems.push(format!("[{i}] issuer does not match [{}] subject", i + 1));
        }
    }
    let now = now.as_second();
    for (i, cert) in certs.iter().enumerate() {
        let validity = cert.validity();
        if now < validity.not_before.timestamp() {
            problems.push(format!("[{i}] not yet valid"));
        } else if now > validity.not_after.timestamp() {
            problems.push(format!("[{i}] expired"));
        }
    }
    Ok(problems)
}

pub fn chain_check_label(problems: &[String]) -> String {
    if problems.is_empty() {
        "OK".to_string()
    } else {
        format!("NG: {}", problems.join("; "))
    }
}
