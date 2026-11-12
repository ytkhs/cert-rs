mod common;

use cert_rs::cert::{cert_info_from_der, days_left, error_info, format_time, format_time_in};
use cert_rs::error::ErrorKind;
use common::make_cert;

const OV: &[u64] = &[2, 23, 140, 1, 2, 2];

#[test]
fn format_time_utc() {
    let t: jiff::Timestamp = "2026-10-07T19:09:54Z".parse().unwrap();
    assert_eq!(format_time(t, true), "2026-10-07 19:09:54 +0000 UTC");
}

#[test]
fn format_time_local_jst() {
    let tz = jiff::tz::TimeZone::get("Asia/Tokyo").unwrap();
    let t: jiff::Timestamp = "2026-10-07T19:09:54Z".parse().unwrap();
    assert_eq!(format_time_in(t, &tz), "2026-10-08 04:09:54 +0900 JST");
}

#[test]
fn fields_from_der() {
    let (der, _) = make_cert(
        Some("Acme"),
        &[OV],
        false,
        &["a.example.com", "*.example.com"],
    );
    let info = cert_info_from_der(&der, "a.example.com", "192.0.2.1", "443", true, now()).unwrap();
    assert_eq!(info.domain_name, "a.example.com");
    assert_eq!(info.ip, "192.0.2.1");
    assert_eq!(info.port, "443");
    assert_eq!(info.common_name, "a.example.com");
    assert_eq!(info.issuer, "a.example.com");
    assert_eq!(
        info.sans,
        Some(vec![
            "a.example.com".to_string(),
            "*.example.com".to_string()
        ])
    );
    assert_eq!(info.validation_type, "OV");
    assert_eq!(info.organization, "Acme");
    assert_eq!(info.error, "");
    assert!(info.not_before.ends_with("+0000 UTC"));
    assert!(info.not_after.ends_with("+0000 UTC"));
}

#[test]
fn error_info_shape() {
    let e = error_info("x.example", ErrorKind::Dns, "boom");
    assert_eq!(e.error_kind, Some(ErrorKind::Dns));
    assert_eq!(e.days_left, None);
    assert_eq!(e.domain_name, "x.example");
    assert_eq!(e.error, "boom");
    assert!(e.sans.is_none());
    assert_eq!(e.port, "");
}

fn cert_with_names(cn: rcgen::DnValue, org: Option<rcgen::DnValue>) -> Vec<u8> {
    let mut params = rcgen::CertificateParams::new(vec!["a.example.com".to_string()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    if let Some(org) = org {
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, org);
    }
    let key = rcgen::KeyPair::generate().unwrap();
    params.self_signed(&key).unwrap().der().to_vec()
}

#[test]
fn teletex_common_name_is_read() {
    let cn = rcgen::DnValue::TeletexString("*.example.com".try_into().unwrap());
    let der = cert_with_names(cn, None);
    let info = cert_info_from_der(&der, "a.example.com", "192.0.2.1", "443", true, now()).unwrap();
    assert_eq!(info.common_name, "*.example.com");
    assert_eq!(info.issuer, "*.example.com");
    assert_eq!(info.validation_type, "DV");
}

#[test]
fn bmp_organization_counts_as_ov_and_is_shown() {
    let cn = rcgen::DnValue::BmpString("a.example.com".try_into().unwrap());
    let org = rcgen::DnValue::BmpString("Acmé 株式会社".try_into().unwrap());
    let der = cert_with_names(cn, Some(org));
    let info = cert_info_from_der(&der, "a.example.com", "192.0.2.1", "443", true, now()).unwrap();
    assert_eq!(info.common_name, "a.example.com");
    assert_eq!(info.validation_type, "OV");
    assert_eq!(info.organization, "Acmé 株式会社");
}

fn now() -> jiff::Timestamp {
    "2026-06-01T00:00:00Z".parse().unwrap()
}

#[test]
fn days_left_rounds_down_and_goes_negative_once_expired() {
    let at = |s: &str| -> jiff::Timestamp { s.parse().unwrap() };
    let now = at("2026-06-01T12:00:00Z");
    assert_eq!(days_left(at("2026-06-03T11:59:59Z"), now), 1);
    assert_eq!(days_left(at("2026-06-03T12:00:00Z"), now), 2);
    assert_eq!(days_left(at("2026-06-01T12:00:00Z"), now), 0);
    assert_eq!(days_left(at("2026-06-01T11:00:00Z"), now), -1);
}

#[test]
fn machine_readable_times_are_rfc3339_utc() {
    let (der, _) = make_cert(None, &[], false, &["a.example.com"]);
    let info = cert_info_from_der(&der, "a.example.com", "192.0.2.1", "443", false, now()).unwrap();
    let not_after = info.not_after_utc.unwrap();
    assert!(not_after.ends_with('Z'), "{not_after}");
    assert!(not_after.parse::<jiff::Timestamp>().is_ok(), "{not_after}");
    assert!(info.days_left.is_some());
    assert_eq!(info.error_kind, None);
}
