mod common;

use cert_rs::validation::{ValidationType, organization, validation_type};
use common::make_cert;
use x509_parser::parse_x509_certificate;

const EV: &[u64] = &[2, 23, 140, 1, 1];
const DV: &[u64] = &[2, 23, 140, 1, 2, 1];
const OV: &[u64] = &[2, 23, 140, 1, 2, 2];

fn classify(org: Option<&str>, policies: &[&[u64]], ev_attrs: bool) -> (ValidationType, String) {
    let (der, _) = make_cert(org, policies, ev_attrs, &["example.com"]);
    let (_, cert) = parse_x509_certificate(&der).unwrap();
    let vt = validation_type(&cert);
    (vt, organization(&cert, vt))
}

#[test]
fn ev_by_policy() {
    assert_eq!(
        classify(Some("Acme"), &[EV], false),
        (ValidationType::EV, "Acme".into())
    );
}

#[test]
fn ev_by_subject_attrs_without_policy() {
    assert_eq!(classify(Some("Acme"), &[], true).0, ValidationType::EV);
}

#[test]
fn ev_attrs_without_org_is_not_ev() {
    assert_eq!(classify(None, &[], true).0, ValidationType::DV);
}

#[test]
fn ov_by_policy() {
    assert_eq!(
        classify(Some("Acme"), &[OV], false),
        (ValidationType::OV, "Acme".into())
    );
}

#[test]
fn dv_by_policy_hides_org() {
    assert_eq!(
        classify(Some("Acme"), &[DV], false),
        (ValidationType::DV, String::new())
    );
}

#[test]
fn fallback_org_means_ov() {
    assert_eq!(classify(Some("Acme"), &[], false).0, ValidationType::OV);
}

#[test]
fn fallback_no_org_means_dv() {
    assert_eq!(classify(None, &[], false).0, ValidationType::DV);
}

#[test]
fn ov_policy_wins_over_dv_policy() {
    assert_eq!(classify(None, &[DV, OV], false).0, ValidationType::OV);
}

#[test]
fn display_is_plain_string() {
    assert_eq!(ValidationType::EV.to_string(), "EV");
}
