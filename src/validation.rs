use std::fmt;

use serde::Serialize;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::ParsedExtension;
use x509_parser::oid_registry::{Oid, asn1_rs::oid};

use crate::cert::attribute_string;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ValidationType {
    DV,
    OV,
    EV,
}

impl fmt::Display for ValidationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ValidationType::DV => "DV",
            ValidationType::OV => "OV",
            ValidationType::EV => "EV",
        })
    }
}

const CABF_EV: Oid<'static> = oid!(2.23.140.1.1);
const CABF_DV: Oid<'static> = oid!(2.23.140.1.2.1);
const CABF_OV: Oid<'static> = oid!(2.23.140.1.2.2);
const BUSINESS_CATEGORY: Oid<'static> = oid!(2.5.4.15);
const SERIAL_NUMBER: Oid<'static> = oid!(2.5.4.5);
const JURISDICTION_LOCALITY: Oid<'static> = oid!(1.3.6.1.4.1.311.60.2.1.1);
const JURISDICTION_STATE: Oid<'static> = oid!(1.3.6.1.4.1.311.60.2.1.2);
const JURISDICTION_COUNTRY: Oid<'static> = oid!(1.3.6.1.4.1.311.60.2.1.3);

fn has_policy(cert: &X509Certificate, policy: &Oid) -> bool {
    cert.iter_extensions()
        .any(|ext| match ext.parsed_extension() {
            ParsedExtension::CertificatePolicies(infos) => {
                infos.iter().any(|info| info.policy_id == *policy)
            }
            _ => false,
        })
}

fn has_subject_attribute(cert: &X509Certificate, oid: &Oid) -> bool {
    cert.subject()
        .iter_attributes()
        .any(|a| a.attr_type() == oid)
}

fn organizations(cert: &X509Certificate) -> Vec<String> {
    cert.subject()
        .iter_organization()
        .filter_map(|a| attribute_string(a.attr_value()))
        .collect()
}

// Same decoding as the displayed value, so an OV verdict always comes with an Organization.
fn has_organization(cert: &X509Certificate) -> bool {
    !organizations(cert).is_empty()
}

fn is_ev(cert: &X509Certificate) -> bool {
    if has_policy(cert, &CABF_EV) {
        return true;
    }
    has_organization(cert)
        && has_subject_attribute(cert, &BUSINESS_CATEGORY)
        && has_subject_attribute(cert, &SERIAL_NUMBER)
        && [
            JURISDICTION_COUNTRY,
            JURISDICTION_STATE,
            JURISDICTION_LOCALITY,
        ]
        .iter()
        .any(|oid| has_subject_attribute(cert, oid))
}

pub fn validation_type(cert: &X509Certificate) -> ValidationType {
    if is_ev(cert) {
        ValidationType::EV
    } else if has_policy(cert, &CABF_OV) {
        ValidationType::OV
    } else if has_policy(cert, &CABF_DV) {
        ValidationType::DV
    } else if has_organization(cert) {
        ValidationType::OV
    } else {
        ValidationType::DV
    }
}

pub fn organization(cert: &X509Certificate, vt: ValidationType) -> String {
    if vt == ValidationType::DV {
        return String::new();
    }
    organizations(cert).join(", ")
}
