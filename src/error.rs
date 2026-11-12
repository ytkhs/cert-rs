use std::fmt;

use serde::Serialize;

/// What went wrong with a row, as a fixed value a script or an AI can branch
/// on. `message` wording may change; these values do not.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    InvalidInput,
    Dns,
    Connect,
    Timeout,
    NotTls,
    HandshakeRefused,
    HandshakeFailed,
    Expired,
    NotYetValid,
    NameMismatch,
    Untrusted,
    Revoked,
    WeakSignature,
    MissingIntermediate,
    SentIntermediateOutOfDate,
    CertificateInvalid,
    ParseError,
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub kind: ErrorKind,
    pub message: String,
}

impl Failure {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Failure {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
