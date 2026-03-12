//! Error types for the acir_llzk crate.

use std::fmt;

use llzk::prelude::LlzkError;

/// Error type for ACIR-to-LLZK translation.
#[derive(Debug)]
pub enum Error {
    /// An ACIR opcode that is not yet supported was encountered.
    UnsupportedOpcode(String),
    /// An error from the underlying LLZK library.
    Llzk(LlzkError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnsupportedOpcode(name) => write!(f, "unsupported ACIR opcode: {name}"),
            Error::Llzk(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Llzk(e) => Some(e),
            _ => None,
        }
    }
}

impl From<LlzkError> for Error {
    fn from(e: LlzkError) -> Self {
        Error::Llzk(e)
    }
}
