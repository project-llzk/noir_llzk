//! Error types for the acir_llzk crate.

use std::fmt;

use llzk::prelude::LlzkError;

/// Error type for ACIR-to-LLZK translation.
#[derive(Debug)]
pub enum Error {
    /// An ACIR opcode that is not yet supported was encountered.
    UnsupportedOpcode(String),
    /// A witness cannot be solved because there are too many unknowns.
    UnsolvableWitness {
        /// The first unknown witness index.
        witness: u32,
        /// How many unknowns were found (expected at most 1).
        num_unknowns: usize,
        /// The opcode index where the error occurred.
        opcode_index: usize,
    },
    /// An error from the underlying LLZK library.
    Llzk(LlzkError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnsupportedOpcode(name) => write!(f, "unsupported ACIR opcode: {name}"),
            Error::UnsolvableWitness {
                witness,
                num_unknowns,
                opcode_index,
            } => write!(
                f,
                "cannot solve witness w{witness} in opcode {opcode_index}: \
                 {num_unknowns} unknowns (expected at most 1)"
            ),
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
