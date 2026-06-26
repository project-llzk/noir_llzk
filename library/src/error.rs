//! Error types for the acir_llzk crate.

use std::fmt;

use acir::FieldElement;
use llzk::prelude::{LlzkError, MeliorError};

/// Error type for ACIR-to-LLZK translation.
#[derive(Debug)]
pub enum Error {
    /// An ACIR opcode that is not yet supported was encountered.
    UnsupportedOpcode(String),
    /// A Brillig construct (opcode, predicate, or marshalling shape) that is
    /// not yet supported was encountered.
    UnsupportedBrillig {
        /// Human-readable reason describing what is unsupported.
        reason: String,
    },
    /// A witness cannot be solved because there are too many unknowns.
    UnsolvableWitness {
        /// The first unknown witness index.
        witness: u32,
        /// How many unknowns were found (expected at most 1).
        num_unknowns: usize,
        /// The opcode index where the error occurred.
        opcode_index: usize,
    },
    /// A gate has exactly one unknown witness but the gate is not linear in
    /// it.
    NonLinearUnknown {
        /// The unknown witness index.
        witness: u32,
    },
    /// A gate has exactly one unknown witness, but every term involving it
    /// has a zero overall coefficient — the gate does not constrain the
    /// unknown.
    UnconstrainedUnknown {
        /// The unknown witness index.
        witness: u32,
    },
    /// A `Call` opcode references a circuit index that does not exist in the program.
    OutOfRangeCallTarget {
        /// The out-of-range circuit index that was requested.
        id: u32,
        /// Total number of circuits in the program.
        num_circuits: usize,
    },
    /// A constant input does not fit in the declared bit width.
    ConstantOutOfRange {
        /// The constant value that exceeds the bit width.
        value: FieldElement,
        /// The declared bit width.
        num_bits: u32,
    },
    /// An error from the underlying LLZK library.
    Llzk(LlzkError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnsupportedOpcode(name) => write!(f, "unsupported ACIR opcode: {name}"),
            Error::UnsupportedBrillig { reason } => {
                write!(f, "unsupported Brillig: {reason}")
            }
            Error::UnsolvableWitness {
                witness,
                num_unknowns,
                opcode_index,
            } => write!(
                f,
                "cannot solve witness w{witness} in opcode {opcode_index}: \
                 {num_unknowns} unknowns (expected at most 1)"
            ),
            Error::NonLinearUnknown { witness } => write!(
                f,
                "cannot solve witness w{witness}: gate is non-linear \
                     in the unknown"
            ),
            Error::UnconstrainedUnknown { witness } => write!(
                f,
                "cannot solve witness w{witness}: \
                 gate does not constrain the unknown (zero coefficient)"
            ),
            Error::OutOfRangeCallTarget { id, num_circuits } => write!(
                f,
                "call targets circuit {id}, but the program only has {num_circuits} circuit(s)"
            ),
            Error::ConstantOutOfRange { value, num_bits } => {
                write!(f, "constant {value} does not fit in {num_bits} bits")
            }
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

impl From<MeliorError> for Error {
    fn from(e: MeliorError) -> Self {
        Error::Llzk(LlzkError::from(e))
    }
}
