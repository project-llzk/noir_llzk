//! A library to compile ACIR programs to LLZK modules
mod circuit;
mod common;
mod compute;
mod constrain;
mod error;
mod opcode;
pub mod program;

pub use error::Error;

/// The field name used for all felt types and constants.
const FIELD_NAME: &str = "bn254";

#[cfg(test)]
mod tests;
