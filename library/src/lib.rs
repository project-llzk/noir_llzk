//! A library to compile ACIR programs to LLZK modules
mod circuit;
mod error;
pub mod program;

pub use error::Error;

#[cfg(test)]
mod tests;
