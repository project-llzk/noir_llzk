//! A library to compile ACIR programs to LLZK modules
mod blackboxes;
mod block_writer;
mod brillig_writer;
mod circuit;
mod common;
mod error;
mod multiprec;
mod opcodes;
pub mod program;

pub use error::Error;

use acir::{FieldElement, circuit::Program};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

#[cfg(test)]
mod tests;

/// The field name used for all felt types and constants.
const FIELD_NAME: &str = "bn254";

/// Deserializes an ACIR [`Program`] from the JSON string of a nargo artifact.
pub fn load_program(json_str: &str) -> Result<Program<FieldElement>, String> {
    let json: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("JSON parse error: {e}"))?;

    let bytecode_b64 = json
        .get("bytecode")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "JSON artifact missing 'bytecode' string field".to_string())?;

    let bytecode = STANDARD
        .decode(bytecode_b64)
        .map_err(|e| format!("base64 decode error: {e}"))?;

    Program::deserialize_program(&bytecode).map_err(|e| format!("ACIR deserialization error: {e}"))
}
