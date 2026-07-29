//! A library to compile ACIR programs to LLZK modules
mod blackboxes;
mod block_writer;
mod brillig;
mod brillig_writer;
mod circuit;
mod common;
pub mod config;
pub mod error;
mod multiprec;
mod opcodes;
mod program;
mod writer;

use acir::{circuit::Program, FieldElement};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
pub use error::Error;
use llzk::prelude::{LlzkContext, Module, ModuleExt as _};
use program::translate_program;

use crate::config::{Config, OutputFormat};

#[cfg(test)]
mod tests;

/// The field name used for all felt types and constants.
pub const FIELD_NAME: &str = "bn254";

/// A result produced by the driver.
pub type DriverResult<T> = Result<T, Error>;

/// Handles the orchestration of ACIR to LLZK compilation.
pub struct Driver<'c> {
    config: &'c dyn Config,
    ctx: LlzkContext,
}

impl<'c> Driver<'c> {
    /// Creates a new driver.
    pub fn new(config: &'c dyn Config) -> Self {
        let mut ctx = LlzkContext::new();
        ctx.set_field(config.field_name());
        Self { config, ctx }
    }

    /// Returns a reference to the LLZK context.
    pub fn context(&self) -> &LlzkContext {
        &self.ctx
    }

    /// Deserializes an ACIR [`Program`] from the input file.
    pub fn load_program(&self) -> DriverResult<Program<FieldElement>> {
        let json: serde_json::Value = serde_json::from_reader(self.config.input_reader()?)
            .map_err(|e| Error::Loading(format!("JSON parse error: {e}")))?;

        let bytecode_b64 = json
            .get("bytecode")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                Error::Loading("JSON artifact missing 'bytecode' string field".to_string())
            })?;

        let bytecode = STANDARD
            .decode(bytecode_b64)
            .map_err(|e| Error::Loading(format!("base64 decode error: {e}")))?;

        Program::deserialize_program(&bytecode)
            .map_err(|e| Error::Loading(format!("ACIR deserialization error: {e}")))
    }

    /// Translates the ACIR [`Program`] into a LLZK [`Module`]
    pub fn translate<'d>(&'d self, program: &Program<FieldElement>) -> DriverResult<Module<'d>> {
        translate_program(&self.ctx, program, self.config.source_language())
    }

    /// Writes the resulting module.
    pub fn dump_llzk_ir<'d>(&'d self, module: &Module<'d>) -> DriverResult<()> {
        let mut writer = self.config.output_writer()?;
        match self.config.output_format() {
            OutputFormat::Assembly => writeln!(&mut writer, "{}", module.as_operation())?,
            OutputFormat::Bytecode => module.write_bytecode(&mut writer)?,
        }
        Ok(())
    }
}
