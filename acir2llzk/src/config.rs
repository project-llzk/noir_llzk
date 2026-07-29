//! Tool configuration.

use std::io::{self, Read, Write};

use clap::ValueEnum;

/// Possible output formats for LLZK IR.
#[derive(ValueEnum, Debug, Copy, Clone, Default)]
pub enum OutputFormat {
    /// Emit the LLZK IR in plain text.
    #[default]
    Assembly,
    /// Emit the LLZK IR in binary format.
    Bytecode,
}

/// Central trait for handling configuration.
pub trait Config {
    /// Returns a readable input.
    fn input_reader(&self) -> io::Result<Box<dyn Read>>;

    /// Returns a writable output.
    fn output_writer(&self) -> io::Result<Box<dyn Write>>;

    /// Returns the name of the field.
    fn field_name(&self) -> &str;

    /// Returns the format in which to print the LLZK output.
    fn output_format(&self) -> OutputFormat;

    /// Returns the name of the source language.
    fn source_language(&self) -> &str;
}
