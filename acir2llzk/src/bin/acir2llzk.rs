//! `acir2llzk` CLI tool entrypoint.

use std::{
    convert::Infallible,
    fs::File,
    io::{self, Read, Write},
    path::PathBuf,
    str::FromStr,
};

use acir2llzk::{
    Driver, Error, FIELD_NAME,
    config::{Config, OutputFormat},
};
use clap::Parser;

fn main() -> Result<(), Error> {
    let config = Cli::new()?;
    let driver = Driver::new(&config);

    let acir_program = driver.load_program()?;
    let llzk_module = driver.translate(&acir_program)?;
    driver.dump_llzk_ir(&llzk_module)
}

/// Possible options for the input file.
#[derive(Debug, Clone)]
enum Input {
    /// Read from stdin.
    Stdin,
    /// Read from a file path.
    File(PathBuf),
}

impl FromStr for Input {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if s == "-" {
            Self::Stdin
        } else {
            Self::File(s.into())
        })
    }
}

/// Possible options for the output file.
#[derive(Debug, Clone)]
enum Output {
    /// Write into stdout.
    Stdout,
    /// Write into a file.
    File(PathBuf),
}

impl FromStr for Output {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if s == "-" {
            Self::Stdout
        } else {
            Self::File(s.into())
        })
    }
}

/// Command line arguments.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// ACIR input file.
    #[arg(default_value = "-")]
    input: Input,
    /// Output LLZK file.
    #[arg(short, long, default_value = "-")]
    output: Output,
    /// Field name used for all felt types and constants.
    #[arg(long, default_value = FIELD_NAME)]
    field: String,
    /// Format of the resulting LLZK IR.
    #[arg(long)]
    emit: Option<OutputFormat>,
    /// Name of the source language (i.e. Noir)
    #[arg(long, default_value = "ACIR")]
    language: String,
}

/// Command line configurator.
#[derive(Debug)]
struct Cli {
    args: Args,
}

impl Cli {
    /// Creates a new instance.
    pub fn new() -> Result<Self, Error> {
        let args = Args::try_parse()?;
        Ok(Self { args })
    }
}

impl Config for Cli {
    /// Returns a readable input.
    fn input_reader(&self) -> io::Result<Box<dyn Read>> {
        match &self.args.input {
            Input::Stdin => Ok(Box::new(io::stdin())),
            Input::File(path) => Ok(Box::new(File::open(&path)?)),
        }
    }

    /// Returns a writable output.
    fn output_writer(&self) -> io::Result<Box<dyn Write>> {
        match &self.args.output {
            Output::Stdout => Ok(Box::new(io::stdout())),
            Output::File(path) => Ok(Box::new(File::create(&path)?)),
        }
    }

    /// Returns the name of the field.
    fn field_name(&self) -> &str {
        &self.args.field
    }

    /// Returns the format in which to print the LLZK output.
    fn output_format(&self) -> OutputFormat {
        self.args.emit.unwrap_or_default()
    }

    /// Returns the name of the source language.
    fn source_language(&self) -> &str {
        &self.args.language
    }
}
