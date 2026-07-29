//! Shared helpers for tests that compile real Noir programs via `nargo`
//! and consume the resulting ACIR/Brillig artifacts.

use std::fs::{read_to_string, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::{Config, OutputFormat};
use crate::FIELD_NAME;

pub(crate) struct NargoConfig {
    pub(crate) artifact: PathBuf,
}

impl Config for NargoConfig {
    fn input_reader(&self) -> io::Result<Box<dyn Read>> {
        Ok(Box::new(File::open(&self.artifact)?))
    }

    fn output_writer(&self) -> io::Result<Box<dyn io::Write>> {
        unimplemented!()
    }

    fn field_name(&self) -> &str {
        FIELD_NAME
    }

    fn output_format(&self) -> OutputFormat {
        unimplemented!()
    }

    fn source_language(&self) -> &str {
        "ACIR"
    }
}

pub(crate) fn circuits_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("noir_examples")
}

pub(crate) fn nargo_available() -> bool {
    Command::new("nargo")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn package_name(project_dir: &Path) -> String {
    let nargo_toml = project_dir.join("Nargo.toml");
    let toml_str = read_to_string(&nargo_toml)
        .unwrap_or_else(|e| panic!("failed to read {:?}: {e}", nargo_toml));
    let toml: toml::Value = toml_str
        .parse()
        .unwrap_or_else(|e| panic!("failed to parse {:?}: {e}", nargo_toml));
    toml["package"]["name"]
        .as_str()
        .expect("missing package.name in Nargo.toml")
        .to_string()
}

pub(crate) fn nargo_compile(project_dir: &Path) -> PathBuf {
    let status = Command::new("nargo")
        .arg("compile")
        .current_dir(project_dir)
        .status()
        .expect("failed to run nargo compile");
    assert!(
        status.success(),
        "nargo compile failed for {}",
        project_dir.display()
    );

    let name = package_name(project_dir);
    project_dir.join("target").join(format!("{name}.json"))
}
