//! Shared helpers for tests that compile real Noir programs via `nargo`
//! and consume the resulting ACIR/Brillig artifacts.

use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::load_program;

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

pub(crate) fn load_program_from_file(
    artifact_path: &Path,
) -> acir::circuit::Program<acir::FieldElement> {
    let json_str = read_to_string(artifact_path)
        .unwrap_or_else(|e| panic!("failed to read {:?}: {e}", artifact_path));
    load_program(&json_str).unwrap_or_else(|e| panic!("failed to load program: {e}"))
}
