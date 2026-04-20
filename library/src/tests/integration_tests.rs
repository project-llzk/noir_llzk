//! End-to-end integration tests that compile real Noir programs with `nargo`,
//! deserialize the ACIR output, run the translation pipeline, and verify the
//! resulting LLZK module.
//!
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use std::process::Command;

use llzk::prelude::{LlzkContext, OperationLike};

use crate::{load_program, program::translate_program};

/// Returns the path to the `noir_examples` directory.
fn circuits_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("noir_examples")
}

/// Returns true if `nargo` is available on PATH.
fn nargo_available() -> bool {
    Command::new("nargo")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Compiles a Noir project and returns the path to the JSON artifact.
fn nargo_compile(project_dir: &Path) -> PathBuf {
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

    // Get the project name, this will be the name of the compiled noir code file
    let nargo_toml = project_dir.join("Nargo.toml");
    let toml_str = read_to_string(&nargo_toml)
        .unwrap_or_else(|e| panic!("failed to read {:?}: {e}", nargo_toml));
    let toml: toml::Value = toml_str
        .parse()
        .unwrap_or_else(|e| panic!("failed to parse {:?}: {e}", nargo_toml));
    let name = toml["package"]["name"]
        .as_str()
        .expect("missing package.name in Nargo.toml");

    // Construct the path and return
    project_dir.join("target").join(format!("{name}.json"))
}

/// Loads an ACIR program from a nargo JSON artifact file.
fn load_program_from_file(artifact_path: &Path) -> acir::circuit::Program<acir::FieldElement> {
    let json_str = read_to_string(artifact_path)
        .unwrap_or_else(|e| panic!("failed to read {:?}: {e}", artifact_path));
    load_program(&json_str).unwrap_or_else(|e| panic!("failed to load program: {e}"))
}

/// Core test logic: compile, load, translate, verify.
fn run_noir_test(name: &str) {
    assert!(nargo_available(), "nargo not found on PATH");

    let project_dir = circuits_dir().join(name);
    assert!(
        project_dir.exists(),
        "test circuit directory not found: {}",
        project_dir.display()
    );

    // Compile and execute
    println!("Compiling {name}...");
    let artifact = nargo_compile(&project_dir);

    // Load ACIR
    let program = load_program_from_file(&artifact);
    println!(
        "Loaded ACIR program with {} circuit(s):",
        program.functions.len()
    );

    // Translate
    let context = LlzkContext::new();
    let module = translate_program(&context, &program).unwrap_or_else(|e| {
        panic!("Translation failed for {name}: {e}");
    });

    // Verify
    assert!(
        module.as_operation().verify(),
        "LLZK module verification failed for {name}"
    );
    println!("{name}: OK");
}

// ── tests ────────────────────────────────────────────────────────────────────

#[test]
fn noir_single_mul() {
    run_noir_test("polynomial");
}

#[test]
fn noir_linear_assert() {
    run_noir_test("circuit_call");
}

#[test]
fn noir_bitwise_blackboxes() {
    run_noir_test("bitwise");
}

#[test]
fn noir_memory_ops() {
    run_noir_test("memory_ops");
}

#[test]
fn noir_poseidon2() {
    run_noir_test("poseidon2");
}

#[test]
fn noir_blake2s() {
    run_noir_test("blake2s");
}

#[test]
fn noir_blake3() {
    run_noir_test("blake3");
}

#[test]
fn noir_sha256() {
    run_noir_test("sha256");
}

#[test]
fn noir_keccak() {
    run_noir_test("keccak");
}

#[test]
fn noir_aes128() {
    run_noir_test("aes128");
}
