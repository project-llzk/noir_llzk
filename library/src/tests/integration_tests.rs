//! End-to-end integration tests that compile real Noir programs with `nargo`,
//! deserialize the ACIR output, run the translation pipeline, and verify the
//! resulting LLZK module.

use llzk::prelude::{LlzkContext, OperationLike};

use super::noir_helpers::{circuits_dir, load_program_from_file, nargo_available, nargo_compile};
use crate::program::translate_program;

/// Core test logic: compile, load, translate, verify.
fn run_noir_test(name: &str) {
    assert!(nargo_available(), "nargo not found on PATH");

    let project_dir = circuits_dir().join(name);
    assert!(
        project_dir.exists(),
        "test circuit directory not found: {}",
        project_dir.display()
    );

    println!("Compiling {name}...");
    let artifact = nargo_compile(&project_dir);

    let program = load_program_from_file(&artifact);
    println!(
        "Loaded ACIR program with {} circuit(s):",
        program.functions.len()
    );

    let context = LlzkContext::new();
    let module = translate_program(&context, &program).unwrap_or_else(|e| {
        panic!("Translation failed for {name}: {e}");
    });

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
fn noir_inclusive_break() {
    run_noir_test("inclusive_break");
}

#[test]
fn noir_panic_after_loop() {
    run_noir_test("panic_in_loop");
}

#[test]
fn noir_multi_exit_loop() {
    run_noir_test("multi_exit_loop");
}

#[test]
fn noir_unconstrained_recursion() {
    run_noir_test("recursive_unconstrained");
}

#[test]
fn noir_mutual_recursion() {
    run_noir_test("mutual_recursion");
}

#[test]
fn noir_aes128() {
    run_noir_test("aes128");
}
