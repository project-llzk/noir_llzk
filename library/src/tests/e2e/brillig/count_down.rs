//! End-to-end tests for the `recursive_unconstrained` Noir fixture: an
//! unconstrained `count_down(n)` that recurses on `n - 1` until `n == 0`.

use crate::tests::e2e::{assert_witness_eq, felt_u64, run_e2e_program};
use crate::tests::noir_helpers::{
    circuits_dir, load_program_from_file, nargo_available, nargo_compile,
};

const RESULT_WITNESS: &str = "w2";

fn run_count_down(n: u64) {
    assert!(nargo_available(), "nargo not found on PATH");
    let project_dir = circuits_dir().join("recursive_unconstrained");
    assert!(
        project_dir.exists(),
        "test circuit directory not found: {}",
        project_dir.display()
    );
    let artifact = nargo_compile(&project_dir);
    let program = load_program_from_file(&artifact);

    let inputs = [felt_u64(n), felt_u64(n)];
    let computed = run_e2e_program(&program, &inputs, &[]);
    assert_witness_eq(&computed.members, RESULT_WITNESS, &n.to_string());
}

#[test]
fn count_down_zero() {
    // Base case — `count_down` returns immediately, no recursion frame.
    run_count_down(0);
}

#[test]
fn count_down_one() {
    // One recursive call: a single SP bump and restore.
    run_count_down(1);
}

#[test]
fn count_down_three() {
    // Three nested calls — exercises repeated frame management.
    run_count_down(3);
}
