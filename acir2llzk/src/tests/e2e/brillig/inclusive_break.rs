//! End-to-end tests for the `inclusive_break` Noir fixture: an
//! unconstrained `first_zero_inclusive` that scans a 256-element `u8`
//! array with `for i in 0..=255_u8` and `break`s on the first zero.
//!
//! The inclusive bound equals `u8::MAX`, so Noir lowers the loop as an
//! exclusive loop followed by a "should-execute-final-iteration"
//! diamond. The body's `break` must converge with the loop's natural
//! exit at the diamond's head — these cases drive each convergence
//! path: break before the final iteration, break exactly on `i = 255`,
//! and no break at all (loop runs to completion through the diamond).

use crate::tests::e2e::{assert_witness_eq, felt_u64, run_e2e_program};
use crate::tests::noir_helpers::{
    circuits_dir, load_program_from_file, nargo_available, nargo_compile,
};

const RESULT_WITNESS: &str = "w257";

fn run_inclusive_break(xs: [u8; 256], expected: u32) {
    assert!(nargo_available(), "nargo not found on PATH");
    let project_dir = circuits_dir().join("inclusive_break");
    assert!(
        project_dir.exists(),
        "test circuit directory not found: {}",
        project_dir.display()
    );
    let artifact = nargo_compile(&project_dir);
    let program = load_program_from_file(&artifact);

    // Witness-index order matches `main`: xs[0..256], expected.
    let mut inputs = Vec::with_capacity(257);
    inputs.extend(xs.iter().map(|&v| felt_u64(u64::from(v))));
    inputs.push(felt_u64(u64::from(expected)));
    let computed = run_e2e_program(&program, &inputs, &[]);

    assert_witness_eq(&computed.members, RESULT_WITNESS, &expected.to_string());
}

#[test]
fn inclusive_break_no_zero_runs_to_completion() {
    // No element is zero: loop runs all 256 iterations through the
    // final-iteration diamond and falls through, leaving idx = 256.
    run_inclusive_break([1; 256], 256);
}

#[test]
fn inclusive_break_first_index() {
    // xs[0] = 0: break fires on the very first iteration, idx = 0.
    let mut xs = [1u8; 256];
    xs[0] = 0;
    run_inclusive_break(xs, 0);
}

#[test]
fn inclusive_break_middle_index() {
    // Zero at i = 128: generic mid-loop break, idx = 128.
    let mut xs = [1u8; 256];
    xs[128] = 0;
    run_inclusive_break(xs, 128);
}

#[test]
fn inclusive_break_last_index() {
    // Zero at i = 255: break fires exactly on the inclusive-bound
    // iteration that lives inside the diamond's then-branch. Exercises
    // the convergence between the break and the diamond head.
    let mut xs = [1u8; 256];
    xs[255] = 0;
    run_inclusive_break(xs, 255);
}
