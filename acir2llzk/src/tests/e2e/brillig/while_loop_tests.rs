//! End-to-end tests for the `while_loop` Noir fixture: an unconstrained
//! function `count_iterations_to_reach(target)` that loops until a
//! triangular sum reaches `target`, returning the iteration count.
//!
//! These cases exercise the [`StructuredFunction`] loop region across
//! several iteration counts — including the critical `target = 0` case
//! where the loop body never runs at runtime, and any translation-time
//! `Memory` cache state from the body walk must not bleed into the
//! post-loop assertion.

use crate::tests::e2e::{felt_u64, run_e2e_program};
use crate::tests::noir_helpers::{
    circuits_dir, load_program_from_file, nargo_available, nargo_compile,
};

fn run_while_loop(target: u64, expected: u64) {
    assert!(nargo_available(), "nargo not found on PATH");
    let project_dir = circuits_dir().join("while_loop");
    assert!(
        project_dir.exists(),
        "test circuit directory not found: {}",
        project_dir.display()
    );
    let artifact = nargo_compile(&project_dir);
    let program = load_program_from_file(&artifact);

    // Witness-index order matches `main`: target, expected.
    let inputs = [felt_u64(target), felt_u64(expected)];
    let _ = run_e2e_program(&program, &inputs, &[]);
}

#[test]
fn while_loop_zero_iterations() {
    // target = 0: loop condition `sum < 0` is false on entry, so the
    // body never runs. Result is i = 0.
    run_while_loop(0, 0);
}

#[test]
fn while_loop_single_iteration() {
    // target = 1: i=1, sum=1; 1 < 1 is false, exit. Result is 1.
    run_while_loop(1, 1);
}

#[test]
fn while_loop_exact_triangular() {
    // target = 10 = 1+2+3+4. Loop runs 4 times. Result is 4.
    run_while_loop(10, 4);
}

#[test]
fn while_loop_overshoot() {
    // target = 11: 1+2+3+4=10 < 11, then i=5, sum=15 >= 11. Result is 5.
    run_while_loop(11, 5);
}
