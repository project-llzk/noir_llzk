//! End-to-end tests for the `multi_exit_loop` Noir fixture: an
//! unconstrained `classify` that scans an 8-element array with two
//! `break`s inside the body, producing a loop with multiple exit edges
//! converging on the post-loop block. Each case picks a different exit
//! path so the structurer's multi-exit handling is covered end-to-end.

use crate::tests::e2e::{felt_u64, run_e2e_program};
use crate::tests::noir_helpers::{
    circuits_dir, load_program_from_file, nargo_available, nargo_compile,
};

fn run_multi_exit_loop(xs: [u64; 8], expected: u64) {
    assert!(nargo_available(), "nargo not found on PATH");
    let project_dir = circuits_dir().join("multi_exit_loop");
    assert!(
        project_dir.exists(),
        "test circuit directory not found: {}",
        project_dir.display()
    );
    let artifact = nargo_compile(&project_dir);
    let program = load_program_from_file(&artifact);

    // Witness-index order matches `main`: xs[0..8], expected.
    let mut inputs = Vec::with_capacity(9);
    inputs.extend(xs.iter().map(|&v| felt_u64(v)));
    inputs.push(felt_u64(expected));
    let _ = run_e2e_program(&program, &inputs, &[]);
}

#[test]
fn multi_exit_loop_no_match_falls_through() {
    // No element equals 99 or 100; loop runs to completion and returns 0.
    run_multi_exit_loop([0, 0, 0, 0, 0, 0, 0, 0], 0);
}

#[test]
fn multi_exit_loop_first_break_pair_of_99s() {
    // xs[0]=99 and xs[2]=99: inner-then break fires at i=0, result = 1.
    run_multi_exit_loop([99, 0, 99, 0, 0, 0, 0, 0], 1);
}

#[test]
fn multi_exit_loop_second_break_99_then_9() {
    // xs[5]=99 and xs[7]=9: second nested break fires at i=5, result = 3.
    run_multi_exit_loop([9, 0, 9, 0, 99, 0, 9, 0], 3);
}

#[test]
fn multi_exit_loop_third_break_100_at_head() {
    // xs[0]=100 hits the outer post-nested break at i=0, result = 2.
    run_multi_exit_loop([100, 0, 0, 0, 0, 0, 0, 0], 2);
}

#[test]
fn multi_exit_loop_third_break_100_mid_array() {
    // 100 only appears at i=2: loop iterates twice before breaking, result = 2.
    run_multi_exit_loop([0, 0, 100, 0, 0, 0, 0, 0], 2);
}
