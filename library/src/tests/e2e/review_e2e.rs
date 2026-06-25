//! End-to-end differential test against the `nargo execute` (ACVM/Brillig) reference.
//!
//! The existing e2e harness only checks that `@compute` output satisfies
//! `@constrain` of the *same* module — pure self-consistency, which cannot
//! detect an internally-consistent miscompile. This test adds the independent
//! oracle that was missing: every witness our `@compute` produces is compared
//! element-for-element against ACVM's reference witness.

use super::{felt_from_field_element, felt_u64, run_e2e_program};
use crate::tests::noir_helpers::{
    circuits_dir, load_program_from_file, nargo_available, nargo_compile, nargo_execute,
};

/// Differential against `nargo execute` on a known-good fixture (`basic_div`:
/// `a / b == c`). For a correct circuit our `@compute` witness must agree with
/// ACVM's reference witness on every shared witness index. Running this same
/// harness over bug-targeting fixtures (e.g. integer over/underflow, predicated
/// sub-calls) is what surfaces miscompiles the self-consistency harness misses.
///
/// Skips gracefully when `nargo` is not on `PATH` (e.g. minimal CI).
#[test]
fn g1_differential_basic_div_matches_acvm() {
    if !nargo_available() {
        eprintln!("nargo not on PATH; skipping differential test");
        return;
    }
    let project_dir = circuits_dir().join("basic_div");
    let artifact = nargo_compile(&project_dir);
    let program = load_program_from_file(&artifact);

    // Prover.toml: a=6, b=2, c=3.
    let inputs = [felt_u64(6), felt_u64(2), felt_u64(3)];
    let computed = run_e2e_program(&program, &inputs, &[]);

    // Reference witness from ACVM.
    let reference = nargo_execute(&project_dir);

    let mut compared = 0usize;
    for (witness, ref_val) in reference.into_iter() {
        let key = format!("w{}", witness.0);
        if let Some(ours) = computed.members.get(&key) {
            assert_eq!(
                ours,
                &felt_from_field_element(ref_val),
                "differential mismatch at {key}: our @compute disagrees with ACVM"
            );
            compared += 1;
        }
    }
    // Input params are interpreter arguments (block args), not struct members,
    // so the differential covers the internally-solved witnesses (here the
    // Brillig-computed division witness). Every compared witness must match;
    // a future per-witness export of inputs would widen coverage.
    assert!(
        compared >= 1,
        "expected to differentially compare at least one internal witness; compared {compared}"
    );
    println!("differential: {compared} internal witness(es) matched ACVM reference (0 mismatches)");
}
