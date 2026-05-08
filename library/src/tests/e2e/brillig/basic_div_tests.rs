//! End-to-end test for the `basic_div` Noir fixture: a single
//! `assert(a / b == c)` over `Field`. Field division forces nargo to
//! emit a brillig block that computes `b^{-1}`, so this exercises the
//! constrain side (the multiplicative check) alongside a minimal
//! brillig program on the compute side.

use crate::tests::e2e::{felt_u64, run_e2e_program};
use crate::tests::noir_helpers::{
    circuits_dir, load_program_from_file, nargo_available, nargo_compile,
};

#[test]
fn basic_div_satisfying_witness_verifies() {
    assert!(nargo_available(), "nargo not found on PATH");

    let project_dir = circuits_dir().join("basic_div");
    assert!(
        project_dir.exists(),
        "test circuit directory not found: {}",
        project_dir.display()
    );

    let artifact = nargo_compile(&project_dir);
    let program = load_program_from_file(&artifact);

    // Witness-index order matches `main`'s parameter list: a, b, c.
    // 6 / 2 == 3.
    let inputs = [felt_u64(6), felt_u64(2), felt_u64(3)];

    let _computed = run_e2e_program(&program, &inputs, &[]);
}
