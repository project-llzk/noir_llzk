//! End-to-end test for the `const_in_branch` Noir fixture: an
//! unconstrained `if x > 10 { x + 42 } else { x + 7 }`. Each arm emits
//! its own `Const` opcode at the same Brillig slot, exercising the
//! cross-arm `known_constants` discipline of `Memory`: the cache must
//! not leak the then-arm's tracked value into the else-arm walk, and
//! must not leak the else-arm's value into post-branch code.

use crate::tests::e2e::{assert_witness_eq, felt_u64, run_e2e_program};
use crate::tests::noir_helpers::{
    circuits_dir, load_program_from_file, nargo_available, nargo_compile,
};

#[test]
fn const_in_branch_then_arm() {
    assert!(nargo_available(), "nargo not found on PATH");

    let project_dir = circuits_dir().join("const_in_branch");
    assert!(
        project_dir.exists(),
        "test circuit directory not found: {}",
        project_dir.display()
    );

    let artifact = nargo_compile(&project_dir);
    let program = load_program_from_file(&artifact);

    // x = 11 takes the `x > 10` arm: result is 11 + 42 = 53.
    let inputs = [felt_u64(11)];
    let computed = run_e2e_program(&program, &inputs, &[]);
    assert_witness_eq(&computed.members, "w1", "53");
    assert_witness_eq(&computed.members, "w2", "53");
}

#[test]
fn const_in_branch_else_arm() {
    assert!(nargo_available(), "nargo not found on PATH");

    let project_dir = circuits_dir().join("const_in_branch");
    let artifact = nargo_compile(&project_dir);
    let program = load_program_from_file(&artifact);

    // x = 1 takes the `else` arm: result is 1 + 7 = 8.
    let inputs = [felt_u64(1)];
    let computed = run_e2e_program(&program, &inputs, &[]);
    assert_witness_eq(&computed.members, "w1", "8");
    assert_witness_eq(&computed.members, "w2", "8");
}
