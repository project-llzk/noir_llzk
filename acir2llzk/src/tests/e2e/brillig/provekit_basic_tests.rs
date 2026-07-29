//! End-to-end test for the `provekit_basic` Noir fixture: a Poseidon2-t2
//! permutation over a public input pair, asserted against a precomputed
//! output. Exercises ACIR + Brillig translation against real nargo
//! output and verifies the satisfying witness from `Prover.toml`.

use crate::tests::e2e::{felt_from_hex, felt_u64, run_e2e_program};
use crate::tests::noir_helpers::{
    circuits_dir, load_program_from_file, nargo_available, nargo_compile,
};

/// Witness from `noir_examples/provekit_basic/Prover.toml`:
///
/// ```toml
/// plains = [1, 2]
/// result = '0x0e90c132311e864e0c8bca37976f28579a2dd9436bbc11326e21ec7c00cea5b2'
/// ```
const PROVEKIT_BASIC_RESULT_HEX: &str =
    "0x0e90c132311e864e0c8bca37976f28579a2dd9436bbc11326e21ec7c00cea5b2";

#[test]
fn provekit_basic_satisfying_witness_verifies() {
    assert!(nargo_available(), "nargo not found on PATH");

    let project_dir = circuits_dir().join("provekit_basic");
    assert!(
        project_dir.exists(),
        "test circuit directory not found: {}",
        project_dir.display()
    );

    let artifact = nargo_compile(&project_dir);
    let program = load_program_from_file(&artifact);

    // Inputs in witness-index order: plains[0], plains[1], result.
    let inputs = [
        felt_u64(1),
        felt_u64(2),
        felt_from_hex(PROVEKIT_BASIC_RESULT_HEX),
    ];

    let _computed = run_e2e_program(&program, &inputs, &[]);
}
