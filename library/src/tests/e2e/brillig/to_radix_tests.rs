//! End-to-end test for the `to_radix` Noir fixture
use llzk::prelude::LlzkContext;

use crate::program::translate_program;
use crate::tests::e2e::{Interpreter, assert_witness_eq, felt_u64};
use crate::tests::noir_helpers::{
    circuits_dir, load_program_from_file, nargo_available, nargo_compile,
};
use crate::tests::print_and_verify_module;

/// Runs the `to_radix` Noir fixture against multiple `u32` inputs while
/// compiling and translating the circuit only once.
fn run_to_radix_cases(inputs: &[u32]) {
    assert!(nargo_available(), "nargo not found on PATH");
    let project_dir = circuits_dir().join("to_radix");
    assert!(
        project_dir.exists(),
        "test circuit directory not found: {}",
        project_dir.display()
    );
    let artifact = nargo_compile(&project_dir);
    let program = load_program_from_file(&artifact);

    let context = LlzkContext::new();
    let module = translate_program(&context, &program).expect("translation should succeed");

    print_and_verify_module(&module, "to_radix");
    for &input in inputs {
        let inputs_felt = [felt_u64(u64::from(input))];

        let mut interpreter = Interpreter::new(&module);
        let computed = interpreter
            .run_compute("Circuit0", &inputs_felt)
            .unwrap_or_else(|e| panic!("compute should succeed for 0x{input:08x}: {e:?}"));
        interpreter
            .run_constrain("Circuit0", computed.clone(), &inputs_felt)
            .unwrap_or_else(|e| panic!("constrain should succeed for 0x{input:08x}: {e:?}"));

        // w1..w4 are the output_bytes of the noir circuit
        // w5..w8 are the outputs of the brillig function
        let bytes = input.to_be_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            let keys = [format!("w{}", i + 1), format!("w{}", i + 5)];
            for key in keys {
                assert_witness_eq(&computed.members, &key, &b.to_string());
            }
        }
    }
}

#[test]
fn test_to_radix_decomp() {
    run_to_radix_cases(&[0x12345678, 0, u32::MAX]);
}
