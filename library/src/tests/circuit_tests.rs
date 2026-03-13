use llzk::prelude::{BlockLike, LlzkContext, OperationLike, RegionLike, StructDefOpLike};

use super::{make_circuit, make_program, print_and_verify_module, verify_struct_in_module};
use crate::circuit::translate_circuit;
use crate::program::translate_program;

/// Circuit with 0 opcodes → valid LLZK that passes verify()
#[test]
fn zero_opcodes_verifies() {
    let context = LlzkContext::new();
    let circuit = make_circuit(1, &[0, 1], &[], &[]);
    let program = make_program(vec![circuit]);
    let module = translate_program(&context, &program).unwrap();

    print_and_verify_module(&module, "zero_opcodes_verifies");
}

/// translate_program with 3 circuits → module with 3 struct defs
#[test]
fn three_circuits_three_structs() {
    let context = LlzkContext::new();
    let circuits = vec![
        make_circuit(1, &[0, 1], &[], &[]),
        make_circuit(2, &[0], &[1], &[2]),
        make_circuit(0, &[0], &[], &[]),
    ];
    let program = make_program(circuits);
    let module = translate_program(&context, &program).unwrap();

    let ir = format!("{}", module.as_operation());
    println!("three_circuits_three_structs:\n{ir}");

    // Check all three struct names appear
    assert!(ir.contains("@Circuit0"), "Should contain Circuit0");
    assert!(ir.contains("@Circuit1"), "Should contain Circuit1");
    assert!(ir.contains("@Circuit2"), "Should contain Circuit2");
    assert!(module.as_operation().verify(), "Module should verify");
}

/// Compute and constrain have correct number of parameters
#[test]
fn compute_constrain_parameter_counts() {
    let context = LlzkContext::new();
    // 2 private + 1 public = 3 input params
    let circuit = make_circuit(3, &[0, 2], &[1], &[3]);
    let struct_def = translate_circuit(&context, &circuit, 0).unwrap();

    let compute = struct_def.get_compute_func().expect("Should have @compute");
    let constrain = struct_def
        .get_constrain_func()
        .expect("Should have @constrain");

    // Compute: 3 params (2 private + 1 public), returns struct type
    let compute_block = compute.region(0).unwrap().first_block().unwrap();
    assert_eq!(
        compute_block.argument_count(),
        3,
        "Compute should have 3 parameters"
    );

    // Constrain: 4 params (self + 3 inputs)
    let constrain_block = constrain.region(0).unwrap().first_block().unwrap();
    assert_eq!(
        constrain_block.argument_count(),
        4,
        "Constrain should have 4 parameters (self + 3 inputs)"
    );

    verify_struct_in_module(&context, struct_def, "compute_constrain_parameter_counts");
}
