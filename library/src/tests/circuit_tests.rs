use llzk::prelude::{BlockLike, LlzkContext, OperationLike, RegionLike, StructDefOpLike};

use super::{
    make_circuit, make_circuit_with_opcodes, make_program, mul_constraint, print_and_verify_module,
    translate_single_circuit, verify_struct_in_module,
};
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
    let struct_def = translate_single_circuit(&context, circuit).unwrap();

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

/// ACIR can skip witness indices (e.g., w0, w1, w5 with no w2–w4). Only witnesses
/// actually referenced by opcodes should become struct members — gaps should not
/// produce phantom members.
#[test]
fn skipped_witness_indices_no_phantom_members() {
    let context = LlzkContext::new();
    // Inputs: w0, w1. Opcode references w5 (large gap, w2–w4 unused).
    // current_witness_index = 5 to satisfy ACIR, but only w5 should be a member.
    let circuit = make_circuit_with_opcodes(5, &[0, 1], &[], &[], vec![mul_constraint(0, 1, 5)]);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();

    let members = struct_def.get_member_defs();
    assert_eq!(
        members.len(),
        1,
        "Should have 1 member (w5 only), not phantom members for w2–w4"
    );

    let ir = format!(
        "{}",
        super::wrap_struct_in_module(&context, struct_def).as_operation()
    );
    println!("skipped_witness_indices_no_phantom_members:\n{ir}");
    assert!(ir.contains("@w5"), "Should contain member @w5");
    assert!(!ir.contains("@w2"), "Should not contain phantom member @w2");
    assert!(!ir.contains("@w3"), "Should not contain phantom member @w3");
    assert!(!ir.contains("@w4"), "Should not contain phantom member @w4");
}
