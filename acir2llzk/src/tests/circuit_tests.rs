use acir::{
    FieldElement,
    circuit::{Opcode, opcodes::AcirFunctionId},
    native_types::{Expression, Witness},
};
use llzk::prelude::{
    BlockLike, LlzkContext, LlzkModuleBuilder, MemberDefOpLike, OperationLike, RegionLike,
    StructDefOpLike, StructType,
};

use super::{
    first_struct_def, make_circuit, make_circuit_with_opcodes, make_program, mul_constraint,
    print_and_verify_module, translate_single_circuit,
};
use crate::{Driver, FIELD_NAME, tests::TestConfig};

/// A zero-opcode entry circuit with private inputs and no returns lowers to PCL.
#[test]
fn zero_opcodes_verifies() {
    let driver = Driver::new(&TestConfig);
    let circuit = make_circuit(1, &[0, 1], &[], &[]);
    let program = make_program(vec![circuit]);
    let module = driver.translate(&program).unwrap();

    let entry = first_struct_def(&module);
    assert_eq!(entry.member_defs().len(), 1);
    assert!(
        entry
            .find_member_def("__pcl_unit")
            .unwrap()
            .has_public_attr()
    );
    print_and_verify_module(&module, "zero_opcodes_verifies");
}

/// Public input parameters are not output members; they also need a unit return.
#[test]
fn no_returns_lowers_to_pcl_with_no_inputs_or_public_inputs() {
    for public in [&[][..], &[0][..]] {
        let driver = Driver::new(&TestConfig);
        let program = make_program(vec![make_circuit(0, &[], public, &[])]);
        let module = driver.translate(&program).unwrap();
        assert!(
            first_struct_def(&module)
                .find_member_def("__pcl_unit")
                .unwrap()
                .has_public_attr()
        );
        print_and_verify_module(&module, "no_returns_lowers_to_pcl");
    }
}

/// A zero-opcode callee verifies and inlines into a PCL-compatible caller.
#[test]
fn zero_opcode_callee_lowers_to_pcl() {
    let driver = Driver::new(&TestConfig);
    let circuit = make_circuit(1, &[0, 1], &[], &[]);
    assert!(circuit.opcodes.is_empty());
    // Keep the callee empty. The caller supplies the public output PCL needs.
    let caller = make_circuit_with_opcodes(
        2,
        &[0, 1],
        &[],
        &[2],
        vec![
            Opcode::Call {
                id: AcirFunctionId(1),
                inputs: vec![Witness(0), Witness(1)],
                outputs: vec![],
                predicate: Expression::<FieldElement>::one(),
            },
            mul_constraint(0, 1, 2),
        ],
    );
    let program = make_program(vec![caller, circuit]);
    let module = driver.translate(&program).unwrap();

    print_and_verify_module(&module, "zero_opcode_callee_lowers_to_pcl");
}

/// translate_program with 3 circuits → module with 3 struct defs
#[test]
fn three_circuits_three_structs() {
    let driver = Driver::new(&TestConfig);
    let circuits = vec![
        make_circuit(1, &[0, 1], &[], &[]),
        make_circuit(2, &[0], &[1], &[2]),
        make_circuit(0, &[0], &[], &[]),
    ];
    let program = make_program(circuits);
    let module = driver.translate(&program).unwrap();

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
    let mut context = LlzkContext::new();
    context.set_field(FIELD_NAME);
    let module = LlzkModuleBuilder::new(&context)
        .with_language("Noir")
        .with_main(StructType::from_str(&context, "Circuit0"))
        .build();
    // 2 private + 1 public = 3 input params
    let circuit = make_circuit_with_opcodes(3, &[0, 2], &[1], &[3], vec![mul_constraint(0, 2, 3)]);
    let struct_def = translate_single_circuit(&context, circuit, module.body()).unwrap();

    assert!(
        struct_def.find_member_def("__pcl_unit").is_none(),
        "an existing ACIR return must not gain a synthetic output"
    );
    let compute = struct_def.compute_func().expect("Should have @compute");
    let constrain = struct_def.constrain_func().expect("Should have @constrain");

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

    print_and_verify_module(&module, "compute_constrain_parameter_counts");
}

/// ACIR can skip witness indices (e.g., w0, w1, w5 with no w2–w4). Only witnesses
/// actually referenced by opcodes should become struct members — gaps should not
/// produce phantom members.
#[test]
fn skipped_witness_indices_no_phantom_members() {
    let mut context = LlzkContext::new();
    context.set_field(FIELD_NAME);
    let module = LlzkModuleBuilder::new(&context)
        .with_language("Noir")
        .with_main(StructType::from_str(&context, "Circuit0"))
        .build();
    // Inputs: w0, w1. Opcode references w5 (large gap, w2–w4 unused).
    // current_witness_index = 5 to satisfy ACIR, but only w5 should be a member.
    let circuit = make_circuit_with_opcodes(5, &[0, 1], &[], &[], vec![mul_constraint(0, 1, 5)]);
    let struct_def = translate_single_circuit(&context, circuit, module.body()).unwrap();

    let members = struct_def.member_defs();
    assert_eq!(
        members.len(),
        2,
        "Should have w5 and the unit output, not phantom members for w2–w4"
    );

    let ir = format!("{}", module.as_operation());
    println!("skipped_witness_indices_no_phantom_members:\n{ir}");
    assert!(ir.contains("@w5"), "Should contain member @w5");
    assert!(!ir.contains("@w2"), "Should not contain phantom member @w2");
    assert!(!ir.contains("@w3"), "Should not contain phantom member @w3");
    assert!(!ir.contains("@w4"), "Should not contain phantom member @w4");
}
