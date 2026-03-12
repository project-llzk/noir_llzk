
use acir::FieldElement;
use acir::circuit::{Circuit, Program, PublicInputs};
use acir::native_types::Witness;
use llzk::prelude::{
    BlockLike, LlzkContext, Location, MemberDefOpLike, OperationLike, RegionLike, StructDefOpLike,
    llzk_module,
};

use crate::circuit::translate_circuit;
use crate::program::translate_program;

/// Helper to build a Circuit with specified witness count, private params,
/// public params, and return values.
fn make_circuit(
    current_witness_index: u32,
    private: &[u32],
    public: &[u32],
    returns: &[u32],
) -> Circuit<FieldElement> {
    Circuit {
        function_name: "test".to_string(),
        current_witness_index,
        opcodes: vec![],
        private_parameters: private.iter().map(|&i| Witness(i)).collect(),
        public_parameters: PublicInputs(public.iter().map(|&i| Witness(i)).collect()),
        return_values: PublicInputs(returns.iter().map(|&i| Witness(i)).collect()),
        assert_messages: vec![],
    }
}

fn make_program(circuits: Vec<Circuit<FieldElement>>) -> Program<FieldElement> {
    Program {
        functions: circuits,
        unconstrained_functions: vec![],
    }
}

/// Circuit with 1 private witness, 0 public → struct with 1 member, no {llzk.pub}
#[test]
fn single_private_witness_no_public() {
    let context = LlzkContext::new();
    // 1 witness (w0), private only
    let circuit = make_circuit(1, &[0], &[], &[]);
    let struct_def = translate_circuit(&context, &circuit, 0).unwrap();

    // Should have 1 member
    let members = struct_def.get_member_defs();
    assert_eq!(members.len(), 1, "Should have exactly 1 member");
    assert_eq!(members[0].member_name(), "w0");
    assert!(
        !members[0].has_public_attr(),
        "Private witness should not have llzk.pub"
    );

    // Wrap in module and verify
    let location = Location::unknown(&context);
    let module = llzk_module(location);
    module.body().append_operation(struct_def.into());
    let ir = format!("{}", module.as_operation());
    println!("single_private_witness_no_public:\n{ir}");
    assert!(module.as_operation().verify(), "Module should verify");
}

/// Circuit with 2 private, 1 public input, 1 public return → correct pub annotations
#[test]
fn mixed_private_public_annotations() {
    let context = LlzkContext::new();
    // 4 witnesses: w0 private, w1 public input, w2 private, w3 public return
    let circuit = make_circuit(4, &[0, 2], &[1], &[3]);
    let struct_def = translate_circuit(&context, &circuit, 0).unwrap();

    let members = struct_def.get_member_defs();
    assert_eq!(members.len(), 4, "Should have 4 members");

    // Check public annotations
    assert!(!members[0].has_public_attr(), "w0 is private");
    assert!(members[1].has_public_attr(), "w1 is public (input)");
    assert!(!members[2].has_public_attr(), "w2 is private");
    assert!(members[3].has_public_attr(), "w3 is public (return)");

    // Wrap in module and verify
    let location = Location::unknown(&context);
    let module = llzk_module(location);
    module.body().append_operation(struct_def.into());
    let ir = format!("{}", module.as_operation());
    println!("mixed_private_public_annotations:\n{ir}");
    assert!(module.as_operation().verify(), "Module should verify");
}

/// Circuit with 0 opcodes → valid LLZK that passes verify()
#[test]
fn zero_opcodes_verifies() {
    let context = LlzkContext::new();
    let circuit = make_circuit(2, &[0, 1], &[], &[]);
    let program = make_program(vec![circuit]);
    let module = translate_program(&context, &program).unwrap();

    let ir = format!("{}", module.as_operation());
    println!("zero_opcodes_verifies:\n{ir}");
    assert!(module.as_operation().verify(), "Module should verify");
}

/// translate_program with 3 circuits → module with 3 struct defs
#[test]
fn three_circuits_three_structs() {
    let context = LlzkContext::new();
    let circuits = vec![
        make_circuit(2, &[0, 1], &[], &[]),
        make_circuit(3, &[0], &[1], &[2]),
        make_circuit(1, &[0], &[], &[]),
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
    let circuit = make_circuit(4, &[0, 2], &[1], &[3]);
    let struct_def = translate_circuit(&context, &circuit, 0).unwrap();

    let compute = struct_def.get_compute_func().expect("Should have @compute");
    let constrain = struct_def
        .get_constrain_func()
        .expect("Should have @constrain");

    // Compute: 3 params (2 private + 1 public), returns struct type
    let compute_block = compute.region(0).unwrap().first_block().unwrap();
    // Block arguments = function parameters
    // compute_fn helper creates a block with the input params
    let mut compute_arg_count = 0;
    while compute_block.argument(compute_arg_count).is_ok() {
        compute_arg_count += 1;
    }
    assert_eq!(compute_arg_count, 3, "Compute should have 3 parameters");

    // Constrain: 4 params (self + 3 inputs)
    let constrain_block = constrain.region(0).unwrap().first_block().unwrap();
    let mut constrain_arg_count = 0;
    while constrain_block.argument(constrain_arg_count).is_ok() {
        constrain_arg_count += 1;
    }
    assert_eq!(
        constrain_arg_count, 4,
        "Constrain should have 4 parameters (self + 3 inputs)"
    );

    // Verify the whole thing
    let location = Location::unknown(&context);
    let module = llzk_module(location);
    module.body().append_operation(struct_def.into());
    assert!(module.as_operation().verify(), "Module should verify");
}
