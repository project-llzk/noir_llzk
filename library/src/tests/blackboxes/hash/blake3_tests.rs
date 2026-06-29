use acir::FieldElement;
use acir::circuit::Opcode;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::native_types::Witness;

use llzk::prelude::{LlzkContext, OperationLike};

use crate::opcodes::{OpcodeEmitter, blake3};
use crate::tests::{count_occurrences, make_circuit_with_opcodes, translate_single_circuit_module};

fn blake3_blackbox(inputs: &[u32], outputs: [u32; 32]) -> Opcode<FieldElement> {
    Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Blake3 {
        inputs: inputs
            .iter()
            .copied()
            .map(|w| FunctionInput::Witness(Witness(w)))
            .collect(),
        outputs: Box::new(outputs.map(Witness)),
    })
}

#[test]
fn blake3_collects_all_witnesses() {
    let outputs = std::array::from_fn(|i| 3 + i as u32);
    let opcode = blake3_blackbox(&[0, 1, 2], outputs);
    let translated = blake3::from_opcode(&opcode)
        .expect("translation should succeed")
        .expect("should parse opcode");

    let witnesses: Vec<u32> = translated.get_witnesses().into_iter().collect();
    assert_eq!(witnesses, (0..35).collect::<Vec<_>>());
}

#[test]
fn blake3_rejects_constant_input_that_does_not_fit_in_byte() {
    let opcode = Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Blake3 {
        inputs: vec![FunctionInput::Constant(FieldElement::from(256u128))],
        outputs: Box::new(std::array::from_fn(|i| Witness(i as u32))),
    });

    let result = blake3::from_opcode(&opcode);
    assert!(matches!(
        result,
        Err(crate::Error::ConstantOutOfRange { num_bits: 8, .. })
    ));
}

#[test]
fn blake3_emits_shared_helper_and_calls_it_from_wrappers() {
    let context = LlzkContext::new();
    let outputs1 = std::array::from_fn(|i| 6 + i as u32);
    let outputs2 = std::array::from_fn(|i| 38 + i as u32);
    let circuit = make_circuit_with_opcodes(
        69,
        &[0, 1, 2, 3, 4, 5],
        &[],
        &outputs2,
        vec![
            blake3_blackbox(&[0, 1, 2], outputs1),
            blake3_blackbox(&[3, 4, 5], outputs2),
        ],
    );

    let module =
        translate_single_circuit_module(&context, circuit).expect("translation should pass");
    let ir = format!("{}", module.as_operation());

    assert!(module.as_operation().verify(), "Module should verify");
    assert_eq!(count_occurrences(&ir, "function.def @blake3_blocks_1"), 1);
    assert_eq!(count_occurrences(&ir, "function.call @blake3_blocks_1"), 4);
    assert!(count_occurrences(&ir, "felt.bit_xor") > 0);
    assert!(count_occurrences(&ir, "felt.shr") > 0);
    assert!(count_occurrences(&ir, "felt.shl") > 0);
}

#[test]
fn blake3_reuses_helper_within_same_block_bucket() {
    let context = LlzkContext::new();
    let outputs1 = std::array::from_fn(|i| 10 + i as u32);
    let outputs2 = std::array::from_fn(|i| 78 + i as u32);
    let circuit = make_circuit_with_opcodes(
        109,
        &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        &[],
        &outputs2,
        vec![
            blake3_blackbox(&[0, 1, 2], outputs1),
            blake3_blackbox(&[3, 4, 5, 6, 7, 8, 9], outputs2),
        ],
    );

    let module =
        translate_single_circuit_module(&context, circuit).expect("translation should pass");
    let ir = format!("{}", module.as_operation());

    assert!(module.as_operation().verify(), "Module should verify");
    assert_eq!(count_occurrences(&ir, "function.def @blake3_blocks_1"), 1);
    assert_eq!(count_occurrences(&ir, "function.call @blake3_blocks_1"), 4);
}

#[test]
fn blake3_emits_distinct_helpers_for_distinct_block_buckets() {
    let context = LlzkContext::new();
    let outputs1 = std::array::from_fn(|i| 68 + i as u32);
    let outputs2 = std::array::from_fn(|i| 100 + i as u32);
    let short_inputs = [0u32, 1, 2];
    let long_inputs: Vec<u32> = (3..68).collect();
    let mut private_inputs = short_inputs.to_vec();
    private_inputs.extend(long_inputs.iter().copied());
    let circuit = make_circuit_with_opcodes(
        131,
        &private_inputs,
        &[],
        &outputs2,
        vec![
            blake3_blackbox(&short_inputs, outputs1),
            blake3_blackbox(&long_inputs, outputs2),
        ],
    );

    let module =
        translate_single_circuit_module(&context, circuit).expect("translation should pass");
    let ir = format!("{}", module.as_operation());

    assert!(module.as_operation().verify(), "Module should verify");
    assert_eq!(count_occurrences(&ir, "function.def @blake3_blocks_1"), 1);
    assert_eq!(count_occurrences(&ir, "function.def @blake3_blocks_2"), 1);
    assert_eq!(count_occurrences(&ir, "function.call @blake3_blocks_1"), 2);
    assert_eq!(count_occurrences(&ir, "function.call @blake3_blocks_2"), 2);
}

#[test]
fn blake3_does_not_emit_helper_when_unused() {
    let context = LlzkContext::new();
    let circuit = make_circuit_with_opcodes(
        2,
        &[0, 1],
        &[],
        &[2],
        vec![crate::tests::mul_constraint(0, 1, 2)],
    );

    let module =
        translate_single_circuit_module(&context, circuit).expect("translation should pass");
    let ir = format!("{}", module.as_operation());

    assert!(module.as_operation().verify(), "Module should verify");
    assert_eq!(count_occurrences(&ir, "function.def @blake3_blocks_"), 0);
    assert_eq!(count_occurrences(&ir, "function.call @blake3_blocks_"), 0);
}

#[test]
fn blake3_with_constant_inputs_translates() {
    let context = LlzkContext::new();
    let circuit = make_circuit_with_opcodes(
        31,
        &[],
        &[],
        &(0..32).collect::<Vec<_>>(),
        vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Blake3 {
            inputs: vec![
                FunctionInput::Constant(FieldElement::from('a' as u128)),
                FunctionInput::Constant(FieldElement::from('b' as u128)),
                FunctionInput::Constant(FieldElement::from('c' as u128)),
            ],
            outputs: Box::new(std::array::from_fn(|i| Witness(i as u32))),
        })],
    );

    let module =
        translate_single_circuit_module(&context, circuit).expect("translation should pass");
    assert!(module.as_operation().verify(), "Module should verify");
}

#[test]
fn blake3_witness_inputs_emit_byte_range_constraints() {
    let context = LlzkContext::new();
    let inputs = [0u32, 1, 2];
    let outputs: [u32; 32] = std::array::from_fn(|i| 3 + i as u32);
    let circuit = make_circuit_with_opcodes(
        34,
        &inputs,
        &[],
        &outputs,
        vec![blake3_blackbox(&inputs, outputs)],
    );

    let module =
        translate_single_circuit_module(&context, circuit).expect("translation should pass");
    let ir = format!("{}", module.as_operation());

    assert!(module.as_operation().verify(), "Module should verify");
    assert_eq!(
        count_occurrences(&ir, "cast.tofelt"),
        inputs.len(),
        "each witness byte input should emit one range-check cast"
    );
}
