use acir::FieldElement;
use acir::circuit::Opcode;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::native_types::Witness;

use llzk::prelude::{LlzkContext, OperationLike};

use crate::opcodes::{OpcodeEmitter, blake2s};
use crate::tests::{count_occurrences, make_circuit_with_opcodes, translate_single_circuit_module};

fn blake2s_blackbox(inputs: &[u32], outputs: [u32; 32]) -> Opcode<FieldElement> {
    Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Blake2s {
        inputs: inputs
            .iter()
            .copied()
            .map(|w| FunctionInput::Witness(Witness(w)))
            .collect(),
        outputs: Box::new(outputs.map(Witness)),
    })
}

#[test]
fn blake2s_collects_all_witnesses() {
    let outputs = std::array::from_fn(|i| 3 + i as u32);
    let opcode = blake2s_blackbox(&[0, 1, 2], outputs);
    let translated = blake2s::from_opcode(&opcode)
        .expect("translation should succeed")
        .expect("should parse opcode");

    let witnesses: Vec<u32> = translated.get_witnesses().into_iter().collect();
    assert_eq!(witnesses, (0..35).collect::<Vec<_>>());
}

#[test]
fn blake2s_rejects_constant_input_that_does_not_fit_in_byte() {
    let opcode = Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Blake2s {
        inputs: vec![FunctionInput::Constant(FieldElement::from(256u128))],
        outputs: Box::new(std::array::from_fn(|i| Witness(i as u32))),
    });

    let result = blake2s::from_opcode(&opcode);
    assert!(matches!(
        result,
        Err(crate::Error::ConstantOutOfRange { num_bits: 8, .. })
    ));
}

#[test]
fn blake2s_emits_shared_helper_and_calls_it_from_wrappers() {
    let context = LlzkContext::new();
    let outputs1 = std::array::from_fn(|i| 6 + i as u32);
    let outputs2 = std::array::from_fn(|i| 38 + i as u32);
    let circuit = make_circuit_with_opcodes(
        69,
        &[0, 1, 2, 3, 4, 5],
        &[],
        &outputs2,
        vec![
            blake2s_blackbox(&[0, 1, 2], outputs1),
            blake2s_blackbox(&[3, 4, 5], outputs2),
        ],
    );

    let module =
        translate_single_circuit_module(&context, circuit).expect("translation should pass");
    let ir = format!("{}", module.as_operation());

    assert!(module.as_operation().verify(), "Module should verify");
    assert_eq!(count_occurrences(&ir, "function.def @blake2s_3"), 1);
    assert_eq!(count_occurrences(&ir, "function.call @blake2s_3"), 4);
    assert!(count_occurrences(&ir, "felt.bit_xor") > 0);
    assert!(count_occurrences(&ir, "felt.shr") > 0);
    assert!(count_occurrences(&ir, "felt.shl") > 0);
}

#[test]
fn blake2s_emits_distinct_helpers_for_distinct_input_lengths() {
    let context = LlzkContext::new();
    let outputs1 = std::array::from_fn(|i| 8 + i as u32);
    let outputs2 = std::array::from_fn(|i| 45 + i as u32);
    let circuit = make_circuit_with_opcodes(
        76,
        &[0, 1, 2, 3, 4, 5, 6, 7],
        &[],
        &outputs2,
        vec![
            blake2s_blackbox(&[0, 1, 2], outputs1),
            blake2s_blackbox(&[3, 4, 5, 6, 7], outputs2),
        ],
    );

    let module =
        translate_single_circuit_module(&context, circuit).expect("translation should pass");
    let ir = format!("{}", module.as_operation());

    assert!(module.as_operation().verify(), "Module should verify");
    assert_eq!(count_occurrences(&ir, "function.def @blake2s_3"), 1);
    assert_eq!(count_occurrences(&ir, "function.def @blake2s_5"), 1);
    assert_eq!(count_occurrences(&ir, "function.call @blake2s_3"), 2);
    assert_eq!(count_occurrences(&ir, "function.call @blake2s_5"), 2);
}

#[test]
fn blake2s_does_not_emit_helper_when_unused() {
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
    assert_eq!(count_occurrences(&ir, "function.def @blake2s_"), 0);
    assert_eq!(count_occurrences(&ir, "function.call @blake2s_"), 0);
}

#[test]
fn blake2s_with_constant_inputs_translates() {
    let context = LlzkContext::new();
    let circuit = make_circuit_with_opcodes(
        31,
        &[],
        &[],
        &(0..32).collect::<Vec<_>>(),
        vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Blake2s {
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
