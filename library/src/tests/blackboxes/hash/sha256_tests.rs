use acir::FieldElement;
use acir::circuit::Opcode;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::native_types::Witness;

use llzk::prelude::{LlzkContext, OperationLike};

use crate::opcodes::{OpcodeEmitter, sha256};
use crate::tests::{count_occurrences, make_circuit_with_opcodes, translate_single_circuit_module};

fn sha256_blackbox(
    inputs: [u32; 16],
    hash_values: [u32; 8],
    outputs: [u32; 8],
) -> Opcode<FieldElement> {
    Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Sha256Compression {
        inputs: Box::new(inputs.map(|w| FunctionInput::Witness(Witness(w)))),
        hash_values: Box::new(hash_values.map(|w| FunctionInput::Witness(Witness(w)))),
        outputs: Box::new(outputs.map(Witness)),
    })
}

#[test]
fn sha256_collects_all_witnesses() {
    let inputs: [u32; 16] = std::array::from_fn(|i| i as u32);
    let hash_values: [u32; 8] = std::array::from_fn(|i| 16 + i as u32);
    let outputs: [u32; 8] = std::array::from_fn(|i| 24 + i as u32);
    let opcode = sha256_blackbox(inputs, hash_values, outputs);
    let translated = sha256::from_opcode(&opcode)
        .expect("translation should succeed")
        .expect("should parse opcode");

    let witnesses: Vec<u32> = translated.get_witnesses().into_iter().collect();
    assert_eq!(witnesses, (0..32).collect::<Vec<_>>());
}

#[test]
fn sha256_emits_shared_helper_and_calls_it() {
    let context = LlzkContext::new();
    let inputs: [u32; 16] = std::array::from_fn(|i| i as u32);
    let hash_values: [u32; 8] = std::array::from_fn(|i| 16 + i as u32);
    let outputs: [u32; 8] = std::array::from_fn(|i| 24 + i as u32);
    let circuit = make_circuit_with_opcodes(
        31,
        &(0..24).collect::<Vec<_>>(),
        &[],
        &outputs,
        vec![sha256_blackbox(inputs, hash_values, outputs)],
    );

    let module =
        translate_single_circuit_module(&context, circuit).expect("translation should pass");
    let ir = format!("{}", module.as_operation());

    assert!(module.as_operation().verify(), "Module should verify");
    assert_eq!(
        count_occurrences(&ir, "function.def @sha256_compression"),
        1
    );
    // Called once from compute, once from constrain.
    assert_eq!(
        count_occurrences(&ir, "function.call @sha256_compression"),
        2
    );
    assert!(count_occurrences(&ir, "felt.bit_and") > 0);
    assert!(count_occurrences(&ir, "felt.bit_xor") > 0);
    assert!(count_occurrences(&ir, "felt.shr") > 0);
}

#[test]
fn sha256_does_not_emit_helper_when_unused() {
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
    assert_eq!(
        count_occurrences(&ir, "function.def @sha256_compression"),
        0
    );
}

#[test]
fn sha256_with_constant_inputs_translates() {
    let context = LlzkContext::new();
    let outputs: [u32; 8] = std::array::from_fn(|i| i as u32);
    let circuit = make_circuit_with_opcodes(
        7,
        &[],
        &[],
        &outputs,
        vec![Opcode::BlackBoxFuncCall(
            BlackBoxFuncCall::Sha256Compression {
                inputs: Box::new(std::array::from_fn(|_| {
                    FunctionInput::Constant(FieldElement::from(0u128))
                })),
                hash_values: Box::new(std::array::from_fn(|_| {
                    FunctionInput::Constant(FieldElement::from(0u128))
                })),
                outputs: Box::new(outputs.map(Witness)),
            },
        )],
    );

    let module =
        translate_single_circuit_module(&context, circuit).expect("translation should pass");
    assert!(module.as_operation().verify(), "Module should verify");
}

#[test]
fn sha256_rejects_oversized_constant_input() {
    let opcode = Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Sha256Compression {
        inputs: Box::new(std::array::from_fn(|i| {
            if i == 0 {
                // Value that doesn't fit in u32
                FunctionInput::Constant(FieldElement::from(1u128 << 33))
            } else {
                FunctionInput::Constant(FieldElement::from(0u128))
            }
        })),
        hash_values: Box::new(std::array::from_fn(|_| {
            FunctionInput::Constant(FieldElement::from(0u128))
        })),
        outputs: Box::new(std::array::from_fn(|i| Witness(i as u32))),
    });

    let result = sha256::from_opcode(&opcode);
    assert!(matches!(
        result,
        Err(crate::Error::ConstantOutOfRange { num_bits: 32, .. })
    ));
}

#[test]
fn sha256_rejects_oversized_constant_hash_value() {
    let opcode = Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Sha256Compression {
        inputs: Box::new(std::array::from_fn(|_| {
            FunctionInput::Constant(FieldElement::from(0u128))
        })),
        hash_values: Box::new(std::array::from_fn(|i| {
            if i == 0 {
                FunctionInput::Constant(FieldElement::from(1u128 << 33))
            } else {
                FunctionInput::Constant(FieldElement::from(0u128))
            }
        })),
        outputs: Box::new(std::array::from_fn(|i| Witness(i as u32))),
    });

    let result = sha256::from_opcode(&opcode);
    assert!(matches!(
        result,
        Err(crate::Error::ConstantOutOfRange { num_bits: 32, .. })
    ));
}

#[test]
fn sha256_two_calls_share_one_helper() {
    let context = LlzkContext::new();
    // All inputs are private params (0..47), outputs are separate (48..63).
    let inputs1: [u32; 16] = std::array::from_fn(|i| i as u32);
    let hv1: [u32; 8] = std::array::from_fn(|i| 16 + i as u32);
    let out1: [u32; 8] = std::array::from_fn(|i| 48 + i as u32);
    let inputs2: [u32; 16] = std::array::from_fn(|i| 24 + i as u32);
    let hv2: [u32; 8] = std::array::from_fn(|i| 40 + i as u32);
    let out2: [u32; 8] = std::array::from_fn(|i| 56 + i as u32);

    let private_inputs: Vec<u32> = (0..48).collect();
    let circuit = make_circuit_with_opcodes(
        63,
        &private_inputs,
        &[],
        &out2,
        vec![
            sha256_blackbox(inputs1, hv1, out1),
            sha256_blackbox(inputs2, hv2, out2),
        ],
    );

    let module =
        translate_single_circuit_module(&context, circuit).expect("translation should pass");
    let ir = format!("{}", module.as_operation());

    assert!(module.as_operation().verify(), "Module should verify");
    // One shared helper, called 4 times (2 compute + 2 constrain).
    assert_eq!(
        count_occurrences(&ir, "function.def @sha256_compression"),
        1
    );
    assert_eq!(
        count_occurrences(&ir, "function.call @sha256_compression"),
        4
    );
}

/// Each witness input and hash_value gets a `< 2^32` range constraint in
/// `@constrain`. Each `cast.tofelt` is one range-check.
#[test]
fn sha256_witness_inputs_emit_u32_range_constraints() {
    let context = LlzkContext::new();
    let inputs: [u32; 16] = std::array::from_fn(|i| i as u32);
    let hash_values: [u32; 8] = std::array::from_fn(|i| 16 + i as u32);
    let outputs: [u32; 8] = std::array::from_fn(|i| 24 + i as u32);
    let circuit = make_circuit_with_opcodes(
        31,
        &(0..24).collect::<Vec<_>>(),
        &[],
        &outputs,
        vec![sha256_blackbox(inputs, hash_values, outputs)],
    );

    let module =
        translate_single_circuit_module(&context, circuit).expect("translation should pass");
    let ir = format!("{}", module.as_operation());

    assert!(module.as_operation().verify(), "Module should verify");
    assert_eq!(
        count_occurrences(&ir, "cast.tofelt"),
        inputs.len() + hash_values.len(),
        "every input and hash_value witness should emit one range-check cast"
    );
}
