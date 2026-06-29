use acir::FieldElement;
use acir::circuit::Opcode;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::native_types::Witness;

use llzk::prelude::{LlzkContext, OperationLike};

use crate::opcodes::aes128;
use crate::tests::{count_occurrences, make_circuit_with_opcodes, translate_single_circuit_module};

fn aes128_blackbox(
    inputs: Vec<FunctionInput<FieldElement>>,
    outputs: Vec<Witness>,
) -> Opcode<FieldElement> {
    let iv: [FunctionInput<FieldElement>; 16] =
        std::array::from_fn(|i| FunctionInput::Witness(Witness(1000 + i as u32)));
    let key: [FunctionInput<FieldElement>; 16] =
        std::array::from_fn(|i| FunctionInput::Witness(Witness(2000 + i as u32)));
    Opcode::BlackBoxFuncCall(BlackBoxFuncCall::AES128Encrypt {
        inputs,
        iv: Box::new(iv),
        key: Box::new(key),
        outputs,
    })
}

#[test]
fn aes128_rejects_non_block_aligned_input_length() {
    let inputs: Vec<FunctionInput<FieldElement>> = (0..15)
        .map(|i| FunctionInput::Witness(Witness(i)))
        .collect();
    let outputs: Vec<Witness> = (100..115).map(Witness).collect();
    let opcode = aes128_blackbox(inputs, outputs);

    let result = aes128::from_opcode(&opcode);
    assert!(matches!(result, Err(crate::Error::UnsupportedOpcode(_))));
}

#[test]
fn aes128_rejects_output_length_mismatch() {
    let inputs: Vec<FunctionInput<FieldElement>> = (0..16)
        .map(|i| FunctionInput::Witness(Witness(i)))
        .collect();
    let outputs: Vec<Witness> = (100..132).map(Witness).collect();
    let opcode = aes128_blackbox(inputs, outputs);

    let result = aes128::from_opcode(&opcode);
    assert!(matches!(result, Err(crate::Error::UnsupportedOpcode(_))));
}

#[test]
fn aes128_rejects_constant_input_that_does_not_fit_in_byte() {
    let mut inputs: Vec<FunctionInput<FieldElement>> = (0..15)
        .map(|i| FunctionInput::Witness(Witness(i)))
        .collect();
    inputs.push(FunctionInput::Constant(FieldElement::from(256u128)));
    let outputs: Vec<Witness> = (100..116).map(Witness).collect();
    let opcode = aes128_blackbox(inputs, outputs);

    let result = aes128::from_opcode(&opcode);
    assert!(matches!(
        result,
        Err(crate::Error::ConstantOutOfRange { num_bits: 8, .. })
    ));
}

/// Each byte of plaintext, iv, and key gets a `< 2^8` range constraint in
/// `@constrain` when it's a witness. AES128's helper does not emit
/// `cast.tofelt` internally, so each `cast.tofelt` is one range-check.
#[test]
fn aes128_witness_inputs_emit_byte_range_constraints() {
    let context = LlzkContext::new();
    let plaintext: [u32; 16] = std::array::from_fn(|i| i as u32);
    let iv: [u32; 16] = std::array::from_fn(|i| 16 + i as u32);
    let key: [u32; 16] = std::array::from_fn(|i| 32 + i as u32);
    let outputs: [u32; 16] = std::array::from_fn(|i| 48 + i as u32);

    let private: Vec<u32> = (0..48).collect();
    let circuit = make_circuit_with_opcodes(
        63,
        &private,
        &[],
        &outputs,
        vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::AES128Encrypt {
            inputs: plaintext
                .iter()
                .map(|&w| FunctionInput::Witness(Witness(w)))
                .collect(),
            iv: Box::new(iv.map(|w| FunctionInput::Witness(Witness(w)))),
            key: Box::new(key.map(|w| FunctionInput::Witness(Witness(w)))),
            outputs: outputs.iter().copied().map(Witness).collect(),
        })],
    );

    let module =
        translate_single_circuit_module(&context, circuit).expect("translation should pass");
    let ir = format!("{}", module.as_operation());

    assert!(module.as_operation().verify(), "Module should verify");
    assert_eq!(
        count_occurrences(&ir, "cast.tofelt"),
        plaintext.len() + iv.len() + key.len(),
        "every byte of plaintext+iv+key should emit one range-check cast"
    );
}
