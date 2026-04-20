use acir::FieldElement;
use acir::circuit::Opcode;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::native_types::Witness;

use crate::opcodes::aes128;

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
