use acir::FieldElement;
use acir::circuit::Opcode;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::native_types::Witness;

use llzk::prelude::{LlzkContext, OperationLike};

use crate::opcodes::keccak;
use crate::tests::{count_occurrences, make_circuit_with_opcodes, translate_single_circuit_module};

const STATE_WORDS: usize = 25;

fn keccak_blackbox(
    inputs: [u32; STATE_WORDS],
    outputs: [u32; STATE_WORDS],
) -> Opcode<FieldElement> {
    Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Keccakf1600 {
        inputs: Box::new(inputs.map(|w| FunctionInput::Witness(Witness(w)))),
        outputs: Box::new(outputs.map(Witness)),
    })
}

#[test]
fn keccak_rejects_outsized_constant_input() {
    let opcode = Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Keccakf1600 {
        inputs: Box::new(std::array::from_fn(|i| {
            if i == 0 {
                FunctionInput::Constant(FieldElement::from(1u128 << 64))
            } else {
                FunctionInput::Constant(FieldElement::from(0u128))
            }
        })),
        outputs: Box::new(std::array::from_fn(|i| Witness(i as u32))),
    });

    let result = keccak::from_opcode(&opcode);
    assert!(matches!(
        result,
        Err(crate::Error::ConstantOutOfRange { num_bits: 64, .. })
    ));
}

/// Each witness lane gets a `< 2^64` range constraint in `@constrain`.
#[test]
fn keccak_constraints_emit_range_constraints() {
    let context = LlzkContext::new();
    let inputs: [u32; STATE_WORDS] = std::array::from_fn(|i| i as u32);
    let outputs: [u32; STATE_WORDS] = std::array::from_fn(|i| STATE_WORDS as u32 + i as u32);
    let private: Vec<u32> = (0..STATE_WORDS as u32).collect();
    let circuit = make_circuit_with_opcodes(
        2 * STATE_WORDS as u32 - 1,
        &private,
        &[],
        &outputs,
        vec![keccak_blackbox(inputs, outputs)],
    );

    let module =
        translate_single_circuit_module(&context, circuit).expect("translation should pass");
    let ir = format!("{}", module.as_operation());

    assert!(module.as_operation().verify(), "Module should verify");
    assert_eq!(
        count_occurrences(&ir, "cast.tofelt"),
        inputs.len(),
        "every witness lane should emit one range-check cast"
    );
}
