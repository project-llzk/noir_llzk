use acir::circuit::Opcode;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::native_types::Witness;
use acir::{AcirField, FieldElement};

use llzk::prelude::{LlzkContext, OperationLike};

use crate::opcodes::{OpcodeEmitter, poseidon2};
use crate::tests::{
    count_occurrences, make_circuit_with_opcodes, mul_constraint, translate_single_circuit_module,
};

fn poseidon2_blackbox(inputs: [u32; 4], outputs: [u32; 4]) -> Opcode<FieldElement> {
    Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Poseidon2Permutation {
        inputs: inputs
            .into_iter()
            .map(|w| FunctionInput::Witness(Witness(w)))
            .collect(),
        outputs: outputs.into_iter().map(Witness).collect(),
    })
}

#[test]
fn poseidon2_collects_all_witnesses() {
    let opcode = poseidon2_blackbox([0, 1, 2, 3], [4, 5, 6, 7]);
    let translated = poseidon2::from_opcode(&opcode)
        .expect("translation should succeed")
        .expect("should parse opcode");

    let witnesses: Vec<u32> = translated.get_witnesses().into_iter().collect();
    assert_eq!(witnesses, vec![0, 1, 2, 3, 4, 5, 6, 7]);
}

#[test]
fn poseidon2_rejects_wrong_arity_without_panicking() {
    let opcode = Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Poseidon2Permutation {
        inputs: vec![
            FunctionInput::Witness(Witness(0)),
            FunctionInput::Witness(Witness(1)),
            FunctionInput::Witness(Witness(2)),
        ],
        outputs: vec![Witness(3), Witness(4), Witness(5), Witness(6)],
    });

    let result = poseidon2::from_opcode(&opcode);
    assert!(matches!(result, Err(crate::Error::UnsupportedOpcode(_))));
}

#[test]
fn poseidon2_emits_shared_helper_and_calls_it_from_wrappers() {
    let context = LlzkContext::new();
    let circuit = make_circuit_with_opcodes(
        11,
        &[0, 1, 2, 3],
        &[],
        &[8, 9, 10, 11],
        vec![
            poseidon2_blackbox([0, 1, 2, 3], [4, 5, 6, 7]),
            poseidon2_blackbox([4, 5, 6, 7], [8, 9, 10, 11]),
        ],
    );

    let module =
        translate_single_circuit_module(&context, circuit).expect("translation should pass");
    let ir = format!("{}", module.as_operation());

    assert!(module.as_operation().verify(), "Module should verify");
    assert_eq!(
        count_occurrences(&ir, "function.def @poseidon2_permutation"),
        1
    );
    assert_eq!(
        count_occurrences(&ir, "function.call @poseidon2_permutation"),
        4
    );
    assert_eq!(count_occurrences(&ir, "scf.if"), 0);
    assert!(count_occurrences(&ir, "felt.mul") > 0);
    assert!(count_occurrences(&ir, "felt.add") > 0);
}

#[test]
fn poseidon2_does_not_emit_helper_when_unused() {
    let context = LlzkContext::new();
    let circuit = make_circuit_with_opcodes(2, &[0, 1], &[], &[2], vec![mul_constraint(0, 1, 2)]);

    let module =
        translate_single_circuit_module(&context, circuit).expect("translation should pass");
    let ir = format!("{}", module.as_operation());

    assert!(module.as_operation().verify(), "Module should verify");
    assert_eq!(
        count_occurrences(&ir, "function.def @poseidon2_permutation"),
        0
    );
    assert_eq!(
        count_occurrences(&ir, "function.call @poseidon2_permutation"),
        0
    );
}

#[test]
fn poseidon2_with_constant_inputs_translates() {
    let context = LlzkContext::new();
    let zero = FieldElement::zero();
    let one = FieldElement::one();
    let circuit = make_circuit_with_opcodes(
        3,
        &[],
        &[],
        &[0, 1, 2, 3],
        vec![Opcode::BlackBoxFuncCall(
            BlackBoxFuncCall::Poseidon2Permutation {
                inputs: vec![
                    FunctionInput::Constant(zero),
                    FunctionInput::Constant(one),
                    FunctionInput::Constant(zero),
                    FunctionInput::Constant(zero),
                ],
                outputs: vec![Witness(0), Witness(1), Witness(2), Witness(3)],
            },
        )],
    );

    let module =
        translate_single_circuit_module(&context, circuit).expect("translation should pass");
    assert!(module.as_operation().verify(), "Module should verify");
}
