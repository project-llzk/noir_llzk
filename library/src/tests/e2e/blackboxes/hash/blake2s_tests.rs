use acir::FieldElement;
use acir::circuit::Opcode;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::native_types::Witness;
use llzk::prelude::LlzkContext;

use crate::program::translate_program;
use crate::tests::e2e::{Interpreter, assert_witness_eq, felt_u64, run_e2e};
use crate::tests::{make_circuit_with_opcodes, make_program};

// Verified with Python hashlib.new('blake2s', ..., digest_size=32).
const BLAKE2S_EMPTY: [u64; 32] = [
    0x69, 0x21, 0x7a, 0x30, 0x79, 0x90, 0x80, 0x94, 0xe1, 0x11, 0x21, 0xd0, 0x42, 0x35, 0x4a, 0x7c,
    0x1f, 0x55, 0xb6, 0x48, 0x2c, 0xa1, 0xa5, 0x1e, 0x1b, 0x25, 0x0d, 0xfd, 0x1e, 0xd0, 0xee, 0xf9,
];

const BLAKE2S_ABC: [u64; 32] = [
    0x50, 0x8c, 0x5e, 0x8c, 0x32, 0x7c, 0x14, 0xe2, 0xe1, 0xa7, 0x2b, 0xa3, 0x4e, 0xeb, 0x45, 0x2f,
    0x37, 0x45, 0x8b, 0x20, 0x9e, 0xd6, 0x3a, 0x29, 0x4d, 0x99, 0x9b, 0x4c, 0x86, 0x67, 0x59, 0x82,
];

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
fn abc_matches_known_vector() {
    let outputs: [u32; 32] = std::array::from_fn(|i| 3 + i as u32);
    let circuit = make_circuit_with_opcodes(
        34,
        &[0, 1, 2],
        &[],
        &outputs,
        vec![blake2s_blackbox(&[0, 1, 2], outputs)],
    );

    // "abc" = [97, 98, 99]
    let computed = run_e2e(circuit, &[felt_u64(97), felt_u64(98), felt_u64(99)]);

    for (i, &expected) in BLAKE2S_ABC.iter().enumerate() {
        assert_witness_eq(
            &computed.members,
            &format!("w{}", 3 + i),
            &expected.to_string(),
        );
    }
}

#[test]
fn empty_input_matches_known_vector() {
    let outputs: [u32; 32] = std::array::from_fn(|i| i as u32);
    let circuit = make_circuit_with_opcodes(
        31,
        &[],
        &[],
        &outputs,
        vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Blake2s {
            inputs: vec![],
            outputs: Box::new(outputs.map(Witness)),
        })],
    );

    let computed = run_e2e(circuit, &[]);

    for (i, &expected) in BLAKE2S_EMPTY.iter().enumerate() {
        assert_witness_eq(&computed.members, &format!("w{i}"), &expected.to_string());
    }
}

#[test]
fn constrain_rejects_corrupted_output() {
    let outputs: [u32; 32] = std::array::from_fn(|i| 3 + i as u32);
    let circuit = make_circuit_with_opcodes(
        34,
        &[0, 1, 2],
        &[],
        &outputs,
        vec![blake2s_blackbox(&[0, 1, 2], outputs)],
    );
    let inputs = vec![felt_u64(97), felt_u64(98), felt_u64(99)];

    let program = make_program(vec![circuit]);
    let context = LlzkContext::new();
    let module = translate_program(&context, &program).expect("translation should succeed");
    let mut interpreter = Interpreter::new(&module);
    let mut computed = interpreter
        .run_compute("Circuit0", &inputs)
        .expect("compute should succeed");

    computed.members.insert("w3".to_string(), felt_u64(0xdead));

    let err = interpreter
        .run_constrain("Circuit0", computed, &inputs)
        .expect_err("constrain should reject corrupted output");
    assert!(err.to_string().contains("!="), "got: {err}");
}
