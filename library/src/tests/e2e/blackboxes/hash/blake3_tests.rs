use acir::FieldElement;
use acir::circuit::Opcode;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::native_types::Witness;
use llzk::prelude::LlzkContext;

use crate::program::translate_program;
use crate::tests::e2e::{Interpreter, assert_witness_eq, felt_u64, run_e2e};
use crate::tests::{make_circuit_with_opcodes, make_program};

// Blake3("abc") — from the blake3 crate.
const BLAKE3_ABC: [u64; 32] = [
    0x64, 0x37, 0xb3, 0xac, 0x38, 0x46, 0x51, 0x33, 0xff, 0xb6, 0x3b, 0x75, 0x27, 0x3a, 0x8d, 0xb5,
    0x48, 0xc5, 0x58, 0x46, 0x5d, 0x79, 0xdb, 0x03, 0xfd, 0x35, 0x9c, 0x6c, 0xd5, 0xbd, 0x9d, 0x85,
];

// Blake3("") — from the blake3 crate.
const BLAKE3_EMPTY: [u64; 32] = [
    0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
    0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62,
];

// Blake3(bytes(range(80))) — verified with a standalone reference implementation.
const BLAKE3_0_TO_79: [u64; 32] = [
    0x4a, 0x68, 0x47, 0xef, 0x66, 0xbc, 0xe6, 0xc1, 0x4c, 0xa0, 0x5e, 0xc8, 0xf8, 0xad, 0x73, 0x83,
    0xbf, 0x29, 0x31, 0xf4, 0xbc, 0xfd, 0x03, 0x73, 0xc1, 0x8e, 0x05, 0x9e, 0x93, 0xf9, 0xde, 0xf6,
];

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
fn abc_matches_known_vector() {
    let outputs: [u32; 32] = std::array::from_fn(|i| 3 + i as u32);
    let circuit = make_circuit_with_opcodes(
        34,
        &[0, 1, 2],
        &[],
        &outputs,
        vec![blake3_blackbox(&[0, 1, 2], outputs)],
    );

    let computed = run_e2e(circuit, &[felt_u64(97), felt_u64(98), felt_u64(99)]);

    for (i, &expected) in BLAKE3_ABC.iter().enumerate() {
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
        vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Blake3 {
            inputs: vec![],
            outputs: Box::new(outputs.map(Witness)),
        })],
    );

    let computed = run_e2e(circuit, &[]);

    for (i, &expected) in BLAKE3_EMPTY.iter().enumerate() {
        assert_witness_eq(&computed.members, &format!("w{i}"), &expected.to_string());
    }
}

#[test]
fn long_input_matches_known_vector() {
    let inputs: Vec<u32> = (0..80).collect();
    let outputs: [u32; 32] = std::array::from_fn(|i| 80 + i as u32);
    let circuit = make_circuit_with_opcodes(
        111,
        &inputs,
        &[],
        &outputs,
        vec![blake3_blackbox(&inputs, outputs)],
    );
    let witness_values: Vec<_> = (0..80).map(felt_u64).collect();

    let computed = run_e2e(circuit, &witness_values);

    for (i, &expected) in BLAKE3_0_TO_79.iter().enumerate() {
        assert_witness_eq(
            &computed.members,
            &format!("w{}", 80 + i),
            &expected.to_string(),
        );
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
        vec![blake3_blackbox(&[0, 1, 2], outputs)],
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
