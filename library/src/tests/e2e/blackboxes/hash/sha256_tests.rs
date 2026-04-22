use acir::FieldElement;
use acir::circuit::Opcode;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::native_types::Witness;
use llzk::prelude::LlzkContext;

use crate::program::translate_program;
use crate::tests::e2e::{Interpreter, assert_witness_eq, felt_u64, run_e2e};
use crate::tests::{make_circuit_with_opcodes, make_program};

// SHA-256 initial hash values.
const IV: [u64; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// SHA-256("") = compress(IV, padded_empty_block).
const SHA256_EMPTY: [u64; 8] = [
    0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924, 0x27ae41e4, 0x649b934c, 0xa495991b, 0x7852b855,
];

// SHA-256("abc") = compress(IV, padded_abc_block).
const SHA256_ABC: [u64; 8] = [
    0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad,
];

// compress(state=[0..7], input=[0..15]) — non-standard inputs, cross-checked
// against Noir's sha256_compression output.
const SHA256_SEQUENTIAL: [u64; 8] = [
    0xc7ab6df5, 0x6219b929, 0xd861889b, 0x3bde61ca, 0x2c18d4b1, 0xd342178b, 0x213f4968, 0xcf85a63b,
];

/// Witness layout: 0..15 = message words, 16..23 = hash values, 24..31 = outputs.
fn make_sha256_circuit(
    msg: [u64; 16],
    iv: [u64; 8],
) -> (
    acir::circuit::Circuit<FieldElement>,
    Vec<crate::tests::e2e::Value>,
) {
    let inputs_w: [u32; 16] = std::array::from_fn(|i| i as u32);
    let hv_w: [u32; 8] = std::array::from_fn(|i| 16 + i as u32);
    let out_w: [u32; 8] = std::array::from_fn(|i| 24 + i as u32);

    let circuit = make_circuit_with_opcodes(
        31,
        &(0..24).collect::<Vec<_>>(),
        &[],
        &out_w,
        vec![Opcode::BlackBoxFuncCall(
            BlackBoxFuncCall::Sha256Compression {
                inputs: Box::new(inputs_w.map(|w| FunctionInput::Witness(Witness(w)))),
                hash_values: Box::new(hv_w.map(|w| FunctionInput::Witness(Witness(w)))),
                outputs: Box::new(out_w.map(Witness)),
            },
        )],
    );

    let mut input_values: Vec<crate::tests::e2e::Value> =
        msg.iter().map(|&v| felt_u64(v)).collect();
    input_values.extend(iv.iter().map(|&v| felt_u64(v)));

    (circuit, input_values)
}

#[test]
fn empty_message_matches_known_vector() {
    let mut msg = [0u64; 16];
    msg[0] = 0x80000000; // padding bit

    let (circuit, inputs) = make_sha256_circuit(msg, IV);
    let computed = run_e2e(circuit, &inputs);

    for (i, &expected) in SHA256_EMPTY.iter().enumerate() {
        assert_witness_eq(
            &computed.members,
            &format!("w{}", 24 + i),
            &expected.to_string(),
        );
    }
}

#[test]
fn abc_matches_known_vector() {
    let mut msg = [0u64; 16];
    msg[0] = 0x61626380; // "abc" + padding bit
    msg[15] = 24; // length in bits

    let (circuit, inputs) = make_sha256_circuit(msg, IV);
    let computed = run_e2e(circuit, &inputs);

    for (i, &expected) in SHA256_ABC.iter().enumerate() {
        assert_witness_eq(
            &computed.members,
            &format!("w{}", 24 + i),
            &expected.to_string(),
        );
    }
}

#[test]
fn sequential_inputs_match_noir_stdlib() {
    let msg: [u64; 16] = std::array::from_fn(|i| i as u64);
    let state: [u64; 8] = std::array::from_fn(|i| i as u64);

    let (circuit, inputs) = make_sha256_circuit(msg, state);
    let computed = run_e2e(circuit, &inputs);

    for (i, &expected) in SHA256_SEQUENTIAL.iter().enumerate() {
        assert_witness_eq(
            &computed.members,
            &format!("w{}", 24 + i),
            &expected.to_string(),
        );
    }
}

#[test]
fn constrain_rejects_corrupted_output() {
    let mut msg = [0u64; 16];
    msg[0] = 0x80000000;

    let (circuit, inputs) = make_sha256_circuit(msg, IV);

    let program = make_program(vec![circuit]);
    let context = LlzkContext::new();
    let module = translate_program(&context, &program).expect("translation should succeed");
    let mut interpreter = Interpreter::new(&module);
    let mut computed = interpreter
        .run_compute("Circuit0", &inputs)
        .expect("compute should succeed");

    computed.members.insert("w24".to_string(), felt_u64(0xdead));

    let err = interpreter
        .run_constrain("Circuit0", computed, &inputs)
        .expect_err("constrain should reject corrupted output");
    assert!(err.to_string().contains("!="), "got: {err}");
}
