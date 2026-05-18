use std::collections::BTreeMap;

use acir::FieldElement;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::circuit::{Circuit, Opcode};
use acir::native_types::Witness;
use llzk_interpreter::Value;

use crate::tests::e2e::{
    assert_constrain_rejects_corrupted_witness, assert_witness_eq, felt_u64, run_e2e,
};
use crate::tests::make_circuit_with_opcodes;

const AES_KEY: [u64; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];
const AES_IV: [u64; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

// AES-128-CBC(key=[0..15], iv=[0..15], plaintext=[0..15]).
// Since plaintext == iv, XOR gives zeros, so this is AES-ECB(zeros, key=[0..15]).
const AES_EXPECTED: [u64; 16] = [
    0xc6, 0xa1, 0x3b, 0x37, 0x87, 0x8f, 0x5b, 0x82, 0x6f, 0x4f, 0x81, 0x62, 0xa1, 0xc8, 0xd8, 0x79,
];

// NIST SP 800-38A AES-128-CBC example: first two ciphertext blocks.
const AES_CBC_TWO_BLOCK_INPUT: [u64; 32] = [
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
];
const AES_CBC_TWO_BLOCK_OUTPUT: [u64; 32] = [
    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
    0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
];

fn aes128_blackbox(
    inputs: &[u32],
    iv: [u32; 16],
    key: [u32; 16],
    outputs: &[u32],
) -> Opcode<FieldElement> {
    Opcode::BlackBoxFuncCall(BlackBoxFuncCall::AES128Encrypt {
        inputs: inputs
            .iter()
            .copied()
            .map(|w| FunctionInput::Witness(Witness(w)))
            .collect(),
        iv: Box::new(iv.map(|w| FunctionInput::Witness(Witness(w)))),
        key: Box::new(key.map(|w| FunctionInput::Witness(Witness(w)))),
        outputs: outputs.iter().copied().map(Witness).collect(),
    })
}

fn make_aes_circuit(input_len: usize) -> (Circuit<FieldElement>, Vec<u32>) {
    let input_len_u32 = input_len as u32;
    let plaintext_w: Vec<u32> = (0..input_len_u32).collect();
    let iv_w: [u32; 16] = std::array::from_fn(|i| input_len_u32 + i as u32);
    let key_w: [u32; 16] = std::array::from_fn(|i| input_len_u32 + 16 + i as u32);
    let output_start = input_len_u32 + 32;
    let outputs: Vec<u32> = (output_start..output_start + input_len_u32).collect();
    let private_inputs: Vec<u32> = (0..output_start).collect();

    let circuit = make_circuit_with_opcodes(
        output_start + input_len_u32 - 1,
        &private_inputs,
        &[],
        &outputs,
        vec![aes128_blackbox(&plaintext_w, iv_w, key_w, &outputs)],
    );
    (circuit, outputs)
}

fn aes_inputs(plaintext: &[u64], iv: &[u64; 16], key: &[u64; 16]) -> Vec<Value> {
    let mut inputs = Vec::with_capacity(plaintext.len() + 32);
    inputs.extend(plaintext.iter().copied().map(felt_u64));
    inputs.extend(iv.iter().copied().map(felt_u64));
    inputs.extend(key.iter().copied().map(felt_u64));
    inputs
}

fn assert_output_bytes(members: &BTreeMap<String, Value>, output_start: u32, expected: &[u64]) {
    for (i, &byte) in expected.iter().enumerate() {
        assert_witness_eq(
            members,
            &format!("w{}", output_start + i as u32),
            &byte.to_string(),
        );
    }
}

#[test]
fn single_block_matches_known_vector() {
    let plaintext: [u64; 16] = std::array::from_fn(|i| i as u64);
    let iv = plaintext;
    let key = plaintext;
    let (circuit, outputs) = make_aes_circuit(plaintext.len());
    let inputs = aes_inputs(&plaintext, &iv, &key);

    let computed = run_e2e(circuit, &inputs);
    assert_output_bytes(&computed.members, outputs[0], &AES_EXPECTED);
}

#[test]
fn two_block_cbc_matches_nist_vector() {
    let (circuit, outputs) = make_aes_circuit(AES_CBC_TWO_BLOCK_INPUT.len());
    let inputs = aes_inputs(&AES_CBC_TWO_BLOCK_INPUT, &AES_IV, &AES_KEY);

    let computed = run_e2e(circuit, &inputs);
    assert_output_bytes(&computed.members, outputs[0], &AES_CBC_TWO_BLOCK_OUTPUT);
}

#[test]
fn constrain_rejects_corrupted_output() {
    let plaintext: [u64; 16] = std::array::from_fn(|i| i as u64);
    let iv = plaintext;
    let key = plaintext;
    let (circuit, outputs) = make_aes_circuit(plaintext.len());
    let inputs = aes_inputs(&plaintext, &iv, &key);
    assert_constrain_rejects_corrupted_witness(circuit, &inputs, &format!("w{}", outputs[0]));
}
