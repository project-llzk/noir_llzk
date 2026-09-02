use acir::FieldElement;
use acir::circuit::Opcode;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::native_types::Witness;

use crate::tests::e2e::{
    assert_constrain_rejects_corrupted_witness, assert_witness_eq, felt_u64, run_e2e,
};
use crate::tests::make_circuit_with_opcodes;

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

// Blake3(bytes(range(80))).
const BLAKE3_0_TO_79: [u64; 32] = [
    0x4a, 0x68, 0x47, 0xef, 0x66, 0xbc, 0xe6, 0xc1, 0x4c, 0xa0, 0x5e, 0xc8, 0xf8, 0xad, 0x73, 0x83,
    0xbf, 0x29, 0x31, 0xf4, 0xbc, 0xfd, 0x03, 0x73, 0xc1, 0x8e, 0x05, 0x9e, 0x93, 0xf9, 0xde, 0xf6,
];

// Blake3((0..=255).cycle().take(1025)).
const BLAKE3_1025_BYTES: [u64; 32] = [
    0x3e, 0x85, 0xe5, 0xa7, 0xff, 0xcd, 0x07, 0xc2, 0x37, 0x94, 0xc0, 0x79, 0xd4, 0x3e, 0xbb, 0x27,
    0x37, 0x2d, 0x06, 0xbb, 0x1f, 0x75, 0xe4, 0xb4, 0x77, 0x32, 0xfc, 0xaa, 0xf1, 0xa8, 0xcf, 0x3d,
];

// Blake3((0..=255).cycle().take(2048)).
const BLAKE3_2048_BYTES: [u64; 32] = [
    0x1b, 0xdc, 0xcf, 0xde, 0x02, 0x10, 0xa8, 0xca, 0x17, 0x8b, 0xe1, 0x9c, 0x67, 0x77, 0xcd, 0xb4,
    0xb9, 0xa8, 0xfd, 0x24, 0xe7, 0xfe, 0x2b, 0x6b, 0x25, 0x9b, 0x98, 0xe7, 0xaa, 0xaa, 0x0b, 0xb6,
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

fn witness_range<const N: usize>(start: u32) -> [u32; N] {
    std::array::from_fn(|i| start + i as u32)
}

fn assert_input_matches_expected(values: &[u64], expected_digest: &[u64; 32]) {
    let inputs: Vec<u32> = (0..values.len() as u32).collect();
    let output_start = values.len() as u32;
    let outputs = witness_range::<32>(output_start);
    let circuit = make_circuit_with_opcodes(
        output_start + 31,
        &inputs,
        &[],
        &outputs,
        vec![blake3_blackbox(&inputs, outputs)],
    );
    let witness_values: Vec<_> = values.iter().copied().map(felt_u64).collect();

    let computed = run_e2e(circuit, &witness_values);

    for (i, &expected) in expected_digest.iter().enumerate() {
        assert_witness_eq(
            &computed.members,
            &format!("w{}", output_start + i as u32),
            &expected.to_string(),
        );
    }
}

#[test]
fn abc_matches_known_vector() {
    assert_input_matches_expected(&[97, 98, 99], &BLAKE3_ABC);
}

#[test]
fn empty_input_matches_known_vector() {
    assert_input_matches_expected(&[], &BLAKE3_EMPTY);
}

#[test]
fn long_input_matches_known_vector() {
    let values: Vec<u64> = (0..80).collect();
    assert_input_matches_expected(&values, &BLAKE3_0_TO_79);
}

#[test]
fn two_chunk_input_matches_known_vector() {
    let values: Vec<u64> = (0u64..=255).cycle().take(1025).collect();
    assert_input_matches_expected(&values, &BLAKE3_1025_BYTES);
}

#[test]
fn two_full_chunks_match_known_vector() {
    let values: Vec<u64> = (0u64..=255).cycle().take(2048).collect();
    assert_input_matches_expected(&values, &BLAKE3_2048_BYTES);
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
    assert_constrain_rejects_corrupted_witness(circuit, &inputs, "w3");
}
