use acir::FieldElement;
use acir::circuit::Opcode;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::native_types::Witness;

use crate::tests::e2e::{
    assert_constrain_rejects_corrupted_witness, assert_witness_eq, felt_u64, run_e2e,
};
use crate::tests::make_circuit_with_opcodes;

// XKCP reference: KeccakF-1600-IntermediateValues.txt, also used by
// ACVM at acvm-repo/blackbox_solver/src/hash.rs.
const KECCAK_ZERO_OUT: [u64; 25] = [
    0xF1258F7940E1DDE7,
    0x84D5CCF933C0478A,
    0xD598261EA65AA9EE,
    0xBD1547306F80494D,
    0x8B284E056253D057,
    0xFF97A42D7F8E6FD4,
    0x90FEE5A0A44647C4,
    0x8C5BDA0CD6192E76,
    0xAD30A6F71B19059C,
    0x30935AB7D08FFC64,
    0xEB5AA93F2317D635,
    0xA9A6E6260D712103,
    0x81A57C16DBCF555F,
    0x43B831CD0347C826,
    0x01F22F1A11A5569F,
    0x05E5635A21D9AE61,
    0x64BEFEF28CC970F2,
    0x613670957BC46611,
    0xB87C5A554FD00ECB,
    0x8C3EE88A1CCF32C8,
    0x940C7922AE3A2614,
    0x1841F924A2C509E4,
    0x16F53526E70465C2,
    0x75F644E97F30A13B,
    0xEAF1FF7B5CECA249,
];

// keccak-f[1600] applied twice to all-zeros (XKCP / ACVM).
const KECCAK_DOUBLE_OUT: [u64; 25] = [
    0x2D5C954DF96ECB3C,
    0x6A332CD07057B56D,
    0x093D8D1270D76B6C,
    0x8A20D9B25569D094,
    0x4F9C4F99E5E7F156,
    0xF957B9A2DA65FB38,
    0x85773DAE1275AF0D,
    0xFAF4F247C3D810F7,
    0x1F1B9EE6F79A8759,
    0xE4FECC0FEE98B425,
    0x68CE61B6B9CE68A1,
    0xDEEA66C4BA8F974F,
    0x33C43D836EAFB1F5,
    0xE00654042719DBD9,
    0x7CF8A9F009831265,
    0xFD5449A6BF174743,
    0x97DDAD33D8994B40,
    0x48EAD5FC5D0BE774,
    0xE3B8C8EE55B7B03C,
    0x91A0226E649E42E9,
    0x900E3129E7BADD7B,
    0x202A9EC5FAA3CCE8,
    0x5B3402464E1C3DB6,
    0x609F4E62A44C1059,
    0x20D06CD26A8FBF5C,
];

fn keccak_blackbox(inputs: [u32; 25], outputs: [u32; 25]) -> Opcode<FieldElement> {
    Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Keccakf1600 {
        inputs: Box::new(inputs.map(|w| FunctionInput::Witness(Witness(w)))),
        outputs: Box::new(outputs.map(Witness)),
    })
}

fn make_keccak_circuit() -> acir::circuit::Circuit<FieldElement> {
    let inputs: [u32; 25] = std::array::from_fn(|i| i as u32);
    let outputs: [u32; 25] = std::array::from_fn(|i| 25 + i as u32);
    make_circuit_with_opcodes(
        49,
        &(0..25).collect::<Vec<_>>(),
        &[],
        &outputs,
        vec![keccak_blackbox(inputs, outputs)],
    )
}

#[test]
fn zero_state_matches_known_vector() {
    let input_values: Vec<_> = (0..25).map(|_| felt_u64(0)).collect();
    let computed = run_e2e(make_keccak_circuit(), &input_values);

    for (i, &expected) in KECCAK_ZERO_OUT.iter().enumerate() {
        assert_witness_eq(
            &computed.members,
            &format!("w{}", 25 + i),
            &expected.to_string(),
        );
    }
}

#[test]
fn double_application_matches_known_vector() {
    let input_values: Vec<_> = KECCAK_ZERO_OUT.iter().map(|&v| felt_u64(v)).collect();
    let computed = run_e2e(make_keccak_circuit(), &input_values);

    for (i, &expected) in KECCAK_DOUBLE_OUT.iter().enumerate() {
        assert_witness_eq(
            &computed.members,
            &format!("w{}", 25 + i),
            &expected.to_string(),
        );
    }
}

#[test]
fn constrain_rejects_corrupted_output() {
    let input_values: Vec<_> = (0..25).map(|_| felt_u64(0)).collect();
    assert_constrain_rejects_corrupted_witness(make_keccak_circuit(), &input_values, "w25");
}
