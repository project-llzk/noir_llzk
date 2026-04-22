//! End-to-end tests for the `Poseidon2Permutation` blackbox.

use acir::FieldElement;
use acir::circuit::Circuit;
use acir::circuit::Opcode;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::native_types::Witness;
use llzk::prelude::LlzkContext;

use crate::program::translate_program;
use crate::tests::e2e::{Interpreter, assert_witness_eq, felt_u64, run_e2e};
use crate::tests::{make_circuit_with_opcodes, make_program};

const POSEIDON2_ZERO_OUT_0: &str =
    "11250791130336988991462250958918728798886439319225016858543557054782819955502";
const POSEIDON2_ZERO_OUT_1: &str =
    "4233607481887396111492892177093879320512704348614197680382514840111435675705";
const POSEIDON2_ZERO_OUT_2: &str =
    "5302890168033070787580458698329923373355198252534959970285489051687438559833";
const POSEIDON2_ZERO_OUT_3: &str =
    "11146950474414891597227044764052461669681231042712299889367802215497079123309";

const POSEIDON2_0123_OUT_0: &str =
    "786823568102245344938517132468097745676732687098822989626730198331658606391";
const POSEIDON2_0123_OUT_1: &str =
    "16105493617470833344375945651585194737369509580406730765188791202038211593826";
const POSEIDON2_0123_OUT_2: &str =
    "2169165722086073256768101917994796590773204847633762971322389403847680713675";
const POSEIDON2_0123_OUT_3: &str =
    "20837792685223053096472825292260687493226094382304778455120670180090619921530";

fn poseidon2_blackbox(inputs: [u32; 4], outputs: [u32; 4]) -> Opcode<FieldElement> {
    Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Poseidon2Permutation {
        inputs: inputs
            .into_iter()
            .map(|w| FunctionInput::Witness(Witness(w)))
            .collect(),
        outputs: outputs.into_iter().map(Witness).collect(),
    })
}

/// Witness layout: 0..3 = inputs, 4..7 = outputs.
fn make_poseidon2_circuit() -> Circuit<FieldElement> {
    make_circuit_with_opcodes(
        7,
        &[0, 1, 2, 3],
        &[],
        &[4, 5, 6, 7],
        vec![poseidon2_blackbox([0, 1, 2, 3], [4, 5, 6, 7])],
    )
}

#[test]
fn zero_input_matches_known_vector() {
    let computed = run_e2e(
        make_poseidon2_circuit(),
        &[felt_u64(0), felt_u64(0), felt_u64(0), felt_u64(0)],
    );

    assert_witness_eq(&computed.members, "w4", POSEIDON2_ZERO_OUT_0);
    assert_witness_eq(&computed.members, "w5", POSEIDON2_ZERO_OUT_1);
    assert_witness_eq(&computed.members, "w6", POSEIDON2_ZERO_OUT_2);
    assert_witness_eq(&computed.members, "w7", POSEIDON2_ZERO_OUT_3);
}

#[test]
fn input_0123_matches_noir_stdlib_vector() {
    let computed = run_e2e(
        make_poseidon2_circuit(),
        &[felt_u64(0), felt_u64(1), felt_u64(2), felt_u64(3)],
    );

    assert_witness_eq(&computed.members, "w4", POSEIDON2_0123_OUT_0);
    assert_witness_eq(&computed.members, "w5", POSEIDON2_0123_OUT_1);
    assert_witness_eq(&computed.members, "w6", POSEIDON2_0123_OUT_2);
    assert_witness_eq(&computed.members, "w7", POSEIDON2_0123_OUT_3);
}

#[test]
fn constrain_rejects_corrupted_output() {
    let inputs = vec![felt_u64(0), felt_u64(0), felt_u64(0), felt_u64(0)];

    let program = make_program(vec![make_poseidon2_circuit()]);
    let context = LlzkContext::new();
    let module = translate_program(&context, &program).expect("translation should succeed");
    let mut interpreter = Interpreter::new(&module);
    let mut computed = interpreter
        .run_compute("Circuit0", &inputs)
        .expect("compute should succeed");

    computed
        .members
        .insert("w4".to_string(), felt_u64(0xdead_beef));

    let err = interpreter
        .run_constrain("Circuit0", computed, &inputs)
        .expect_err("constrain should reject corrupted output");
    assert!(
        err.to_string().contains("!="),
        "expected constraint mismatch, got: {err}"
    );
}
