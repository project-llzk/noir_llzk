//! End-to-end tests for the `MultiScalarMul` blackbox over Grumpkin.

use acir::FieldElement;
use acir::circuit::Circuit;
use llzk::prelude::LlzkContext;
use llzk_interpreter::Felt;

use crate::program::translate_program;
use crate::tests::e2e::{
    Interpreter, assert_witness_eq, felt_from_hex, felt_u64, run_e2e_with_nondet,
};
use crate::tests::{make_circuit_with_opcodes, make_program, multi_scalar_mul_blackbox};

use super::test_vectors::{
    FIVE_P_X_DECIMAL, FIVE_P_Y_DECIMAL, TEST_POINT_X, TEST_POINT_Y_DECIMAL, TEST_POINT_Y_HEX,
    THREE_P_X_DECIMAL, THREE_P_Y_DECIMAL, TWO_P_X_DECIMAL, TWO_P_Y_DECIMAL,
    TWO_POW_128_P_X_DECIMAL, TWO_POW_128_P_Y_DECIMAL,
};

const SCALAR_LOW_BITS: usize = 128;
const SCALAR_HIGH_BITS: usize = 126;
const SCALAR_TOTAL_BITS: usize = SCALAR_LOW_BITS + SCALAR_HIGH_BITS;

fn scalar_bits(lo: u128, hi: u128) -> Vec<Felt> {
    let mut bits = Vec::with_capacity(SCALAR_TOTAL_BITS);
    for i in 0..SCALAR_LOW_BITS {
        bits.push(Felt::from_u64(((lo >> i) & 1) as u64));
    }
    for i in 0..SCALAR_HIGH_BITS {
        bits.push(Felt::from_u64(((hi >> i) & 1) as u64));
    }
    bits
}

fn nondet_for_scalars(scalars: &[(u128, u128)]) -> Vec<Felt> {
    scalars
        .iter()
        .flat_map(|&(lo, hi)| scalar_bits(lo, hi))
        .collect()
}

fn make_single_msm_circuit() -> Circuit<FieldElement> {
    make_circuit_with_opcodes(
        8,
        &[0, 1, 2, 3, 4, 5],
        &[],
        &[6, 7, 8],
        vec![multi_scalar_mul_blackbox(
            &[[0, 1, 2]],
            &[[3, 4]],
            5,
            (6, 7, 8),
        )],
    )
}

fn make_two_point_msm_circuit() -> Circuit<FieldElement> {
    make_circuit_with_opcodes(
        13,
        &(0..=10).collect::<Vec<_>>(),
        &[],
        &[11, 12, 13],
        vec![multi_scalar_mul_blackbox(
            &[[0, 1, 2], [3, 4, 5]],
            &[[6, 7], [8, 9]],
            10,
            (11, 12, 13),
        )],
    )
}

fn single_msm_inputs(
    scalar_lo: u64,
    scalar_hi: u64,
    predicate: u64,
) -> Vec<crate::tests::e2e::Value> {
    vec![
        felt_u64(TEST_POINT_X),
        felt_from_hex(TEST_POINT_Y_HEX),
        felt_u64(0),
        felt_u64(scalar_lo),
        felt_u64(scalar_hi),
        felt_u64(predicate),
    ]
}

#[test]
fn one_times_p_equals_p() {
    let computed = run_e2e_with_nondet(
        make_single_msm_circuit(),
        &single_msm_inputs(1, 0, 1),
        &nondet_for_scalars(&[(1, 0)]),
    );

    assert_witness_eq(&computed.members, "w6", "1");
    assert_witness_eq(&computed.members, "w7", TEST_POINT_Y_DECIMAL);
    assert_witness_eq(&computed.members, "w8", "0");
}

#[test]
fn two_times_p_equals_2p() {
    let computed = run_e2e_with_nondet(
        make_single_msm_circuit(),
        &single_msm_inputs(2, 0, 1),
        &nondet_for_scalars(&[(2, 0)]),
    );

    assert_witness_eq(&computed.members, "w6", TWO_P_X_DECIMAL);
    assert_witness_eq(&computed.members, "w7", TWO_P_Y_DECIMAL);
    assert_witness_eq(&computed.members, "w8", "0");
}

#[test]
fn five_times_p_equals_5p() {
    let computed = run_e2e_with_nondet(
        make_single_msm_circuit(),
        &single_msm_inputs(5, 0, 1),
        &nondet_for_scalars(&[(5, 0)]),
    );

    assert_witness_eq(&computed.members, "w6", FIVE_P_X_DECIMAL);
    assert_witness_eq(&computed.members, "w7", FIVE_P_Y_DECIMAL);
    assert_witness_eq(&computed.members, "w8", "0");
}

#[test]
fn nonzero_high_limb_scalar_2_pow_128_times_p() {
    let computed = run_e2e_with_nondet(
        make_single_msm_circuit(),
        &single_msm_inputs(0, 1, 1),
        &nondet_for_scalars(&[(0, 1)]),
    );

    assert_witness_eq(&computed.members, "w6", TWO_POW_128_P_X_DECIMAL);
    assert_witness_eq(&computed.members, "w7", TWO_POW_128_P_Y_DECIMAL);
    assert_witness_eq(&computed.members, "w8", "0");
}

#[test]
fn zero_times_p_equals_infinity() {
    let computed = run_e2e_with_nondet(
        make_single_msm_circuit(),
        &single_msm_inputs(0, 0, 1),
        &nondet_for_scalars(&[(0, 0)]),
    );

    assert_witness_eq(&computed.members, "w6", "0");
    assert_witness_eq(&computed.members, "w7", "0");
    assert_witness_eq(&computed.members, "w8", "1");
}

#[test]
fn two_point_msm_one_p_plus_two_p_equals_three_p() {
    let computed = run_e2e_with_nondet(
        make_two_point_msm_circuit(),
        &[
            felt_u64(TEST_POINT_X),
            felt_from_hex(TEST_POINT_Y_HEX),
            felt_u64(0),
            felt_u64(TEST_POINT_X),
            felt_from_hex(TEST_POINT_Y_HEX),
            felt_u64(0),
            felt_u64(1),
            felt_u64(0),
            felt_u64(2),
            felt_u64(0),
            felt_u64(1),
        ],
        &nondet_for_scalars(&[(1, 0), (2, 0)]),
    );

    assert_witness_eq(&computed.members, "w11", THREE_P_X_DECIMAL);
    assert_witness_eq(&computed.members, "w12", THREE_P_Y_DECIMAL);
    assert_witness_eq(&computed.members, "w13", "0");
}

#[test]
fn two_point_msm_zero_scalar_drops_term() {
    let computed = run_e2e_with_nondet(
        make_two_point_msm_circuit(),
        &[
            felt_u64(TEST_POINT_X),
            felt_from_hex(TEST_POINT_Y_HEX),
            felt_u64(0),
            felt_u64(TEST_POINT_X),
            felt_from_hex(TEST_POINT_Y_HEX),
            felt_u64(0),
            felt_u64(3),
            felt_u64(0),
            felt_u64(0),
            felt_u64(0),
            felt_u64(1),
        ],
        &nondet_for_scalars(&[(3, 0), (0, 0)]),
    );

    assert_witness_eq(&computed.members, "w11", THREE_P_X_DECIMAL);
    assert_witness_eq(&computed.members, "w12", THREE_P_Y_DECIMAL);
    assert_witness_eq(&computed.members, "w13", "0");
}

#[test]
fn predicate_zero_returns_infinity() {
    let computed = run_e2e_with_nondet(
        make_single_msm_circuit(),
        &single_msm_inputs(2, 0, 0),
        &nondet_for_scalars(&[(2, 0)]),
    );

    assert_witness_eq(&computed.members, "w6", "0");
    assert_witness_eq(&computed.members, "w7", "0");
    assert_witness_eq(&computed.members, "w8", "1");
}

#[test]
fn constrain_rejects_corrupted_output() {
    let inputs = single_msm_inputs(2, 0, 1);
    let nondet = nondet_for_scalars(&[(2, 0)]);

    let program = make_program(vec![make_single_msm_circuit()]);
    let context = LlzkContext::new();
    let module = translate_program(&context, &program).expect("translation should succeed");
    let mut interpreter = Interpreter::new(&module);

    interpreter.set_nondet_values(nondet.iter().cloned());
    let mut computed = interpreter
        .run_compute("Circuit0", &inputs)
        .expect("compute should succeed");

    computed
        .members
        .insert("w6".to_string(), felt_u64(0xdead_beef));

    interpreter.set_nondet_values(nondet.iter().cloned());
    let err = interpreter
        .run_constrain("Circuit0", computed, &inputs)
        .expect_err("constrain should reject corrupted output");
    assert!(
        err.to_string().contains("!="),
        "expected constraint mismatch, got: {err}"
    );
}

fn expect_constrain_failure(inputs: Vec<crate::tests::e2e::Value>, nondet: Vec<Felt>) -> String {
    let program = make_program(vec![make_single_msm_circuit()]);
    let context = LlzkContext::new();
    let module = translate_program(&context, &program).expect("translation should succeed");
    let mut interpreter = Interpreter::new(&module);

    interpreter.set_nondet_values(nondet.iter().cloned());
    let computed = interpreter
        .run_compute("Circuit0", &inputs)
        .expect("compute should succeed");

    interpreter.set_nondet_values(nondet.iter().cloned());
    interpreter
        .run_constrain("Circuit0", computed, &inputs)
        .expect_err("constrain should reject malformed bits")
        .to_string()
}

#[test]
fn constrain_rejects_wrong_bit_decomposition() {
    let inputs = single_msm_inputs(5, 0, 1);
    let nondet = nondet_for_scalars(&[(7, 0)]);
    let err = expect_constrain_failure(inputs, nondet);
    assert!(err.contains("!="), "expected mismatch, got: {err}");
}

#[test]
fn constrain_rejects_non_boolean_nondet_bit() {
    let inputs = single_msm_inputs(1, 0, 1);
    let mut nondet = nondet_for_scalars(&[(1, 0)]);
    nondet[5] = Felt::from_u64(2);
    let err = expect_constrain_failure(inputs, nondet);
    assert!(err.contains("!="), "expected mismatch, got: {err}");
}
