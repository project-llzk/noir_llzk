//! End-to-end tests for the `EmbeddedCurveAdd` blackbox over Grumpkin.

use acir::circuit::Circuit;
use acir::{AcirField, FieldElement};

use crate::tests::e2e::{
    assert_constrain_rejects_corrupted_witness, assert_witness_eq, felt_from_decimal,
    felt_from_field_element, felt_from_hex, felt_u64, run_e2e,
};
use crate::tests::{embedded_curve_add_blackbox, make_circuit_with_opcodes};

use super::test_vectors::{
    NEG_TEST_POINT_Y_DECIMAL, TEST_POINT_X, TEST_POINT_Y_HEX, THREE_P_X_DECIMAL, THREE_P_Y_DECIMAL,
    TWO_P_X_DECIMAL, TWO_P_Y_DECIMAL,
};

/// Builds the standard EmbeddedCurveAdd circuit with witness layout:
/// `0..2` = input1 (x, y, inf), `3..5` = input2, `6` = predicate, `7..9` = outputs.
fn make_curve_add_circuit() -> Circuit<FieldElement> {
    make_circuit_with_opcodes(
        9,
        &[0, 1, 2, 3, 4, 5, 6],
        &[],
        &[7, 8, 9],
        vec![embedded_curve_add_blackbox(
            [0, 1, 2],
            [3, 4, 5],
            6,
            (7, 8, 9),
        )],
    )
}

#[test]
fn doubles_test_point() {
    let computed = run_e2e(
        make_curve_add_circuit(),
        &[
            felt_u64(TEST_POINT_X),
            felt_from_hex(TEST_POINT_Y_HEX),
            felt_u64(0),
            felt_u64(TEST_POINT_X),
            felt_from_hex(TEST_POINT_Y_HEX),
            felt_u64(0),
            felt_u64(1),
        ],
    );

    assert_witness_eq(&computed.members, "w7", TWO_P_X_DECIMAL);
    assert_witness_eq(&computed.members, "w8", TWO_P_Y_DECIMAL);
    assert_witness_eq(&computed.members, "w9", "0");
}

#[test]
fn distinct_points() {
    let computed = run_e2e(
        make_curve_add_circuit(),
        &[
            felt_u64(TEST_POINT_X),
            felt_from_hex(TEST_POINT_Y_HEX),
            felt_u64(0),
            felt_from_decimal(TWO_P_X_DECIMAL),
            felt_from_decimal(TWO_P_Y_DECIMAL),
            felt_u64(0),
            felt_u64(1),
        ],
    );

    assert_witness_eq(&computed.members, "w7", THREE_P_X_DECIMAL);
    assert_witness_eq(&computed.members, "w8", THREE_P_Y_DECIMAL);
    assert_witness_eq(&computed.members, "w9", "0");
}

#[test]
fn p_plus_negative_p_is_infinity() {
    let computed = run_e2e(
        make_curve_add_circuit(),
        &[
            felt_u64(TEST_POINT_X),
            felt_from_hex(TEST_POINT_Y_HEX),
            felt_u64(0),
            felt_u64(TEST_POINT_X),
            felt_from_decimal(NEG_TEST_POINT_Y_DECIMAL),
            felt_u64(0),
            felt_u64(1),
        ],
    );

    // Result is the point at infinity: (0, 0, 1).
    assert_witness_eq(&computed.members, "w7", "0");
    assert_witness_eq(&computed.members, "w8", "0");
    assert_witness_eq(&computed.members, "w9", "1");
}

#[test]
fn predicate_zero_returns_infinity() {
    let computed = run_e2e(
        make_curve_add_circuit(),
        &[
            felt_u64(TEST_POINT_X),
            felt_from_hex(TEST_POINT_Y_HEX),
            felt_u64(0),
            felt_u64(TEST_POINT_X),
            felt_from_hex(TEST_POINT_Y_HEX),
            felt_u64(0),
            felt_u64(0), // predicate = 0
        ],
    );

    assert_witness_eq(&computed.members, "w7", "0");
    assert_witness_eq(&computed.members, "w8", "0");
    assert_witness_eq(&computed.members, "w9", "1");
}

#[test]
fn constrain_rejects_corrupted_output() {
    let inputs = vec![
        felt_u64(TEST_POINT_X),
        felt_from_hex(TEST_POINT_Y_HEX),
        felt_u64(0),
        felt_u64(TEST_POINT_X),
        felt_from_hex(TEST_POINT_Y_HEX),
        felt_u64(0),
        felt_u64(1),
    ];
    // w7 is the x-coordinate of the output.
    assert_constrain_rejects_corrupted_witness(make_curve_add_circuit(), &inputs, "w7");
}

#[test]
fn field_element_input_round_trip() {
    let fe = FieldElement::from_hex(TEST_POINT_Y_HEX).expect("hex");
    let from_fe = felt_from_field_element(fe);
    let from_hex = felt_from_hex(TEST_POINT_Y_HEX);
    assert_eq!(from_fe, from_hex);
}
