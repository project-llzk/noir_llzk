//! End-to-end tests for the `EmbeddedCurveAdd` blackbox over Grumpkin.

use acir::circuit::Circuit;
use acir::{AcirField, FieldElement};
use llzk::prelude::LlzkContext;

use crate::program::translate_program;
use crate::tests::e2e::{
    Interpreter, assert_witness_eq, felt_from_decimal, felt_from_field_element, felt_from_hex,
    felt_u64, run_e2e,
};
use crate::tests::{embedded_curve_add_blackbox, make_circuit_with_opcodes, make_program};

// Grumpkin point with x = 1, y = sqrt(-16) mod p.
const TEST_POINT_X: u64 = 1;
const TEST_POINT_Y_HEX: &str = "0x2cf135e7506a45d632d270d45f1181294833fc48d823f272c";

const TWO_P_X_DECIMAL: &str =
    "3078034153852398078128400807926804309327113743808504829582559963737223069694";
const TWO_P_Y_DECIMAL: &str =
    "12696890884641142049456609402511852099066095483298083855939691685001536962732";

const THREE_P_X_DECIMAL: &str =
    "18660890509582237958343981571981920822503400000196279471655180441138020044621";
const THREE_P_Y_DECIMAL: &str =
    "8902249110305491597038405103722863701255802573786510474664632793109847672620";

const NEG_TEST_POINT_Y_DECIMAL: &str =
    "21888242871839275204614721864072299718383108512864252727949815652902133356757";

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
            felt_u64(1), // predicate
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

    let program = make_program(vec![make_curve_add_circuit()]);
    let context = LlzkContext::new();
    let module = translate_program(&context, &program).expect("translation should succeed");
    let mut interpreter = Interpreter::new(&module);
    let mut computed = interpreter
        .run_compute("Circuit0", &inputs)
        .expect("compute should succeed");

    // Corrupt the x-coordinate of the output.
    computed
        .members
        .insert("w7".to_string(), felt_u64(0xdead_beef));

    let err = interpreter
        .run_constrain("Circuit0", computed, &inputs)
        .expect_err("constrain should reject corrupted output");
    assert!(
        err.to_string().contains("!="),
        "expected constraint mismatch, got: {err}"
    );
}

#[test]
fn field_element_input_round_trip() {
    let fe = FieldElement::from_hex(TEST_POINT_Y_HEX).expect("hex");
    let from_fe = felt_from_field_element(fe);
    let from_hex = felt_from_hex(TEST_POINT_Y_HEX);
    assert_eq!(from_fe, from_hex);
}
