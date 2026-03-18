use llzk::prelude::LlzkContext;

use super::{
    embedded_curve_add_blackbox, make_circuit_with_opcodes, translate_single_circuit,
    verify_struct_in_module,
};
use crate::opcodes::{OpcodeEmitter, embedded_curve_add};

#[test]
fn embedded_curve_add_collects_all_witnesses() {
    let opcode = embedded_curve_add_blackbox([0, 1, 2], [3, 4, 5], 6, (7, 8, 9));
    let translated = embedded_curve_add::from_opcode(&opcode).expect("should parse opcode");

    let witnesses: Vec<u32> = translated.get_witnesses().into_iter().collect();
    assert_eq!(witnesses, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
}

#[test]
fn embedded_curve_add_translates_and_verifies() {
    let context = LlzkContext::new();
    let circuit = make_circuit_with_opcodes(
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
    );

    let struct_def = translate_single_circuit(&context, circuit).expect("translation should pass");
    verify_struct_in_module(
        &context,
        struct_def,
        "embedded_curve_add_translates_and_verifies",
    );
}

#[test]
fn embedded_curve_add_doubling_translates_and_verifies() {
    let context = LlzkContext::new();
    let circuit = make_circuit_with_opcodes(
        6,
        &[0, 1, 2, 3],
        &[],
        &[4, 5, 6],
        vec![embedded_curve_add_blackbox(
            [0, 1, 2],
            [0, 1, 2],
            3,
            (4, 5, 6),
        )],
    );

    let struct_def = translate_single_circuit(&context, circuit).expect("translation should pass");
    verify_struct_in_module(
        &context,
        struct_def,
        "embedded_curve_add_doubling_translates_and_verifies",
    );
}
