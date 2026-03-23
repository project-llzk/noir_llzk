use llzk::prelude::{LlzkContext, Module, OperationLike, WalkOrder, WalkResult};

use super::{
    embedded_curve_add_blackbox, make_circuit_with_opcodes, translate_single_circuit,
    verify_struct_in_module,
};
use crate::opcodes::{OpcodeEmitter, embedded_curve_add};

fn translate_embedded_curve_add_module(
    context: &LlzkContext,
    circuit: acir::circuit::Circuit<acir::FieldElement>,
) -> Module<'_> {
    let struct_def = translate_single_circuit(context, circuit).expect("translation should pass");
    let module = super::wrap_struct_in_module(context, struct_def);
    assert!(module.as_operation().verify(), "Module should verify");
    module
}

fn count_ops_by_name(module: &Module<'_>, op_name: &str) -> usize {
    let mut count = 0;
    module.as_operation().walk(WalkOrder::PreOrder, |op| {
        if op.name().as_string_ref().as_str() == Ok(op_name) {
            count += 1;
        }
        WalkResult::Advance
    });
    count
}

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

#[test]
fn embedded_curve_add_non_doubling_has_infinity_result_branch() {
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

    let module = translate_embedded_curve_add_module(&context, circuit);

    assert_eq!(
        count_ops_by_name(&module, "bool.not"),
        2,
        "only compute should emit the runtime infinity guard negations"
    );
    assert_eq!(
        count_ops_by_name(&module, "bool.or"),
        1,
        "only compute should emit the runtime infinity guard disjunction"
    );
    assert_eq!(
        count_ops_by_name(&module, "scf.if"),
        10,
        "compute and constrain should share the same finite case split, while constrain now also materializes a strict predicate==1 gate"
    );
}

#[test]
fn embedded_curve_add_doubling_has_y_zero_infinity_branch() {
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

    let module = translate_embedded_curve_add_module(&context, circuit);

    assert_eq!(
        count_ops_by_name(&module, "felt.div"),
        4,
        "both compute and constrain should retain the general-addition and doubling formulas"
    );
    assert_eq!(
        count_ops_by_name(&module, "bool.cmp"),
        10,
        "the finite-point lowering should still include the x, y, and y==0 runtime comparisons"
    );
}
