use llzk::prelude::{LlzkContext, Module, OperationLike, WalkOrder, WalkResult};

use crate::blackboxes::registry::BlackboxFunction;
use crate::opcodes::{OpcodeEmitter, grumpkin::embedded_curve_add};
use crate::tests::{
    count_occurrences, embedded_curve_add_blackbox, make_circuit, make_circuit_with_opcodes,
    translate_single_circuit_module,
};

fn translate_embedded_curve_add_module(
    context: &LlzkContext,
    circuit: acir::circuit::Circuit<acir::FieldElement>,
) -> Module<'_> {
    let module =
        translate_single_circuit_module(context, circuit).expect("translation should pass");
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

    let module = translate_embedded_curve_add_module(&context, circuit);
    println!(
        "embedded_curve_add_translates_and_verifies:\n{}",
        module.as_operation()
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

    let module = translate_embedded_curve_add_module(&context, circuit);
    println!(
        "embedded_curve_add_doubling_translates_and_verifies:\n{}",
        module.as_operation()
    );
}

#[test]
fn embedded_curve_add_emits_shared_helper_and_calls_it_from_wrappers() {
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
    let ir = format!("{}", module.as_operation());
    let helper_name = BlackboxFunction::EmbeddedCurveAdd.symbol_name();

    assert!(
        ir.contains(&format!("function.def @{helper_name}")),
        "module should define the shared helper"
    );
    assert_eq!(
        ir.matches(&format!("function.call @{helper_name}")).count(),
        2,
        "compute and constrain should each call the shared helper once"
    );
    assert_eq!(
        count_ops_by_name(&module, "bool.not"),
        1,
        "the shared helper should only negate the first point infinity check"
    );
    assert_eq!(
        count_ops_by_name(&module, "bool.or"),
        0,
        "the shared helper should handle infinity cases with dedicated branches"
    );
    assert_eq!(
        count_ops_by_name(&module, "scf.if"),
        7,
        "the complete-add helper should handle predicate, infinity, and finite-case branching once"
    );
}

#[test]
fn embedded_curve_add_emits_helper_once_for_multiple_opcode_uses() {
    let context = LlzkContext::new();
    let circuit = make_circuit_with_opcodes(
        19,
        &[0, 1, 2, 3, 4, 5, 6, 10, 11, 12, 13, 14, 15, 16],
        &[],
        &[7, 8, 9, 17, 18, 19],
        vec![
            embedded_curve_add_blackbox([0, 1, 2], [3, 4, 5], 6, (7, 8, 9)),
            embedded_curve_add_blackbox([10, 11, 12], [13, 14, 15], 16, (17, 18, 19)),
        ],
    );

    let module = translate_embedded_curve_add_module(&context, circuit);
    let ir = format!("{}", module.as_operation());
    let helper_name = BlackboxFunction::EmbeddedCurveAdd.symbol_name();

    assert_eq!(
        count_occurrences(&ir, &format!("function.def @{helper_name}")),
        1,
        "module should define the shared helper only once"
    );
    assert_eq!(
        count_occurrences(&ir, &format!("function.call @{helper_name}")),
        4,
        "each opcode use should call the shared helper from compute and constrain"
    );
}

#[test]
fn embedded_curve_add_does_not_emit_helper_when_unused() {
    let context = LlzkContext::new();
    let circuit = make_circuit(0, &[], &[], &[]);

    let module = translate_embedded_curve_add_module(&context, circuit);
    let ir = format!("{}", module.as_operation());
    let helper_name = BlackboxFunction::EmbeddedCurveAdd.symbol_name();

    assert_eq!(
        count_occurrences(&ir, &format!("function.def @{helper_name}")),
        0,
        "module should not define the helper when the opcode is unused"
    );
    assert_eq!(
        count_occurrences(&ir, &format!("function.call @{helper_name}")),
        0,
        "module should not call the helper when the opcode is unused"
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
        2,
        "the shared helper should retain the general-addition and doubling formulas once"
    );
    assert_eq!(
        count_ops_by_name(&module, "bool.cmp"),
        7,
        "the shared helper should still include the x, y, and y==0 runtime comparisons"
    );
}
