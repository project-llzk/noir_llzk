use acir::circuit::Opcode;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::native_types::Witness;
use acir::{AcirField, FieldElement};
use llzk::prelude::{LlzkContext, Module, OperationLike, WalkOrder, WalkResult};

use crate::{
    blackboxes::{grumpkin::multi_scalar_mul::SCALAR_TOTAL_BITS, registry::BlackboxFunction},
    opcodes::{OpcodeEmitter, grumpkin::multi_scalar_mul},
    tests::{
        count_occurrences, make_circuit_with_opcodes, multi_scalar_mul_blackbox,
        translate_single_circuit_module,
    },
};

fn translate_multi_scalar_mul_module(
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
fn multi_scalar_mul_collects_all_witnesses() {
    let opcode =
        multi_scalar_mul_blackbox(&[[0, 1, 2], [3, 4, 5]], &[[6, 7], [8, 9]], 10, (11, 12, 13));
    let translated = multi_scalar_mul::from_opcode(&opcode).expect("should parse opcode");

    let witnesses: Vec<u32> = translated.get_witnesses().into_iter().collect();
    assert_eq!(
        witnesses,
        vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
    );
}

#[test]
fn multi_scalar_mul_translates_and_verifies() {
    let context = LlzkContext::new();
    let circuit = make_circuit_with_opcodes(
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
    );

    let module = translate_multi_scalar_mul_module(&context, circuit);
    println!(
        "multi_scalar_mul_translates_and_verifies:\n{}",
        module.as_operation()
    );
}

#[test]
fn multi_scalar_mul_uses_nondet_scalar_decomposition() {
    let context = LlzkContext::new();
    let circuit = make_circuit_with_opcodes(
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
    );

    let module = translate_multi_scalar_mul_module(&context, circuit);

    assert_eq!(
        count_ops_by_name(&module, "llzk.nondet"),
        2 * SCALAR_TOTAL_BITS,
        "compute and constrain should each materialize a full scalar decomposition"
    );
}

#[test]
fn multi_scalar_mul_does_not_collapse_any_infinity_case_to_infinity() {
    let context = LlzkContext::new();
    let circuit = make_circuit_with_opcodes(
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
    );

    let module = translate_multi_scalar_mul_module(&context, circuit);

    assert_eq!(
        count_ops_by_name(&module, "bool.or"),
        0,
        "MSM should handle O+P / P+O with dedicated branches instead of collapsing any infinity case"
    );
    assert!(
        count_ops_by_name(&module, "bool.not") > 0,
        "MSM should retain explicit infinity-branch handling for the accumulator path"
    );
}

#[test]
fn multi_scalar_mul_multiple_points_translates_and_verifies() {
    let context = LlzkContext::new();
    let circuit = make_circuit_with_opcodes(
        14,
        &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        &[],
        &[11, 12, 13],
        vec![multi_scalar_mul_blackbox(
            &[[0, 1, 2], [3, 4, 5]],
            &[[6, 7], [8, 9]],
            10,
            (11, 12, 13),
        )],
    );

    let module = translate_multi_scalar_mul_module(&context, circuit);
    println!(
        "multi_scalar_mul_multiple_points_translates_and_verifies:\n{}",
        module.as_operation()
    );
}

#[test]
fn multi_scalar_mul_emits_shared_helper_and_calls_it_from_wrappers() {
    let context = LlzkContext::new();
    let circuit = make_circuit_with_opcodes(
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
    );

    let module = translate_multi_scalar_mul_module(&context, circuit);
    let ir = format!("{}", module.as_operation());
    let helper_name = BlackboxFunction::MultiScalarMul { num_points: 1 }.symbol_name();

    assert_eq!(
        count_occurrences(&ir, &format!("function.def @{helper_name}")),
        1,
        "module should define the shared MSM helper once"
    );
    assert_eq!(
        count_occurrences(&ir, &format!("function.call @{helper_name}")),
        2,
        "compute and constrain should each call the shared helper once"
    );
}

fn grumpkin_generator() -> (FieldElement, FieldElement) {
    let x = FieldElement::one();
    let y = FieldElement::from_hex("0x2cf135e7506a45d632d270d45f1181294833fc48d823f272c")
        .expect("valid hex for Grumpkin generator y");
    assert_eq!(y * y, x * x * x + FieldElement::from(-17i128));
    (x, y)
}

#[test]
fn multi_scalar_mul_one_times_generator_equals_generator() {
    let context = LlzkContext::new();
    let (gx, gy) = grumpkin_generator();

    let opcode = Opcode::BlackBoxFuncCall(BlackBoxFuncCall::MultiScalarMul {
        points: vec![
            FunctionInput::Constant(gx),
            FunctionInput::Constant(gy),
            FunctionInput::Constant(FieldElement::zero()), // not infinite
        ],
        scalars: vec![
            FunctionInput::Constant(FieldElement::one()),  // lo = 1
            FunctionInput::Constant(FieldElement::zero()), // hi = 0
        ],
        predicate: FunctionInput::Constant(FieldElement::one()),
        outputs: (Witness(0), Witness(1), Witness(2)),
    });

    let circuit = make_circuit_with_opcodes(2, &[], &[], &[0, 1, 2], vec![opcode]);
    let module = translate_multi_scalar_mul_module(&context, circuit);
    println!(
        "multi_scalar_mul_one_times_generator_equals_generator:\n{}",
        module.as_operation()
    );
}
