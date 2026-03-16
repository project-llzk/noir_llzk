use acir::circuit::Opcode;
use acir::native_types::{Expression, Witness};
use acir::{AcirField, FieldElement, circuit::opcodes::AcirFunctionId};
use llzk::prelude::{
    BlockLike, LlzkContext, OperationLike, StructDefOpLike, StructDefOpRef, StructType, Value,
    ValueLike,
};

use super::{
    first_struct_def, func_call_operands, make_circuit, make_circuit_with_opcodes, make_program,
    member_names, mul_constraint, print_and_verify_module,
};
use crate::program::translate_program;

/// Returns the operands of every `func.call` in `@compute`, one inner `Vec` per call.
fn compute_call_operands<'c, 'a>(
    struct_def: &'a llzk::prelude::StructDefOp<'c>,
) -> Vec<Vec<Value<'c, 'a>>> {
    func_call_operands(struct_def.get_compute_func().expect("should have @compute"))
}

/// Returns the operands of every `func.call` in `@constrain`, one inner `Vec` per call.
fn constrain_call_operands<'c, 'a>(
    struct_def: &'a llzk::prelude::StructDefOp<'c>,
) -> Vec<Vec<Value<'c, 'a>>> {
    func_call_operands(
        struct_def
            .get_constrain_func()
            .expect("should have @constrain"),
    )
}

/// Builds a Call opcode with a trivially-true predicate (always execute).
fn call_opcode(id: u32, inputs: Vec<u32>, outputs: Vec<u32>) -> Opcode<FieldElement> {
    Opcode::Call {
        id: AcirFunctionId(id),
        inputs: inputs.into_iter().map(Witness).collect(),
        outputs: outputs.into_iter().map(Witness).collect(),
        predicate: Expression::one(),
    }
}

/// Asserts that `subcircuit_{call_idx}` is present in the struct's member list.
fn assert_subcircuit_member(
    struct_def: &llzk::prelude::StructDefOp,
    call_idx: usize,
    circuit_label: &str,
) {
    let member_name = format!("subcircuit_{call_idx}");
    assert!(
        member_names(struct_def).contains(&member_name),
        "{circuit_label} should have a {member_name} member"
    );
}

/// Asserts that the `call_idx`-th call has consistent operand counts across `@compute` and
/// `@constrain`: `@constrain` takes one extra leading arg (the callee struct instance).
fn assert_call_arities<'c, 'a>(
    compute_calls: &[Vec<Value<'c, 'a>>],
    constrain_calls: &[Vec<Value<'c, 'a>>],
    call_idx: usize,
    circuit_label: &str,
) {
    assert!(
        call_idx < compute_calls.len(),
        "{circuit_label} @compute: expected at least {} func.call(s), found {}",
        call_idx + 1,
        compute_calls.len()
    );
    assert!(
        call_idx < constrain_calls.len(),
        "{circuit_label} @constrain: expected at least {} func.call(s), found {}",
        call_idx + 1,
        constrain_calls.len()
    );
    assert_eq!(
        compute_calls[call_idx].len() + 1,
        constrain_calls[call_idx].len(),
        "{circuit_label} call {call_idx}: @constrain should have one extra arg (callee struct) vs @compute"
    );
}

/// Asserts that the first argument of the `call_idx`-th `@constrain` call is an SSA result
/// (not a block arg) typed `!struct.type<@callee_name>`.
fn assert_callee_struct_type<'c, 'a>(
    context: &'c LlzkContext,
    constrain_calls: &[Vec<Value<'c, 'a>>],
    call_idx: usize,
    callee_name: &str,
    circuit_label: &str,
) {
    assert!(
        !constrain_calls[call_idx][0].is_block_argument(),
        "{circuit_label} @constrain call {call_idx} arg 0 should be an SSA result \
         (struct.readm of subcircuit_{call_idx})"
    );
    let callee_type = StructType::from_str(context, callee_name).into();
    assert_eq!(
        constrain_calls[call_idx][0].r#type(),
        callee_type,
        "{circuit_label} @constrain call {call_idx} arg 0 should be !struct.type<@{callee_name}>"
    );
}

/// Checks the full shape of the `call_idx`-th `func.call` in `struct_def`:
/// member presence, operand-count consistency, and callee-struct argument type.
fn assert_call_shape(
    context: &LlzkContext,
    struct_def: &llzk::prelude::StructDefOp,
    call_idx: usize,
    callee_name: &str,
    circuit_label: &str,
) {
    let compute_calls = compute_call_operands(struct_def);
    let constrain_calls = constrain_call_operands(struct_def);
    assert_subcircuit_member(struct_def, call_idx, circuit_label);
    assert_call_arities(&compute_calls, &constrain_calls, call_idx, circuit_label);
    assert_callee_struct_type(
        context,
        &constrain_calls,
        call_idx,
        callee_name,
        circuit_label,
    );
}

/// Call outputs become known witnesses that can be used in subsequent AssertZero solves.
///
///   Circuit1: w0*w1 = w2
///   Circuit0: call Circuit1(w0, w1) → w2; then assert w2 + w0 - w3 = 0 to solve w3
#[test]
fn call_output_used_in_subsequent_solve() {
    let context = LlzkContext::new();

    // Circuit1: w0 * w1 = w2
    let circuit1 = make_circuit_with_opcodes(2, &[0, 1], &[], &[2], vec![mul_constraint(0, 1, 2)]);

    // Circuit0: w0, w1 inputs; w2 from call; w3 solved by assert
    // assert: w2 + w0 - w3 = 0  →  w3 = w2 + w0
    let assert_expr = Expression {
        mul_terms: vec![],
        linear_combinations: vec![
            (FieldElement::one(), Witness(2)),
            (FieldElement::one(), Witness(0)),
            (-FieldElement::one(), Witness(3)),
        ],
        q_c: FieldElement::zero(),
    };
    let circuit0 = make_circuit_with_opcodes(
        3,
        &[0, 1],
        &[],
        &[],
        vec![
            call_opcode(1, vec![0, 1], vec![2]),
            Opcode::AssertZero(assert_expr),
        ],
    );

    let program = make_program(vec![circuit0, circuit1]);
    let module = translate_program(&context, &program).unwrap();

    let struct0 = first_struct_def(&module);
    assert_call_shape(&context, &struct0, 0, "Circuit1", "Circuit0");

    print_and_verify_module(&module, "call_output_used_in_subsequent_solve");
}

/// Two Call opcodes to the same callee → two distinct subcircuit members.
#[test]
fn two_calls_same_callee() {
    let context = LlzkContext::new();

    // Circuit1: simple mul
    let circuit1 = make_circuit_with_opcodes(2, &[0, 1], &[], &[2], vec![mul_constraint(0, 1, 2)]);

    // Circuit0: calls Circuit1 twice with same inputs; outputs to w2 and w3.
    let circuit0 = make_circuit_with_opcodes(
        3,
        &[0, 1],
        &[],
        &[],
        vec![
            call_opcode(1, vec![0, 1], vec![2]),
            call_opcode(1, vec![0, 1], vec![3]),
        ],
    );

    let program = make_program(vec![circuit0, circuit1]);
    let module = translate_program(&context, &program).unwrap();

    let struct0 = first_struct_def(&module);
    assert_call_shape(&context, &struct0, 0, "Circuit1", "Circuit0");
    assert_call_shape(&context, &struct0, 1, "Circuit1", "Circuit0");

    print_and_verify_module(&module, "two_calls_same_callee");
}

/// Transitive calls: Circuit0 → Circuit1 → Circuit2, plus a direct Circuit0 → Circuit2 call
/// where one argument is the output of the Circuit1 call (not a block arg of Circuit0).
///
///   Circuit2: w0*w1 = w2
///   Circuit1: calls Circuit2(w0, w1) → w2
///   Circuit0: calls Circuit1(w0, w1) → w2, then calls Circuit2(w1, w2) → w3
///
/// The second call in Circuit0 passes w2, which is:
///   - In @compute: the SSA result of reading back w2 from the Circuit1 callee struct.
///   - In @constrain: the SSA result of `struct.readm(%self, @w2)` — not a block arg.
#[test]
fn transitive_calls() {
    let context = LlzkContext::new();

    // Circuit2: w0 * w1 = w2, returns w2.
    let circuit2 = make_circuit_with_opcodes(2, &[0, 1], &[], &[2], vec![mul_constraint(0, 1, 2)]);

    // Circuit1: delegates to Circuit2(w0, w1) → w2, returns w2.
    let circuit1 = make_circuit_with_opcodes(
        2,
        &[0, 1],
        &[],
        &[2],
        vec![call_opcode(2, vec![0, 1], vec![2])],
    );

    // Circuit0: first calls Circuit1(w0, w1) → w2, then calls Circuit2(w1, w2) → w3.
    // The second call uses w2 — the output of the first call — as an argument.
    let circuit0 = make_circuit_with_opcodes(
        3,
        &[0, 1],
        &[],
        &[],
        vec![
            call_opcode(1, vec![0, 1], vec![2]),
            call_opcode(2, vec![1, 2], vec![3]),
        ],
    );

    let program = make_program(vec![circuit0, circuit1, circuit2]);
    let module = translate_program(&context, &program).expect("translation should succeed");

    let body = module.body();
    let op0 = body
        .first_operation()
        .expect("module should have a first op");
    let op1 = op0.next_in_block().expect("module should have a second op");
    let struct0 = StructDefOpRef::try_from(op0).expect("op0 should be a struct def"); // Circuit0
    let struct1 = StructDefOpRef::try_from(op1).expect("op1 should be a struct def"); // Circuit1

    // Pre-collect for Circuit0 so we can inspect individual operand values below.
    let c0_compute_calls = compute_call_operands(&struct0);
    let c0_constrain_calls = constrain_call_operands(&struct0);

    // Circuit0 → Circuit1 (call 0): both inputs (w0, w1) are block args.
    assert_call_shape(&context, &struct0, 0, "Circuit1", "Circuit0");

    // Circuit0 → Circuit2 (call 1): w1 (arg 0) is a block arg; w2 (arg 1) is
    // not — in @compute it is the SSA result of reading back from the Circuit1
    // callee struct, and in @constrain it is `struct.readm(%self, @w2)`.
    let w2_in_compute = c0_compute_calls[1][1];
    let w2_in_constrain = c0_constrain_calls[1][2];
    assert_call_shape(&context, &struct0, 1, "Circuit2", "Circuit0");
    assert!(
        !w2_in_compute.is_block_argument(),
        "w2 in @compute should be an SSA result (readm from Circuit1 callee struct), not a block arg"
    );
    assert!(
        !w2_in_constrain.is_block_argument(),
        "w2 in @constrain should be an SSA result (struct.readm(%self, @w2)), not a block arg"
    );

    // Circuit1 → Circuit2: both inputs (w0, w1) are block args.
    assert_call_shape(&context, &struct1, 0, "Circuit2", "Circuit1");

    print_and_verify_module(&module, "transitive_calls");
}

/// A circuit with no opcodes other than a call still produces a valid module.
#[test]
fn call_only_circuit_verifies() {
    let context = LlzkContext::new();

    // In the translated IR, `callee` becomes Circuit1 and `caller` becomes Circuit0.
    let callee = make_circuit(0, &[0], &[], &[]);
    let caller =
        make_circuit_with_opcodes(0, &[0], &[], &[], vec![call_opcode(1, vec![0], vec![])]);

    let program = make_program(vec![caller, callee]);
    let module = translate_program(&context, &program).unwrap();

    let struct0 = first_struct_def(&module);
    assert_call_shape(&context, &struct0, 0, "Circuit1", "Circuit0");

    print_and_verify_module(&module, "call_only_circuit_verifies");
}

/// The `predicate` field of a Call opcode is not used during translation.
/// Passing a non-trivial predicate should produce a valid module identical in
/// shape to the always-execute case.
#[test]
fn call_with_nontrivial_predicate_is_ignored() {
    let context = LlzkContext::new();

    let circuit1 = make_circuit_with_opcodes(2, &[0, 1], &[], &[2], vec![mul_constraint(0, 1, 2)]);

    // Use a predicate that is not Expression::one().
    let nontrivial_predicate = Expression {
        mul_terms: vec![],
        linear_combinations: vec![(FieldElement::one(), Witness(0))],
        q_c: FieldElement::zero(),
    };
    let circuit0 = make_circuit_with_opcodes(
        2,
        &[0, 1],
        &[],
        &[],
        vec![Opcode::Call {
            id: AcirFunctionId(1),
            inputs: vec![Witness(0), Witness(1)],
            outputs: vec![Witness(2)],
            predicate: nontrivial_predicate,
        }],
    );

    let program = make_program(vec![circuit0, circuit1]);
    let module = translate_program(&context, &program).unwrap();

    // Shape is identical to the trivial-predicate case: one subcircuit member,
    // one func.call in each of @compute and @constrain.
    let struct0 = first_struct_def(&module);
    assert_call_shape(&context, &struct0, 0, "Circuit1", "Circuit0");

    print_and_verify_module(&module, "call_with_nontrivial_predicate_is_ignored");
}

/// A Call opcode referencing a circuit index that does not exist in the program
/// returns an `OutOfRangeCallTarget` error rather than panicking.
#[test]
fn call_with_out_of_range_id_returns_error() {
    let context = LlzkContext::new();

    // Program has only one circuit (Circuit0), but it calls circuit id 99.
    let circuit0 =
        make_circuit_with_opcodes(0, &[0], &[], &[], vec![call_opcode(99, vec![0], vec![])]);

    let program = make_program(vec![circuit0]);
    let result = translate_program(&context, &program);
    assert!(
        matches!(
            result,
            Err(crate::Error::OutOfRangeCallTarget { id: 99, .. })
        ),
        "expected OutOfRangeCallTarget error for circuit id 99, got: {:?}",
        result
    );
}
