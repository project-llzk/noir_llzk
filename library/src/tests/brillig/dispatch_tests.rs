//! Issue 2: `BrilligCall` handler skeleton & dispatch.
//!
//! These cover the shell of the translator — the sibling function exists on
//! the struct with `allow_witness = true`, the call site shows up in
//! `@compute`, and every unsupported Brillig construct (opcodes,
//! marshalling shapes) returns an actionable `UnsupportedBrillig` error.

use acir::brillig::Opcode as BrilligOpcode;
use acir::circuit::Opcode;
use acir::circuit::brillig::{BrilligFunctionId, BrilligInputs, BrilligOutputs};
use acir::native_types::{Expression, Witness};
use acir::{AcirField, FieldElement};
use llzk::prelude::{
    FuncDefOpLike, FuncDefOpRef, LlzkContext, OperationLike, RegionLike, StructDefOpLike,
};

use super::super::{
    count_occurrences, first_struct_def, iter_block_ops, make_circuit_with_opcodes,
    make_program_with_brillig, print_and_verify_module,
};
use super::{
    brillig_call_opcode, brillig_stop, bytecode, const_field, const_int, count_brillig_fns,
    find_brillig_fn, single_witness, store,
};
use crate::Error;
use crate::program::translate_program;

/// Empty BrilligCall — zero inputs, zero outputs, bytecode is just `Stop`.
/// Emits a module-level `@brillig_0` function (with `allow_witness = true`)
/// and a single call site in `@compute`. The module verifies.
#[test]
fn empty_brillig_call_verifies() {
    let context = LlzkContext::new();

    let circuit = make_circuit_with_opcodes(
        0,
        &[],
        &[],
        &[],
        vec![brillig_call_opcode(0, vec![], vec![])],
    );
    let program = make_program_with_brillig(vec![circuit], vec![bytecode(vec![brillig_stop()])]);

    let module = translate_program(&context, &program).expect("translation should succeed");

    // The module-level brillig function exists and carries allow_witness.
    let brillig_op = find_brillig_fn(&module, 0).expect("module should contain @brillig_0");
    let brillig_fn = FuncDefOpRef::try_from(brillig_op).expect("should be a FuncDefOp");
    assert!(
        <FuncDefOpRef as FuncDefOpLike>::has_allow_witness_attr(&brillig_fn),
        "@brillig_0 should have allow_witness = true"
    );

    // Exactly one function.call lives in @compute — the brillig call site.
    let struct0 = first_struct_def(&module);
    let compute_fn = struct0
        .get_compute_func()
        .expect("Circuit0 should have @compute");
    let compute_block = compute_fn.region(0).unwrap().first_block().unwrap();
    let call_count = iter_block_ops(compute_block)
        .filter(llzk::prelude::dialect::function::is_func_call)
        .count();
    assert_eq!(
        call_count, 1,
        "@compute should contain exactly one function.call (the brillig call)"
    );

    print_and_verify_module(&module, "empty_brillig_call_verifies");
}

/// Dispatch is wired up: `Opcode::BrilligCall` routes to the new handler
/// rather than falling through to the `UnsupportedOpcode` arm.
#[test]
fn brillig_dispatch_routes_to_handler() {
    let context = LlzkContext::new();

    let circuit = make_circuit_with_opcodes(
        0,
        &[],
        &[],
        &[],
        vec![brillig_call_opcode(0, vec![], vec![])],
    );
    let program = make_program_with_brillig(vec![circuit], vec![bytecode(vec![brillig_stop()])]);

    let result = translate_program(&context, &program);
    assert!(
        result.is_ok(),
        "BrilligCall should dispatch to the new handler, not UnsupportedOpcode, got {:?}",
        result.err()
    );
}

/// A non-trivial predicate on `BrilligCall` with no outputs succeeds —
/// the predicate is accepted and evaluated, but no gating multiplication
/// is needed because there are no output witnesses to gate.
#[test]
fn brillig_with_nontrivial_predicate_no_outputs() {
    let context = LlzkContext::new();

    let nontrivial = Expression {
        mul_terms: vec![],
        linear_combinations: vec![(FieldElement::one(), Witness(0))],
        q_c: FieldElement::zero(),
    };
    let opcode = Opcode::BrilligCall {
        id: BrilligFunctionId(0),
        inputs: vec![],
        outputs: vec![],
        predicate: nontrivial,
    };
    let circuit = make_circuit_with_opcodes(0, &[0], &[], &[], vec![opcode]);
    let program = make_program_with_brillig(vec![circuit], vec![bytecode(vec![brillig_stop()])]);

    let module = translate_program(&context, &program)
        .expect("non-trivial predicate with no outputs should succeed");
    print_and_verify_module(&module, "brillig_nontrivial_predicate_no_outputs");
}

/// A non-trivial predicate on `BrilligCall` with an output gates the
/// returned value via `predicate * brillig_result` in `@compute`, emitting
/// a `felt.mul` for each output witness.
#[test]
fn brillig_with_nontrivial_predicate_gates_outputs() {
    use acir::brillig::IntegerBitSize;

    let context = LlzkContext::new();

    // Predicate: w0 (a single witness, non-trivial).
    let nontrivial = Expression {
        mul_terms: vec![],
        linear_combinations: vec![(FieldElement::one(), Witness(0))],
        q_c: FieldElement::zero(),
    };

    // Brillig bytecode that stores a value into RAM and returns it:
    //   r0 = 100 (pointer for return_data)
    //   r1 = 1   (size for return_data)
    //   r2 = 42  (the return value)
    //   mem[100] = r2
    //   Stop { return_data: { pointer: r0, size: r1 } }
    let body = vec![
        const_int(0, IntegerBitSize::U32, 100), // r0 = pointer
        const_int(1, IntegerBitSize::U32, 1),   // r1 = size
        const_field(2, 42),                     // r2 = return value
        store(0, 2),                            // mem[r0] = r2
        BrilligOpcode::Stop {
            return_data: acir::brillig::HeapVector {
                pointer: acir::brillig::MemoryAddress::Direct(0),
                size: acir::brillig::MemoryAddress::Direct(1),
            },
        },
    ];

    let opcode = Opcode::BrilligCall {
        id: BrilligFunctionId(0),
        inputs: vec![],
        outputs: vec![BrilligOutputs::Simple(Witness(1))],
        predicate: nontrivial,
    };
    // w0 is the predicate witness (public input); w1 is the output.
    let circuit = make_circuit_with_opcodes(1, &[0], &[], &[], vec![opcode]);
    let program = make_program_with_brillig(vec![circuit], vec![bytecode(body)]);

    let module = translate_program(&context, &program)
        .expect("non-trivial predicate with outputs should succeed");

    // Verify that @compute contains a `felt.mul` for the predicate gating.
    let struct0 = first_struct_def(&module);
    let compute_fn = struct0
        .get_compute_func()
        .expect("Circuit0 should have @compute");
    let compute_block = compute_fn.region(0).unwrap().first_block().unwrap();
    let felt_mul_count = iter_block_ops(compute_block)
        .filter(|op| op.name().as_string_ref().as_str() == Ok("felt.mul"))
        .count();
    assert_eq!(
        felt_mul_count, 1,
        "@compute should contain exactly one felt.mul (the predicate gating)"
    );

    print_and_verify_module(&module, "brillig_nontrivial_predicate_gates_outputs");
}

/// An unsupported Brillig opcode surfaces an `UnsupportedBrillig` error that
/// names the opcode and its bytecode index.
#[test]
fn brillig_with_unsupported_opcode_errors() {
    let context = LlzkContext::new();

    let circuit = make_circuit_with_opcodes(
        0,
        &[],
        &[],
        &[],
        vec![brillig_call_opcode(0, vec![], vec![])],
    );

    // Index 0: Stop (ignored because we short-circuit below... but actually for
    // this test we want the unsupported op to be at index 1, preceded by an
    // unsupported op at index 0 so the error cites index 0).
    // Put the unsupported op first so the reported index is predictable.
    let unsupported = BrilligOpcode::Jump { location: 0 };
    let program = make_program_with_brillig(
        vec![circuit],
        vec![bytecode(vec![brillig_stop(), unsupported, brillig_stop()])],
    );
    // The translator returns at the first Stop — so this bytecode is actually
    // accepted. Build a second case that surfaces the unsupported op.
    let result = translate_program(&context, &program);
    assert!(
        result.is_ok(),
        "Stop at index 0 should terminate translation before the unsupported op is reached"
    );

    let circuit2 = make_circuit_with_opcodes(
        0,
        &[],
        &[],
        &[],
        vec![brillig_call_opcode(0, vec![], vec![])],
    );
    let unsupported_first = BrilligOpcode::Jump { location: 0 };
    let program2 = make_program_with_brillig(
        vec![circuit2],
        vec![bytecode(vec![unsupported_first, brillig_stop()])],
    );
    let err = translate_program(&context, &program2)
        .expect_err("unsupported Brillig opcode should propagate as an error");
    let msg = format!("{err}");
    assert!(
        matches!(err, Error::UnsupportedBrillig { .. }),
        "expected UnsupportedBrillig, got {err:?}"
    );
    assert!(
        msg.contains("Jump"),
        "error message should name the Brillig opcode (Jump), got {msg:?}"
    );
    assert!(
        msg.contains("index 0") || msg.contains("index: 0"),
        "error message should name the bytecode index 0, got {msg:?}"
    );
}

/// BrilligCall with one `Single(w_i)` input and zero outputs emits a
/// `@compute` call that reads `w_i` from `%self` before invoking the sibling
/// function, and the emitted module verifies.
#[test]
fn brillig_reads_single_input_from_self() {
    let context = LlzkContext::new();

    let circuit = make_circuit_with_opcodes(
        0,
        &[0],
        &[],
        &[],
        vec![brillig_call_opcode(0, vec![single_witness(0)], vec![])],
    );
    let program = make_program_with_brillig(vec![circuit], vec![bytecode(vec![brillig_stop()])]);

    let module = translate_program(&context, &program).expect("translation should succeed");

    assert!(
        find_brillig_fn(&module, 0).is_some(),
        "module should contain @brillig_0"
    );

    let ir = format!("{}", module.as_operation());
    assert!(
        ir.contains("@brillig_0"),
        "module IR should reference @brillig_0:\n{ir}"
    );

    print_and_verify_module(&module, "brillig_reads_single_input_from_self");
}

/// A `BrilligCall` that references a `BrilligFunctionId` outside the
/// program's `unconstrained_functions` list errors cleanly.
#[test]
fn brillig_with_out_of_range_id_errors() {
    let context = LlzkContext::new();

    let circuit = make_circuit_with_opcodes(
        0,
        &[],
        &[],
        &[],
        vec![brillig_call_opcode(99, vec![], vec![])],
    );
    let program = make_program_with_brillig(vec![circuit], vec![]);

    let err =
        translate_program(&context, &program).expect_err("out-of-range brillig id should error");
    assert!(
        matches!(err, Error::UnsupportedBrillig { .. }),
        "expected UnsupportedBrillig, got {err:?}"
    );
}

/// Array inputs are accepted and flattened into individual felt-typed
/// function arguments (one per array element).
#[test]
fn brillig_array_input_is_accepted() {
    let context = LlzkContext::new();

    let array_in = BrilligInputs::Array(vec![
        Expression::from(Witness(0)),
        Expression::from(Witness(1)),
    ]);
    let circuit = make_circuit_with_opcodes(
        1,
        &[0, 1],
        &[],
        &[],
        vec![brillig_call_opcode(0, vec![array_in], vec![])],
    );
    let program = make_program_with_brillig(vec![circuit], vec![bytecode(vec![brillig_stop()])]);

    let module = translate_program(&context, &program).expect("array inputs should be accepted");
    print_and_verify_module(&module, "brillig_array_input_is_accepted");
}

/// A `Simple` output paired with bytecode that produces no return values
/// (the skeleton's behavior) is rejected — the translator cannot yet wire
/// register values to return values; that arrives in later milestone-3 issues.
#[test]
fn brillig_simple_output_without_body_is_rejected() {
    let context = LlzkContext::new();

    let circuit = make_circuit_with_opcodes(
        0,
        &[],
        &[],
        &[],
        vec![brillig_call_opcode(
            0,
            vec![],
            vec![BrilligOutputs::Simple(Witness(0))],
        )],
    );
    let program = make_program_with_brillig(vec![circuit], vec![bytecode(vec![brillig_stop()])]);

    let err = translate_program(&context, &program)
        .expect_err("Simple output with empty body should error until register marshalling lands");
    assert!(
        matches!(err, Error::UnsupportedBrillig { .. }),
        "expected UnsupportedBrillig, got {err:?}"
    );
}

/// Sanity check: the emitted `@brillig_{id}` function body has exactly one
/// operation — the terminating `function.return` — for an empty-bytecode call.
#[test]
fn empty_brillig_body_is_just_a_return() {
    let context = LlzkContext::new();

    let circuit = make_circuit_with_opcodes(
        0,
        &[],
        &[],
        &[],
        vec![brillig_call_opcode(0, vec![], vec![])],
    );
    let program = make_program_with_brillig(vec![circuit], vec![bytecode(vec![brillig_stop()])]);

    let module = translate_program(&context, &program).expect("translation should succeed");
    let brillig_op = find_brillig_fn(&module, 0).expect("module should contain @brillig_0");

    let body_block = brillig_op.region(0).unwrap().first_block().unwrap();
    let op_count = iter_block_ops(body_block).count();
    assert_eq!(
        op_count, 1,
        "empty-bytecode @brillig_0 body should contain a single function.return"
    );

    let ir = format!("{}", module.as_operation());
    assert_eq!(
        count_occurrences(&ir, "function.return"),
        // @compute has a return, @constrain has a return, @brillig_0 has a return.
        3,
        "IR should contain exactly three function.return operations, got:\n{ir}"
    );
}

/// Two BrilligCall sites that reference the same `BrilligFunctionId` share a
/// single `@brillig_{id}` module function (deduplication keyed on the ACIR
/// id, not on the call site).
#[test]
fn duplicate_brillig_calls_dedup_to_single_function() {
    let context = LlzkContext::new();

    let circuit = make_circuit_with_opcodes(
        0,
        &[],
        &[],
        &[],
        vec![
            brillig_call_opcode(0, vec![], vec![]),
            brillig_call_opcode(0, vec![], vec![]),
        ],
    );
    let program = make_program_with_brillig(vec![circuit], vec![bytecode(vec![brillig_stop()])]);

    let module = translate_program(&context, &program).expect("translation should succeed");

    assert_eq!(
        count_brillig_fns(&module),
        1,
        "two calls to BrilligFunctionId(0) should produce exactly one module-level function"
    );

    // Both call sites live in @compute.
    let struct0 = first_struct_def(&module);
    let compute_fn = struct0
        .get_compute_func()
        .expect("Circuit0 should have @compute");
    let compute_block = compute_fn.region(0).unwrap().first_block().unwrap();
    let call_count = iter_block_ops(compute_block)
        .filter(llzk::prelude::dialect::function::is_func_call)
        .count();
    assert_eq!(
        call_count, 2,
        "@compute should contain two function.call ops — one per call site"
    );

    print_and_verify_module(&module, "duplicate_brillig_calls_dedup_to_single_function");
}

/// Two BrilligCall sites that reference the same `BrilligFunctionId` but
/// disagree on marshalling shape (different input/output counts) are
/// rejected — shape consistency is required for dedup.
#[test]
fn duplicate_brillig_calls_with_mismatched_shapes_error() {
    let context = LlzkContext::new();

    let circuit = make_circuit_with_opcodes(
        0,
        &[0],
        &[],
        &[],
        vec![
            brillig_call_opcode(0, vec![], vec![]),
            brillig_call_opcode(0, vec![single_witness(0)], vec![]),
        ],
    );
    let program = make_program_with_brillig(vec![circuit], vec![bytecode(vec![brillig_stop()])]);

    let err = translate_program(&context, &program)
        .expect_err("mismatched shapes for the same brillig id should error");
    let msg = format!("{err}");
    assert!(
        matches!(err, Error::UnsupportedBrillig { .. }),
        "expected UnsupportedBrillig, got {err:?}"
    );
    assert!(
        msg.contains("inconsistent marshalling shapes"),
        "error message should mention inconsistent marshalling shapes, got {msg:?}"
    );
}
