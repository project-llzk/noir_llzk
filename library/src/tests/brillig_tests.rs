//! Tests for Milestone 3 Issue 2: `BrilligCall` handler skeleton & dispatch.
//!
//! These cover the shell of the translator — the sibling function exists on
//! the struct with `allow_witness = true`, the call site shows up in
//! `@compute`, and every unsupported Brillig construct (opcodes, predicates,
//! marshalling shapes) returns an actionable `UnsupportedBrillig` error.
//! Register / heap / arithmetic coverage lands in later milestone-3 issues.

use acir::brillig::{BitSize, HeapVector, IntegerBitSize, MemoryAddress, Opcode as BrilligOpcode};
use acir::circuit::Opcode;
use acir::circuit::brillig::{BrilligBytecode, BrilligFunctionId, BrilligInputs, BrilligOutputs};
use acir::native_types::{Expression, Witness};
use acir::{AcirField, FieldElement};
use llzk::prelude::{
    FuncDefOpLike, FuncDefOpRef, LlzkContext, Module, OperationLike, OperationRef, RegionLike,
    StructDefOpLike,
};

use super::{
    count_occurrences, first_struct_def, iter_block_ops, make_circuit_with_opcodes,
    make_program_with_brillig, print_and_verify_module,
};

// BlockLike is used indirectly via Module::body() — keep the import to avoid
// re-importing in every test closure.
use crate::Error;
use crate::program::translate_program;
#[allow(unused_imports)]
use llzk::prelude::BlockLike as _KeepBlockLike;

// ── Test helpers ───────────────────────────────────────────────────────

/// Builds a `BrilligOpcode::Stop` with an empty return-data vector.
fn brillig_stop() -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Stop {
        return_data: HeapVector {
            pointer: MemoryAddress::Direct(0),
            size: MemoryAddress::Direct(0),
        },
    }
}

fn bytecode(ops: Vec<BrilligOpcode<FieldElement>>) -> BrilligBytecode<FieldElement> {
    BrilligBytecode {
        function_name: String::from("test_brillig"),
        bytecode: ops,
    }
}

/// Builds a `BrilligCall` opcode with a trivially-true predicate (always execute).
fn brillig_call_opcode(
    id: u32,
    inputs: Vec<BrilligInputs<FieldElement>>,
    outputs: Vec<BrilligOutputs>,
) -> Opcode<FieldElement> {
    Opcode::BrilligCall {
        id: BrilligFunctionId(id),
        inputs,
        outputs,
        predicate: Expression::one(),
    }
}

fn single_witness(w: u32) -> BrilligInputs<FieldElement> {
    BrilligInputs::Single(Expression::from(Witness(w)))
}

/// Locates the module-level `@brillig_{id}` function, if present.
fn find_brillig_fn<'c, 'a>(module: &'a Module<'c>, id: u32) -> Option<OperationRef<'c, 'a>> {
    let expected = format!("brillig_{id}");
    let body = module.body();
    for op in iter_block_ops(body) {
        if FuncDefOpRef::try_from(op).is_ok() {
            let attr = op.attribute("sym_name").ok()?;
            if attr.to_string().contains(&expected) {
                return Some(op);
            }
        }
    }
    None
}

/// Counts module-level Brillig functions (those whose `sym_name` starts with
/// `brillig_`).
fn count_brillig_fns(module: &Module) -> usize {
    let body = module.body();
    iter_block_ops(body)
        .filter(|op| {
            FuncDefOpRef::try_from(*op).is_ok()
                && op
                    .attribute("sym_name")
                    .ok()
                    .is_some_and(|a| a.to_string().contains("brillig_"))
        })
        .count()
}

// ── Tests ──────────────────────────────────────────────────────────────

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

/// A non-trivial predicate on `BrilligCall` is rejected with a clear error.
#[test]
fn brillig_with_nontrivial_predicate_errors() {
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

    let err =
        translate_program(&context, &program).expect_err("should reject non-trivial predicate");
    let msg = format!("{err}");
    assert!(
        matches!(err, Error::UnsupportedBrillig { .. }),
        "expected UnsupportedBrillig, got {err:?}"
    );
    assert!(
        msg.contains("predicate"),
        "error message should mention predicates, got {msg:?}"
    );
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

/// Array inputs are explicitly deferred to a later milestone-3 issue; the
/// skeleton rejects them with an actionable message.
#[test]
fn brillig_array_input_is_rejected_for_now() {
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

    let err = translate_program(&context, &program)
        .expect_err("array inputs should be rejected in the skeleton");
    assert!(
        matches!(err, Error::UnsupportedBrillig { .. }),
        "expected UnsupportedBrillig, got {err:?}"
    );
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

// ── Issue 3: register-machine opcodes (Const / Mov / Cast / CMov) ──────

fn addr(i: u32) -> MemoryAddress {
    MemoryAddress::Direct(i)
}

fn const_field(dst: u32, value: u128) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Const {
        destination: addr(dst),
        bit_size: BitSize::Field,
        value: FieldElement::from(value),
    }
}

fn const_int(dst: u32, bit_size: IntegerBitSize, value: u128) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Const {
        destination: addr(dst),
        bit_size: BitSize::Integer(bit_size),
        value: FieldElement::from(value),
    }
}

fn mov(dst: u32, src: u32) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Mov {
        destination: addr(dst),
        source: addr(src),
    }
}

fn cast(dst: u32, src: u32, bit_size: BitSize) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Cast {
        destination: addr(dst),
        source: addr(src),
        bit_size,
    }
}

/// Translates a zero-input / zero-output `BrilligCall` with the given body,
/// returning the emitted module on success.
fn translate_body(
    context: &LlzkContext,
    ops: Vec<BrilligOpcode<FieldElement>>,
) -> Result<Module<'_>, Error> {
    let circuit = make_circuit_with_opcodes(
        0,
        &[],
        &[],
        &[],
        vec![brillig_call_opcode(0, vec![], vec![])],
    );
    let program = make_program_with_brillig(vec![circuit], vec![bytecode(ops)]);
    translate_program(context, &program)
}

/// Counts ops in the body of `@brillig_{id}` that match `predicate`.
fn count_brillig_body_ops<F>(module: &Module, id: u32, predicate: F) -> usize
where
    F: Fn(OperationRef<'_, '_>) -> bool,
{
    let brillig_op = find_brillig_fn(module, id).expect("module should contain @brillig_{id}");
    let body = brillig_op.region(0).unwrap().first_block().unwrap();
    iter_block_ops(body).filter(|op| predicate(*op)).count()
}

/// `Const` with `BitSize::Field` emits `felt.const` in the brillig body.
#[test]
fn brillig_const_field_emits_felt_const() {
    let context = LlzkContext::new();
    let module = translate_body(&context, vec![const_field(0, 5), brillig_stop()])
        .expect("translation should succeed");

    let body_op_count =
        count_brillig_body_ops(&module, 0, |op| op.name().as_string_ref().as_str() == Ok("felt.const"));
    assert_eq!(
        body_op_count, 1,
        "@brillig_0 should contain exactly one felt.const op"
    );
    print_and_verify_module(&module, "brillig_const_field_emits_felt_const");
}

/// `Const` with `BitSize::Integer(...)` emits `arith.constant` in the brillig body.
#[test]
fn brillig_const_int_emits_arith_constant() {
    let context = LlzkContext::new();
    let module = translate_body(
        &context,
        vec![const_int(0, IntegerBitSize::U32, 42), brillig_stop()],
    )
    .expect("translation should succeed");

    let body_op_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("arith.constant")
    });
    assert_eq!(
        body_op_count, 1,
        "@brillig_0 should contain exactly one arith.constant op"
    );
    print_and_verify_module(&module, "brillig_const_int_emits_arith_constant");
}

/// `Const` accepts each integer bit size in Brillig's set (U1, U8, U32, U64, U128).
#[test]
fn brillig_const_int_accepts_all_bit_sizes() {
    use IntegerBitSize::*;
    let sizes = [(U1, 1u128), (U8, 200), (U32, 123_456), (U64, 1 << 40), (U128, 1 << 100)];
    for (bs, v) in sizes {
        let context = LlzkContext::new();
        let module = translate_body(&context, vec![const_int(0, bs, v), brillig_stop()])
            .unwrap_or_else(|e| panic!("bit size {bs:?} value {v} failed: {e}"));
        assert!(module.as_operation().verify());
    }
}

/// `Const` rejects values that exceed the declared integer width.
#[test]
fn brillig_const_int_rejects_out_of_range_value() {
    let context = LlzkContext::new();
    // 256 does not fit in u8.
    let err =
        translate_body(&context, vec![const_int(0, IntegerBitSize::U8, 256), brillig_stop()])
            .expect_err("out-of-range const should error");
    assert!(
        matches!(err, Error::ConstantOutOfRange { .. }),
        "expected ConstantOutOfRange, got {err:?}"
    );
}

/// `Mov` emits no op — just re-binds the destination register to the source
/// SSA value. A `Const`-then-`Mov` body therefore contains a single
/// `felt.const` plus the terminator.
#[test]
fn brillig_mov_emits_no_op() {
    let context = LlzkContext::new();
    let module = translate_body(
        &context,
        vec![const_field(0, 7), mov(1, 0), brillig_stop()],
    )
    .expect("translation should succeed");

    // Body should have: one felt.const + one function.return. No cast.* or
    // extra ops for the Mov.
    let brillig_op = find_brillig_fn(&module, 0).expect("@brillig_0 should exist");
    let body = brillig_op.region(0).unwrap().first_block().unwrap();
    let total = iter_block_ops(body).count();
    assert_eq!(
        total, 2,
        "Const + Mov + Stop should produce exactly 2 ops (felt.const + function.return)"
    );
}

/// Reading an unwritten register via `Mov` surfaces an `UndefinedRegister`
/// error with the bytecode index of the offending opcode.
#[test]
fn brillig_mov_from_undefined_register_errors() {
    let context = LlzkContext::new();
    let err = translate_body(&context, vec![mov(1, 0), brillig_stop()])
        .expect_err("Mov from undefined register should error");
    match err {
        Error::UndefinedRegister { addr, opcode_index } => {
            assert_eq!(addr, 0);
            assert_eq!(opcode_index, 0);
        }
        other => panic!("expected UndefinedRegister, got {other:?}"),
    }
}

/// Casting from a felt register to an integer type emits `cast.toindex`.
#[test]
fn brillig_cast_field_to_integer_emits_toindex() {
    let context = LlzkContext::new();
    let module = translate_body(
        &context,
        vec![
            const_field(0, 9),
            cast(1, 0, BitSize::Integer(IntegerBitSize::U32)),
            brillig_stop(),
        ],
    )
    .expect("translation should succeed");

    let toindex_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("cast.toindex")
    });
    assert_eq!(toindex_count, 1, "expected one cast.toindex op");
    print_and_verify_module(&module, "brillig_cast_field_to_integer_emits_toindex");
}

/// Casting from an integer register to a felt type emits `cast.tofelt`.
#[test]
fn brillig_cast_integer_to_field_emits_tofelt() {
    let context = LlzkContext::new();
    let module = translate_body(
        &context,
        vec![
            const_int(0, IntegerBitSize::U32, 11),
            cast(1, 0, BitSize::Field),
            brillig_stop(),
        ],
    )
    .expect("translation should succeed");

    let tofelt_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("cast.tofelt")
    });
    assert_eq!(tofelt_count, 1, "expected one cast.tofelt op");
    print_and_verify_module(&module, "brillig_cast_integer_to_field_emits_tofelt");
}

/// `Cast` with a destination type that matches the source emits no cast op —
/// it behaves like a `Mov` (including across different integer widths, which
/// this milestone collapses to `index`).
#[test]
fn brillig_cast_same_type_family_emits_no_op() {
    let context = LlzkContext::new();
    // Field → Field: same family, no cast emitted.
    let module = translate_body(
        &context,
        vec![const_field(0, 1), cast(1, 0, BitSize::Field), brillig_stop()],
    )
    .expect("translation should succeed");
    let cast_count = count_brillig_body_ops(&module, 0, |op| {
        let name = op.name();
        let s = name.as_string_ref();
        matches!(s.as_str(), Ok("cast.toindex") | Ok("cast.tofelt"))
    });
    assert_eq!(cast_count, 0, "field→field cast should emit no cast op");

    // Integer → Integer across bit widths: also same family for this milestone.
    let context2 = LlzkContext::new();
    let module2 = translate_body(
        &context2,
        vec![
            const_int(0, IntegerBitSize::U8, 3),
            cast(1, 0, BitSize::Integer(IntegerBitSize::U32)),
            brillig_stop(),
        ],
    )
    .expect("translation should succeed");
    let cast_count2 = count_brillig_body_ops(&module2, 0, |op| {
        let name = op.name();
        let s = name.as_string_ref();
        matches!(s.as_str(), Ok("cast.toindex") | Ok("cast.tofelt"))
    });
    assert_eq!(cast_count2, 0, "int→int cast should emit no cast op");
}

/// Reading an unwritten register via `Cast` surfaces an `UndefinedRegister`
/// error that names the opcode's bytecode index.
#[test]
fn brillig_cast_from_undefined_register_errors() {
    let context = LlzkContext::new();
    let err = translate_body(
        &context,
        vec![cast(1, 0, BitSize::Field), brillig_stop()],
    )
    .expect_err("Cast from undefined register should error");
    match err {
        Error::UndefinedRegister { addr, opcode_index } => {
            assert_eq!(addr, 0);
            assert_eq!(opcode_index, 0);
        }
        other => panic!("expected UndefinedRegister, got {other:?}"),
    }
}

/// `ConditionalMov` is control flow and is rejected with a clear message.
#[test]
fn brillig_conditional_mov_is_rejected() {
    let context = LlzkContext::new();
    let cmov = BrilligOpcode::ConditionalMov {
        destination: addr(2),
        source_a: addr(0),
        source_b: addr(1),
        condition: addr(3),
    };
    let err = translate_body(&context, vec![cmov, brillig_stop()])
        .expect_err("ConditionalMov should be rejected");
    let msg = format!("{err}");
    assert!(
        matches!(err, Error::UnsupportedBrillig { .. }),
        "expected UnsupportedBrillig, got {err:?}"
    );
    assert!(
        msg.contains("ConditionalMov"),
        "error message should name ConditionalMov, got {msg:?}"
    );
}
