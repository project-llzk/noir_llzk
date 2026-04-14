//! Issue 3: register-machine opcodes (Const / Mov / Cast / CMov).
//!
//! Covers SSA threading through the Brillig register map, integer constants
//! with width-typed `iN` emission (option b), and the full felt↔iN cast matrix.

use acir::brillig::{BitSize, IntegerBitSize, Opcode as BrilligOpcode};
use llzk::prelude::{LlzkContext, OperationLike, RegionLike};

use super::super::{iter_block_ops, print_and_verify_module};
use super::{
    addr, brillig_stop, cast, const_field, const_int, count_brillig_body_ops, find_brillig_fn, mov,
    translate_body,
};
use crate::Error;

/// `Const` with `BitSize::Field` emits `felt.const` in the brillig body.
#[test]
fn brillig_const_field_emits_felt_const() {
    let context = LlzkContext::new();
    let module = translate_body(&context, vec![const_field(0, 5), brillig_stop()])
        .expect("translation should succeed");

    let body_op_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("felt.const")
    });
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
    let sizes = [
        (U1, 1u128),
        (U8, 200),
        (U32, 123_456),
        (U64, 1 << 40),
        (U128, 1 << 100),
    ];
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
    let err = translate_body(
        &context,
        vec![const_int(0, IntegerBitSize::U8, 256), brillig_stop()],
    )
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
    let module = translate_body(&context, vec![const_field(0, 7), mov(1, 0), brillig_stop()])
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

/// Casting from a felt register to an `iN` integer type emits `cast.toindex`
/// followed by `arith.index_cast` to produce the properly-width-typed result.
#[test]
fn brillig_cast_field_to_integer_emits_toindex_and_index_cast() {
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
    let index_cast_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("arith.index_cast")
    });
    assert_eq!(toindex_count, 1, "expected one cast.toindex op");
    assert_eq!(index_cast_count, 1, "expected one arith.index_cast op");
    print_and_verify_module(&module, "brillig_cast_field_to_integer");
}

/// Casting from an `iN` integer register to a felt type emits `arith.index_cast`
/// (into `index`) followed by `cast.tofelt`.
#[test]
fn brillig_cast_integer_to_field_emits_index_cast_and_tofelt() {
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

    let index_cast_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("arith.index_cast")
    });
    let tofelt_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("cast.tofelt")
    });
    assert_eq!(index_cast_count, 1, "expected one arith.index_cast op");
    assert_eq!(tofelt_count, 1, "expected one cast.tofelt op");
    print_and_verify_module(&module, "brillig_cast_integer_to_field");
}

/// `Cast` with a destination type that matches the source emits no op —
/// field→field and `iN`→`iN` (same width) both collapse to a pure regmap rebind.
#[test]
fn brillig_cast_same_type_emits_no_op() {
    // Field → Field: no cast emitted.
    let context = LlzkContext::new();
    let module = translate_body(
        &context,
        vec![
            const_field(0, 1),
            cast(1, 0, BitSize::Field),
            brillig_stop(),
        ],
    )
    .expect("translation should succeed");
    let body = find_brillig_fn(&module, 0)
        .unwrap()
        .region(0)
        .unwrap()
        .first_block()
        .unwrap();
    assert_eq!(
        iter_block_ops(body).count(),
        2,
        "Const + Cast(same type) + Stop should be felt.const + function.return"
    );

    // iN → iN (same width): no cast or arith widening emitted.
    let context2 = LlzkContext::new();
    let module2 = translate_body(
        &context2,
        vec![
            const_int(0, IntegerBitSize::U32, 3),
            cast(1, 0, BitSize::Integer(IntegerBitSize::U32)),
            brillig_stop(),
        ],
    )
    .expect("translation should succeed");
    let body2 = find_brillig_fn(&module2, 0)
        .unwrap()
        .region(0)
        .unwrap()
        .first_block()
        .unwrap();
    assert_eq!(
        iter_block_ops(body2).count(),
        2,
        "Const + Cast(same width) + Stop should be arith.constant + function.return"
    );
}

/// Casting from a narrow integer to a wider integer emits `arith.extui`
/// (Brillig integers are unsigned, so zero-extension is correct).
#[test]
fn brillig_cast_widens_int_emits_extui() {
    let context = LlzkContext::new();
    let module = translate_body(
        &context,
        vec![
            const_int(0, IntegerBitSize::U8, 3),
            cast(1, 0, BitSize::Integer(IntegerBitSize::U32)),
            brillig_stop(),
        ],
    )
    .expect("translation should succeed");

    let extui_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("arith.extui")
    });
    assert_eq!(extui_count, 1, "expected one arith.extui op");
    print_and_verify_module(&module, "brillig_cast_widens_int");
}

/// Casting from a wider integer to a narrower integer emits `arith.trunci`.
#[test]
fn brillig_cast_narrows_int_emits_trunci() {
    let context = LlzkContext::new();
    let module = translate_body(
        &context,
        vec![
            const_int(0, IntegerBitSize::U32, 3),
            cast(1, 0, BitSize::Integer(IntegerBitSize::U8)),
            brillig_stop(),
        ],
    )
    .expect("translation should succeed");

    let trunci_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("arith.trunci")
    });
    assert_eq!(trunci_count, 1, "expected one arith.trunci op");
    print_and_verify_module(&module, "brillig_cast_narrows_int");
}

/// Reading an unwritten register via `Cast` surfaces an `UndefinedRegister`
/// error that names the opcode's bytecode index.
#[test]
fn brillig_cast_from_undefined_register_errors() {
    let context = LlzkContext::new();
    let err = translate_body(&context, vec![cast(1, 0, BitSize::Field), brillig_stop()])
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
