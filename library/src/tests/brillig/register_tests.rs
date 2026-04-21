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

/// `Const` with `BitSize::Integer(...)` emits `felt.const` in the brillig
/// body — all Brillig values are stored as felts in RAM, including
/// narrow-width integers. The declared bit size is not a distinct IR type;
/// width enforcement happens downstream on cast/use.
#[test]
fn brillig_const_int_emits_felt_const() {
    let context = LlzkContext::new();
    let module = translate_body(
        &context,
        vec![const_int(0, IntegerBitSize::U32, 42), brillig_stop()],
    )
    .expect("translation should succeed");

    let felt_const_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("felt.const")
    });
    assert_eq!(
        felt_const_count, 1,
        "@brillig_0 should contain exactly one felt.const op for the integer value"
    );
    print_and_verify_module(&module, "brillig_const_int_emits_felt_const");
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

/// `Mov` round-trips the source value through RAM: it emits `ram.load` at
/// the source slot and `ram.store` at the destination slot, with no
/// explicit cast (both slots share the source's bit size).
#[test]
fn brillig_mov_emits_no_op() {
    let context = LlzkContext::new();
    let module = translate_body(&context, vec![const_field(0, 7), mov(1, 0), brillig_stop()])
        .expect("translation should succeed");

    // Const(Field): felt.const + arith.constant(slot 0) + ram.store.
    // Mov: ram.load(slot 0) + arith.constant(slot 1) + ram.store.
    // Plus the function.return terminator. No cast.* ops for the Mov.
    let brillig_op = find_brillig_fn(&module, 0).expect("@brillig_0 should exist");
    let body = brillig_op.region(0).unwrap().first_block().unwrap();
    let total = iter_block_ops(body).count();
    assert_eq!(
        total, 7,
        "Const + Mov + Stop should produce 7 ops: felt.const + 2×arith.constant \
         + 2×ram.store + ram.load + function.return"
    );
}

/// Casting from a felt register to an `iN` integer type masks the source
/// with `2^n - 1` via `felt.bit_and`. No cast.* or arith.index_cast ops
/// are involved — values are felt end-to-end.
#[test]
fn brillig_cast_field_to_integer_emits_mask() {
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

    let bit_and_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("felt.bit_and")
    });
    let toindex_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("cast.toindex")
    });
    let index_cast_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("arith.index_cast")
    });
    assert_eq!(bit_and_count, 1, "expected one felt.bit_and mask op");
    assert_eq!(toindex_count, 0, "no cast.toindex — felt values stay felt");
    assert_eq!(index_cast_count, 0, "no arith.index_cast — no iN types");
    print_and_verify_module(&module, "brillig_cast_field_to_integer_emits_mask");
}

/// Casting from an `iN` integer register to a felt type is a no-op in
/// `emit_cast` — the stored felt is already the integer value. The Cast
/// handler still emits a ram.load + ram.store pair to rebind the
/// destination register, but no explicit conversion ops.
#[test]
fn brillig_cast_integer_to_field_no_conversion_ops() {
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
    let bit_and_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("felt.bit_and")
    });
    assert_eq!(index_cast_count, 0, "no arith.index_cast — no iN types");
    assert_eq!(tofelt_count, 0, "no cast.tofelt — value is already felt");
    assert_eq!(
        bit_and_count, 0,
        "no mask — Field target doesn't enforce a bit width"
    );
    print_and_verify_module(&module, "brillig_cast_integer_to_field_no_conversion_ops");
}

/// `Cast` with a destination type that matches the source emits no
/// conversion op in `emit_cast` itself — but the surrounding RAM
/// machinery still reads the source slot and writes the destination slot,
/// so the body is not empty.
#[test]
fn brillig_cast_same_type_emits_no_op() {
    // Field → Field: emit_cast is a no-op, but the Cast still round-trips
    // the value through RAM.
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
    // Const(Field): felt.const + arith.constant(slot 0) + ram.store.
    // Cast(Field→Field): ram.load(slot 0) + arith.constant(slot 1) + ram.store.
    // Plus function.return. No cast.* ops emitted by emit_cast.
    assert_eq!(
        iter_block_ops(body).count(),
        7,
        "Const + Cast(Field→Field) + Stop should emit 7 ops (no cast.* from emit_cast)"
    );

    // iN → iN (same width): emit_cast is a no-op, but the register
    // narrow/widen shuffle around ram.load/ram.store remains.
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
    // Const(iN): felt.const(val) + arith.constant(slot 0) + ram.store  (3 ops)
    // Cast(iN→iN same width): ram.load + felt.const(mask) + felt.bit_and
    //          + arith.constant(slot 1) + ram.store  (5 ops)
    // Plus function.return. The always-mask policy means same-width casts
    // still emit one felt.bit_and — simpler than tracking source widths.
    assert_eq!(
        iter_block_ops(body2).count(),
        9,
        "Const + Cast(iN→iN same width) + Stop should emit 9 ops"
    );
}

/// Casting a narrow integer to a wider integer is a `felt.bit_and` with
/// `2^n_target - 1`. Widening is semantically a no-op (the source value
/// already fits), but the always-mask policy still emits the op.
#[test]
fn brillig_cast_widens_int_emits_mask() {
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

    let bit_and_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("felt.bit_and")
    });
    assert_eq!(bit_and_count, 1, "expected one felt.bit_and mask op");
    print_and_verify_module(&module, "brillig_cast_widens_int_emits_mask");
}

/// Casting a wider integer to a narrower integer is a `felt.bit_and` with
/// `2^n_target - 1`, truncating the high bits.
#[test]
fn brillig_cast_narrows_int_emits_mask() {
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

    let bit_and_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("felt.bit_and")
    });
    assert_eq!(bit_and_count, 1, "expected one felt.bit_and mask op");
    print_and_verify_module(&module, "brillig_cast_narrows_int_emits_mask");
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
