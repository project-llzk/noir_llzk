//! Register-machine opcodes (Const / Mov / Cast / CMov).
use acir::brillig::{BitSize, IntegerBitSize, Opcode as BrilligOpcode};
use llzk::prelude::{LlzkContext, OperationLike};

use super::super::print_and_verify_module;
use super::{
    addr, brillig_stop, cast, const_field, const_int, count_loads, count_op, count_stores, mov,
    translate_body,
};
use crate::Error;

/// `Const` with `BitSize::Field` emits `felt.const` in the brillig body.
#[test]
fn brillig_const_field_emits_felt_const() {
    let context = LlzkContext::new();
    let module = translate_body(&context, vec![const_field(0, 5), brillig_stop()])
        .expect("translation should succeed");

    let body_op_count = count_op(&module, 0, "felt.const");
    assert_eq!(
        body_op_count, 1,
        "@brillig_0 should contain exactly one felt.const op"
    );
    assert_eq!(
        count_stores(&module, 0),
        1,
        "Const should emit one ram.store for the destination register"
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

    let felt_const_count = count_op(&module, 0, "felt.const");
    assert_eq!(
        felt_const_count, 1,
        "@brillig_0 should contain exactly one felt.const op for the integer value"
    );
    assert_eq!(
        count_stores(&module, 0),
        1,
        "Const should emit one ram.store for the destination register"
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
        let felt_const_count = count_op(&module, 0, "felt.const");
        assert_eq!(
            felt_const_count, 1,
            "bit size {bs:?} should emit exactly one felt.const"
        );
        assert!(module.as_operation().verify());
    }
}

/// `Mov` round-trips the source value through RAM: one `ram.load` from the
/// source slot and one `ram.store` to the destination slot.
#[test]
fn brillig_mov_emits_load_store_pair() {
    let context = LlzkContext::new();
    let module = translate_body(&context, vec![const_field(0, 7), mov(1, 0), brillig_stop()])
        .expect("translation should succeed");

    // Const: 1 store. Mov: 1 load + 1 store.
    assert_eq!(count_stores(&module, 0), 2);
    assert_eq!(count_loads(&module, 0), 1);
}

/// Casting to an `iN` integer type masks the source with `2^n - 1` via
/// `felt.bit_and`, regardless of the source's declared bit size. No
/// `cast.*` or `arith.index_cast` ops are involved — values are felt
/// end-to-end. Covers field→int, narrowing int→int, and widening int→int.
#[test]
fn brillig_cast_to_integer_emits_mask() {
    use IntegerBitSize::*;
    let cases: &[(&str, Option<IntegerBitSize>, IntegerBitSize)] = &[
        ("field → U32", None, U32), // field source
        ("U8 → U32 (widen)", Some(U8), U32),
        ("U32 → U8 (narrow)", Some(U32), U8),
    ];

    for (label, src_bs, dst_bs) in cases {
        let context = LlzkContext::new();
        let src_const = match src_bs {
            None => const_field(0, 9),
            Some(bs) => const_int(0, *bs, 3),
        };
        let module = translate_body(
            &context,
            vec![
                src_const,
                cast(1, 0, BitSize::Integer(*dst_bs)),
                brillig_stop(),
            ],
        )
        .unwrap_or_else(|e| panic!("{label} translation failed: {e}"));

        let bit_and_count = count_op(&module, 0, "felt.bit_and");
        let toindex_count = count_op(&module, 0, "cast.toindex");
        let index_cast_count = count_op(&module, 0, "arith.index_cast");
        assert_eq!(
            bit_and_count, 1,
            "{label}: expected one felt.bit_and mask op"
        );
        assert_eq!(
            toindex_count, 0,
            "{label}: no cast.toindex — felt values stay felt"
        );
        assert_eq!(
            index_cast_count, 0,
            "{label}: no arith.index_cast — no iN types"
        );
        print_and_verify_module(&module, label);
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
