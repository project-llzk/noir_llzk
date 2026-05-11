//! Register-machine opcodes (Const / Mov / Cast / CMov).
use acir::brillig::{BitSize, IntegerBitSize};
use llzk::prelude::{LlzkContext, OperationLike};

use crate::brillig::test_helpers::{
    brillig_stop, cast, conditional_mov, const_field, const_int, count_loads, count_op,
    count_stores, mov, translate_body,
};
use crate::tests::print_and_verify_module;

/// `Const` with `BitSize::Field` emits `felt.const` in the brillig body.
#[test]
fn brillig_const_field_emits_felt_const() {
    let context = LlzkContext::new();
    let module = translate_body(&context, vec![const_field(0, 5), brillig_stop()])
        .expect("translation should succeed");

    let body_op_count = count_op(&module, 0, "felt.const");
    assert_eq!(
        body_op_count, 2,
        "@brillig_0 should contain two felt.const ops: the preamble's 0 plus the test's 5"
    );
    assert_eq!(
        count_stores(&module, 0),
        2,
        "ram.stores: preamble Const + test Const = 2"
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
        felt_const_count, 2,
        "@brillig_0 should contain two felt.const ops: the preamble's 0 plus the test's 42"
    );
    assert_eq!(
        count_stores(&module, 0),
        2,
        "ram.stores: preamble Const + test Const = 2"
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
            felt_const_count, 2,
            "bit size {bs:?}: preamble's felt.const 0 plus the test's value = 2"
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

    // Preamble Const: 1 store. User Const: 1 store. Mov: 1 load + 1 store.
    assert_eq!(count_stores(&module, 0), 3);
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

/// `ConditionalMov` lowers to `scf.if` on a truthy (`cond > 0`) check.
/// The three RAM loads are for `source_a`, `source_b`, and `condition`;
/// the single store writes the selected value into `destination`.
#[test]
fn brillig_conditional_mov_emits_scf_if() {
    let context = LlzkContext::new();
    let module = translate_body(
        &context,
        vec![
            const_field(0, 7),                   // source_a
            const_field(1, 9),                   // source_b
            const_int(2, IntegerBitSize::U1, 1), // condition
            conditional_mov(3, 0, 1, 2),
            brillig_stop(),
        ],
    )
    .expect("translation should succeed");

    assert_eq!(
        count_op(&module, 0, "scf.if"),
        1,
        "ConditionalMov should emit one scf.if"
    );
    assert_eq!(
        count_op(&module, 0, "bool.cmp"),
        1,
        "ConditionalMov should emit one bool.cmp for the truthy check"
    );
    assert_eq!(
        count_loads(&module, 0),
        3,
        "ConditionalMov should load source_a, source_b, and condition"
    );
    // Preamble Const + 3 user Const stores + 1 ConditionalMov store = 5.
    assert_eq!(count_stores(&module, 0), 5);
    print_and_verify_module(&module, "brillig_conditional_mov_emits_scf_if");
}
