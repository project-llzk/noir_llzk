//! Brillig binary ops (`BinaryFieldOp` and `BinaryIntOp`).

use acir::brillig::{BinaryFieldOp, BinaryIntOp, BitSize, IntegerBitSize};
use llzk::prelude::{LlzkContext, OperationLike};

use super::super::print_and_verify_module;
use super::{
    binary_field_op, binary_int_op, brillig_stop, cast, const_field, const_int, count_loads,
    count_op, count_stores, find_op, translate_body,
};
/// Each `BinaryFieldOp` variant emits the expected LLZK op on felt operands.
/// Comparison variants additionally carry the expected predicate mnemonic in
/// the `bool.cmp` op.
#[test]
fn brillig_binary_field_op_emits_expected_op() {
    let cases: &[(BinaryFieldOp, &str, Option<&str>)] = &[
        (BinaryFieldOp::Add, "felt.add", None),
        (BinaryFieldOp::Sub, "felt.sub", None),
        (BinaryFieldOp::Mul, "felt.mul", None),
        (BinaryFieldOp::Div, "felt.div", None),
        (BinaryFieldOp::IntegerDiv, "felt.uintdiv", None),
        (BinaryFieldOp::Equals, "bool.cmp", Some("eq")),
        (BinaryFieldOp::LessThan, "bool.cmp", Some("lt")),
        (BinaryFieldOp::LessThanEquals, "bool.cmp", Some("le")),
    ];
    for (op, expected_name, expected_mnemonic) in cases {
        let context = LlzkContext::new();
        let opcodes = vec![
            const_field(0, 5),
            const_field(1, 3),
            binary_field_op(2, *op, 0, 1),
            brillig_stop(),
        ];
        println!("ACIR ({op:?}): {opcodes:#?}");
        let module = translate_body(&context, opcodes)
            .unwrap_or_else(|e| panic!("{op:?} translation failed: {e}"));
        println!("LLZK ({op:?}):\n{}", module.as_operation());

        let count = count_op(&module, 0, expected_name);
        assert_eq!(count, 1, "{op:?} should emit one {expected_name} op");
        if let Some(mnemonic) = expected_mnemonic {
            let emitted = find_op(&module, 0, expected_name)
                .expect("op should be present (count asserted 1)");
            let printed = format!("{emitted}");
            assert!(
                printed.contains(mnemonic),
                "{op:?} should emit {expected_name} with `{mnemonic}` predicate, got: {printed}"
            );
        }
        assert!(
            module.as_operation().verify(),
            "{op:?} module should verify"
        );
    }
}

/// Each `BinaryIntOp` variant emits its expected op for every supported
/// integer bit size. Arithmetic/bitwise variants emit `felt.*`; comparison
/// variants emit `bool.cmp` (and accept `U1`, which arithmetic variants
/// do not since their operand values would overflow). Overflow-prone ops
/// (`Add`, `Sub`, `Mul`, `Shl`) also emit a trailing `felt.bit_and` mask;
/// this test checks the primary op name, not the mask. Comparison variants
/// additionally check the `bool.cmp` predicate mnemonic — `eq`/`lt`/`le` with
/// no signedness marker, so correctness relies on prior ops keeping both
/// operands in `[0, 2^n)`.
#[test]
fn brillig_binary_int_op_emits_expected_op() {
    use IntegerBitSize::*;

    let run = |bs: IntegerBitSize,
               op: BinaryIntOp,
               expected: &str,
               expected_mnemonic: Option<&str>| {
        let context = LlzkContext::new();
        let module = translate_body(
            &context,
            vec![
                const_int(0, bs, 1),
                const_int(1, bs, 1),
                binary_int_op(2, op, bs, 0, 1),
                brillig_stop(),
            ],
        )
        .unwrap_or_else(|e| panic!("{op:?} at {bs:?} failed: {e}"));

        let count = count_op(&module, 0, expected);
        assert_eq!(
            count, 1,
            "{op:?} at {bs:?} should emit exactly one {expected} (got {count})"
        );
        if let Some(mnemonic) = expected_mnemonic {
            let emitted =
                find_op(&module, 0, expected).expect("op should be present (count asserted 1)");
            let printed = format!("{emitted}");
            assert!(
                printed.contains(mnemonic),
                "{op:?} at {bs:?} should emit {expected} with `{mnemonic}` predicate, got: {printed}"
            );
        }
        assert!(
            module.as_operation().verify(),
            "{op:?} at {bs:?} module should verify"
        );
    };

    let arith_cases: &[(BinaryIntOp, &str)] = &[
        (BinaryIntOp::Add, "felt.add"),
        (BinaryIntOp::Sub, "felt.sub"),
        (BinaryIntOp::Mul, "felt.mul"),
        (BinaryIntOp::Div, "felt.uintdiv"),
        (BinaryIntOp::And, "felt.bit_and"),
        (BinaryIntOp::Or, "felt.bit_or"),
        (BinaryIntOp::Xor, "felt.bit_xor"),
        (BinaryIntOp::Shl, "felt.shl"),
        (BinaryIntOp::Shr, "felt.shr"),
    ];
    for &bs in &[U8, U32, U64, U128] {
        for (op, expected) in arith_cases {
            run(bs, *op, expected, None);
        }
    }

    let cmp_cases: &[(BinaryIntOp, &str)] = &[
        (BinaryIntOp::Equals, "eq"),
        (BinaryIntOp::LessThan, "lt"),
        (BinaryIntOp::LessThanEquals, "le"),
    ];
    for &bs in &[U1, U8, U32, U64, U128] {
        for (op, mnemonic) in cmp_cases {
            run(bs, *op, "bool.cmp", Some(mnemonic));
        }
    }
}

/// `BinaryIntOp::Shl` and a `U1` bit size are degenerate (shift-by-1-bit) but
/// still type-check; ensure the translator does not special-case them.
#[test]
fn brillig_binary_int_op_u1_bitwise() {
    let context = LlzkContext::new();
    let module = translate_body(
        &context,
        vec![
            const_int(0, IntegerBitSize::U1, 1),
            const_int(1, IntegerBitSize::U1, 1),
            binary_int_op(2, BinaryIntOp::And, IntegerBitSize::U1, 0, 1),
            brillig_stop(),
        ],
    )
    .expect("U1 bitwise AND should translate");
    let bit_and_count = count_op(&module, 0, "felt.bit_and");
    assert_eq!(
        bit_and_count, 1,
        "U1 And should emit exactly one felt.bit_and"
    );
    assert!(module.as_operation().verify());
}

/// Chained arithmetic threads SSA values correctly through the regmap:
/// `r0=2; r1=3; r2=r0+r1; r3=4; r4=r2*r3; Stop` should produce exactly one
/// `felt.add` and one `felt.mul` in the brillig body.
#[test]
fn brillig_binary_field_op_chained_arithmetic() {
    let context = LlzkContext::new();
    let module = translate_body(
        &context,
        vec![
            const_field(0, 2),
            const_field(1, 3),
            binary_field_op(2, BinaryFieldOp::Add, 0, 1),
            const_field(3, 4),
            binary_field_op(4, BinaryFieldOp::Mul, 2, 3),
            brillig_stop(),
        ],
    )
    .expect("chained translation should succeed");

    let add_count = count_op(&module, 0, "felt.add");
    let mul_count = count_op(&module, 0, "felt.mul");
    assert_eq!(add_count, 1, "expected one felt.add");
    assert_eq!(mul_count, 1, "expected one felt.mul");

    // Each Const writes one register slot (1 ram.store), and each binary op
    // reads its two operand slots (2 ram.load) and writes its result slot
    // (1 ram.store). 3 consts + 2 binops → 5 ram.store, 4 ram.load.
    assert_eq!(count_stores(&module, 0), 5, "expected five ram.store ops");
    assert_eq!(count_loads(&module, 0), 4, "expected four ram.load ops");

    print_and_verify_module(&module, "brillig_binary_field_op_chained_arithmetic");
}

/// `cast.toindex` + `arith.index_cast` chain handles a U1 destination. The
/// boundary case of a 1-bit integer tests that the two-step felt→iN path
/// works for narrow targets.
#[test]
fn brillig_cast_field_to_u1_then_back() {
    let context = LlzkContext::new();
    let module = translate_body(
        &context,
        vec![
            const_field(0, 1),
            cast(1, 0, BitSize::Integer(IntegerBitSize::U1)),
            cast(2, 1, BitSize::Field),
            brillig_stop(),
        ],
    )
    .expect("U1 round-trip should translate");

    // Field → U1: one felt.bit_and mask.
    // U1 → Field: emit_cast is a no-op.
    // Neither direction involves cast.toindex, arith.index_cast, or
    // cast.tofelt — values are felt end-to-end.
    assert_eq!(
        count_op(&module, 0, "felt.bit_and"),
        1,
        "expected one felt.bit_and mask op for the felt→U1 cast"
    );
    assert_eq!(
        count_op(&module, 0, "cast.toindex"),
        0,
        "no cast.toindex — felt values stay felt"
    );
    assert_eq!(
        count_op(&module, 0, "arith.index_cast"),
        0,
        "no arith.index_cast — no iN types in the emitted IR"
    );
    assert_eq!(
        count_op(&module, 0, "cast.tofelt"),
        0,
        "no cast.tofelt — all values are already felt"
    );
    print_and_verify_module(&module, "brillig_cast_field_to_u1_then_back");
}
