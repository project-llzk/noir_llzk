//! Issue 4: Brillig binary ops (`BinaryFieldOp` and `BinaryIntOp`).
//!
//! Covers every variant of each enum, verifies unsigned cmpi predicates and
//! width-preserving arith ops, and exercises mixed felt/integer chains via
//! explicit `Cast` opcodes.

use acir::brillig::{BinaryFieldOp, BinaryIntOp, BitSize, IntegerBitSize};
use llzk::prelude::{LlzkContext, OperationLike, RegionLike, ValueLike};

use super::super::{iter_block_ops, print_and_verify_module};
use super::{
    binary_field_op, binary_int_op, brillig_stop, cast, const_field, const_int,
    count_brillig_body_ops, find_brillig_fn, translate_body,
};
/// Each `BinaryFieldOp` variant emits the expected LLZK op on felt operands.
#[test]
fn brillig_binary_field_op_emits_expected_op() {
    let cases: &[(BinaryFieldOp, &str)] = &[
        (BinaryFieldOp::Add, "felt.add"),
        (BinaryFieldOp::Sub, "felt.sub"),
        (BinaryFieldOp::Mul, "felt.mul"),
        (BinaryFieldOp::Div, "felt.div"),
        (BinaryFieldOp::Equals, "bool.cmp"),
        (BinaryFieldOp::LessThan, "bool.cmp"),
        (BinaryFieldOp::LessThanEquals, "bool.cmp"),
    ];
    for (op, expected_name) in cases {
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

        let count = count_brillig_body_ops(&module, 0, |o| {
            o.name().as_string_ref().as_str() == Ok(*expected_name)
        });
        assert_eq!(count, 1, "{op:?} should emit one {expected_name} op");
        assert!(
            module.as_operation().verify(),
            "{op:?} module should verify"
        );
    }
}

/// `BinaryFieldOp::IntegerDiv` emits `felt.uintdiv`.
#[test]
fn brillig_binary_field_integer_div_emits_uintdiv() {
    let context = LlzkContext::new();
    let module = translate_body(
        &context,
        vec![
            const_field(0, 10),
            const_field(1, 3),
            binary_field_op(2, BinaryFieldOp::IntegerDiv, 0, 1),
            brillig_stop(),
        ],
    )
    .expect("IntegerDiv should translate successfully");
    let count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("felt.uintdiv")
    });
    assert_eq!(count, 1, "expected one felt.uintdiv op");
    print_and_verify_module(&module, "brillig_binary_field_integer_div_emits_uintdiv");
}

/// Each `BinaryIntOp` arithmetic/bitwise variant emits its `felt.*` op for
/// every supported integer bit size. Comparison variants are covered by
/// [`brillig_binary_int_op_cmp_variants`]. Overflow-prone ops (`Add`,
/// `Sub`, `Mul`, `Shl`) also emit a trailing `felt.bit_and` mask; this
/// test checks the primary op name, not the mask.
#[test]
fn brillig_binary_int_op_emits_expected_felt_op() {
    use IntegerBitSize::*;

    let sizes = [U8, U32, U64, U128];
    let cases: &[(BinaryIntOp, &str)] = &[
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

    for &bs in &sizes {
        for (op, expected) in cases {
            let context = LlzkContext::new();
            let module = translate_body(
                &context,
                vec![
                    const_int(0, bs, 5),
                    const_int(1, bs, 3),
                    binary_int_op(2, *op, bs, 0, 1),
                    brillig_stop(),
                ],
            )
            .unwrap_or_else(|e| panic!("{op:?} at {bs:?} failed: {e}"));

            let count = count_brillig_body_ops(&module, 0, |o| {
                o.name().as_string_ref().as_str() == Ok(*expected)
            });
            // `And` itself *is* felt.bit_and, so it adds to the mask count
            // for Add/Sub/Mul/Shl. For `And` we expect at least one felt.bit_and.
            let min_expected = if matches!(op, BinaryIntOp::And) { 1 } else { 1 };
            assert!(
                count >= min_expected,
                "{op:?} at {bs:?} should emit at least one {expected} (got {count})"
            );
            assert!(
                module.as_operation().verify(),
                "{op:?} at {bs:?} module should verify"
            );
        }
    }
}

/// `BinaryIntOp` comparison variants emit `bool.cmp`, same as the
/// felt-domain comparisons. With values stored as felts in `[0, 2^n)`,
/// the comparison gives the correct unsigned-integer answer.
#[test]
fn brillig_binary_int_op_cmp_variants() {
    use IntegerBitSize::*;

    let cases: &[BinaryIntOp] = &[
        BinaryIntOp::Equals,
        BinaryIntOp::LessThan,
        BinaryIntOp::LessThanEquals,
    ];

    for &bs in &[U1, U8, U32, U64, U128] {
        for op in cases {
            let context = LlzkContext::new();
            let module = translate_body(
                &context,
                vec![
                    const_int(0, bs, 1),
                    const_int(1, bs, 1),
                    binary_int_op(2, *op, bs, 0, 1),
                    brillig_stop(),
                ],
            )
            .unwrap_or_else(|e| panic!("{op:?} at {bs:?} failed: {e}"));

            let cmp_count = count_brillig_body_ops(&module, 0, |o| {
                o.name().as_string_ref().as_str() == Ok("bool.cmp")
            });
            assert_eq!(cmp_count, 1, "{op:?} at {bs:?} should emit one bool.cmp");
            assert!(
                module.as_operation().verify(),
                "{op:?} at {bs:?} module should verify"
            );
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

    let add_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("felt.add")
    });
    let mul_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("felt.mul")
    });
    assert_eq!(add_count, 1, "expected one felt.add");
    assert_eq!(mul_count, 1, "expected one felt.mul");
    print_and_verify_module(&module, "brillig_binary_field_op_chained_arithmetic");
}

/// `bool.cmp` ops emitted from `BinaryIntOp::{Equals, LessThan, LessThanEquals}`
/// carry the expected predicate. The mnemonic differs from the felt-domain
/// signed `arith.cmpi` world: `bool.cmp` uses `eq` / `lt` / `le` and relies
/// on the caller maintaining `[0, 2^n)` for both operands.
#[test]
fn brillig_binary_int_op_cmp_uses_unsigned_predicate() {
    let cases: &[(BinaryIntOp, &str)] = &[
        (BinaryIntOp::Equals, "eq"),
        (BinaryIntOp::LessThan, "lt"),
        (BinaryIntOp::LessThanEquals, "le"),
    ];

    for (op, expected_mnemonic) in cases {
        let context = LlzkContext::new();
        let module = translate_body(
            &context,
            vec![
                const_int(0, IntegerBitSize::U32, 1),
                const_int(1, IntegerBitSize::U32, 1),
                binary_int_op(2, *op, IntegerBitSize::U32, 0, 1),
                brillig_stop(),
            ],
        )
        .unwrap_or_else(|e| panic!("{op:?} failed: {e}"));

        let body = find_brillig_fn(&module, 0)
            .unwrap()
            .region(0)
            .unwrap()
            .first_block()
            .unwrap();
        let cmp_op = iter_block_ops(body)
            .find(|o| o.name().as_string_ref().as_str() == Ok("bool.cmp"))
            .unwrap_or_else(|| panic!("{op:?} should emit a bool.cmp op"));
        let printed = format!("{cmp_op}");
        assert!(
            printed.contains(expected_mnemonic),
            "{op:?} should emit bool.cmp with `{expected_mnemonic}` predicate, got: {printed}"
        );
    }
}

/// Every `BinaryIntOp` arithmetic op produces a felt result, regardless of
/// the declared operand bit size. The bit size governs the trailing mask,
/// not the IR type.
#[test]
fn brillig_binary_int_op_produces_felt() {
    use IntegerBitSize::*;
    for bs in [U1, U8, U32, U64, U128] {
        let context = LlzkContext::new();
        let module = translate_body(
            &context,
            vec![
                const_int(0, bs, 1),
                const_int(1, bs, 1),
                binary_int_op(2, BinaryIntOp::Add, bs, 0, 1),
                brillig_stop(),
            ],
        )
        .unwrap_or_else(|e| panic!("{bs:?} failed: {e}"));

        let body = find_brillig_fn(&module, 0)
            .unwrap()
            .region(0)
            .unwrap()
            .first_block()
            .unwrap();
        let add_op = iter_block_ops(body)
            .find(|o| o.name().as_string_ref().as_str() == Ok("felt.add"))
            .expect("should have a felt.add");
        let result_ty = format!("{}", add_op.result(0).unwrap().r#type());
        assert!(
            result_ty.starts_with("!felt."),
            "felt.add at bit size {bs:?} should produce a felt type, got {result_ty}"
        );
    }
}

/// `bool.cmp` always returns `i1`, regardless of operand width.
#[test]
fn brillig_binary_int_cmp_result_is_i1() {
    use IntegerBitSize::*;
    for &bs in &[U1, U8, U32, U64, U128] {
        let context = LlzkContext::new();
        let module = translate_body(
            &context,
            vec![
                const_int(0, bs, 1),
                const_int(1, bs, 1),
                binary_int_op(2, BinaryIntOp::Equals, bs, 0, 1),
                brillig_stop(),
            ],
        )
        .unwrap_or_else(|e| panic!("{bs:?} failed: {e}"));

        let body = find_brillig_fn(&module, 0)
            .unwrap()
            .region(0)
            .unwrap()
            .first_block()
            .unwrap();
        let cmp_op = iter_block_ops(body)
            .find(|o| o.name().as_string_ref().as_str() == Ok("bool.cmp"))
            .expect("should have bool.cmp");
        let result_ty = cmp_op.result(0).unwrap().r#type();
        assert_eq!(
            format!("{result_ty}"),
            "i1",
            "bool.cmp result at operand width {bs:?} should be i1"
        );
    }
}

/// Chained integer arithmetic: `r0=2; r1=3; r2=r0+r1; r3=4; r4=r2*r3; Stop`
/// should produce exactly one `felt.add` and one `felt.mul` (each masked).
#[test]
fn brillig_binary_int_op_chained_arithmetic() {
    let bs = IntegerBitSize::U32;
    let context = LlzkContext::new();
    let module = translate_body(
        &context,
        vec![
            const_int(0, bs, 2),
            const_int(1, bs, 3),
            binary_int_op(2, BinaryIntOp::Add, bs, 0, 1),
            const_int(3, bs, 4),
            binary_int_op(4, BinaryIntOp::Mul, bs, 2, 3),
            brillig_stop(),
        ],
    )
    .expect("chained int translation should succeed");

    let add_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("felt.add")
    });
    let mul_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("felt.mul")
    });
    assert_eq!(add_count, 1, "expected one felt.add");
    assert_eq!(mul_count, 1, "expected one felt.mul");
    print_and_verify_module(&module, "brillig_binary_int_op_chained_arithmetic");
}

/// Mixing integer and field arithmetic still works end-to-end. Since
/// registers are all felts now, the `iN → felt` Cast is a no-op; the test
/// just checks that `felt.add` (from the int op) and `felt.mul` (from the
/// field op) both appear and verify.
#[test]
fn brillig_mixed_int_and_field_via_cast() {
    let context = LlzkContext::new();
    let module = translate_body(
        &context,
        vec![
            const_int(0, IntegerBitSize::U32, 5),
            const_int(1, IntegerBitSize::U32, 3),
            binary_int_op(2, BinaryIntOp::Add, IntegerBitSize::U32, 0, 1),
            cast(3, 2, BitSize::Field),
            const_field(4, 7),
            binary_field_op(5, BinaryFieldOp::Mul, 3, 4),
            brillig_stop(),
        ],
    )
    .expect("mixed translation should succeed");

    let body = find_brillig_fn(&module, 0)
        .unwrap()
        .region(0)
        .unwrap()
        .first_block()
        .unwrap();
    assert!(iter_block_ops(body).any(|op| op.name().as_string_ref().as_str() == Ok("felt.add")));
    assert!(iter_block_ops(body).any(|op| op.name().as_string_ref().as_str() == Ok("felt.mul")));
    print_and_verify_module(&module, "brillig_mixed_int_and_field_via_cast");
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
        count_brillig_body_ops(&module, 0, |op| {
            op.name().as_string_ref().as_str() == Ok("felt.bit_and")
        }),
        1,
        "expected one felt.bit_and mask op for the felt→U1 cast"
    );
    assert_eq!(
        count_brillig_body_ops(&module, 0, |op| {
            op.name().as_string_ref().as_str() == Ok("cast.toindex")
        }),
        0,
        "no cast.toindex — felt values stay felt"
    );
    assert_eq!(
        count_brillig_body_ops(&module, 0, |op| {
            op.name().as_string_ref().as_str() == Ok("arith.index_cast")
        }),
        0,
        "no arith.index_cast — no iN types in the emitted IR"
    );
    assert_eq!(
        count_brillig_body_ops(&module, 0, |op| {
            op.name().as_string_ref().as_str() == Ok("cast.tofelt")
        }),
        0,
        "no cast.tofelt — all values are already felt"
    );
    print_and_verify_module(&module, "brillig_cast_field_to_u1_then_back");
}
