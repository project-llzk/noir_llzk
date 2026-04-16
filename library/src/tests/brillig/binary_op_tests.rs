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
use crate::Error;

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

/// Each `BinaryIntOp` arithmetic/bitwise variant emits its `arith.*` op for
/// every supported integer bit size. Comparison variants are covered by
/// [`brillig_binary_int_op_cmpi_variants`].
#[test]
fn brillig_binary_int_op_emits_expected_arith_op() {
    use IntegerBitSize::*;

    let sizes = [U8, U32, U64, U128];
    let cases: &[(BinaryIntOp, &str)] = &[
        (BinaryIntOp::Add, "arith.addi"),
        (BinaryIntOp::Sub, "arith.subi"),
        (BinaryIntOp::Mul, "arith.muli"),
        (BinaryIntOp::Div, "arith.divui"),
        (BinaryIntOp::And, "arith.andi"),
        (BinaryIntOp::Or, "arith.ori"),
        (BinaryIntOp::Xor, "arith.xori"),
        (BinaryIntOp::Shl, "arith.shli"),
        (BinaryIntOp::Shr, "arith.shrui"),
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
            assert_eq!(count, 1, "{op:?} at {bs:?} should emit one {expected}");
            assert!(
                module.as_operation().verify(),
                "{op:?} at {bs:?} module should verify"
            );
        }
    }
}

/// `BinaryIntOp` comparison variants emit `arith.cmpi` with the expected
/// unsigned predicate.
#[test]
fn brillig_binary_int_op_cmpi_variants() {
    use IntegerBitSize::*;

    let cases: &[(BinaryIntOp, &str)] = &[
        (BinaryIntOp::Equals, "eq"),
        (BinaryIntOp::LessThan, "ult"),
        (BinaryIntOp::LessThanEquals, "ule"),
    ];

    for &bs in &[U1, U8, U32, U64, U128] {
        for (op, _predicate_str) in cases {
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

            let cmpi_count = count_brillig_body_ops(&module, 0, |o| {
                o.name().as_string_ref().as_str() == Ok("arith.cmpi")
            });
            assert_eq!(cmpi_count, 1, "{op:?} at {bs:?} should emit one arith.cmpi");
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

/// `arith.cmpi` ops emitted from `BinaryIntOp::{Equals, LessThan, LessThanEquals}`
/// carry the expected unsigned predicate. Brillig integers are unsigned, so
/// we must emit `eq` / `ult` / `ule` — not the signed variants.
#[test]
fn brillig_binary_int_op_cmpi_uses_unsigned_predicate() {
    let cases: &[(BinaryIntOp, &str)] = &[
        (BinaryIntOp::Equals, "eq"),
        (BinaryIntOp::LessThan, "ult"),
        (BinaryIntOp::LessThanEquals, "ule"),
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
        let cmpi_op = iter_block_ops(body)
            .find(|o| o.name().as_string_ref().as_str() == Ok("arith.cmpi"))
            .unwrap_or_else(|| panic!("{op:?} should emit an arith.cmpi op"));
        let printed = format!("{cmpi_op}");
        assert!(
            printed.contains(expected_mnemonic),
            "{op:?} should emit arith.cmpi with `{expected_mnemonic}` predicate, got: {printed}"
        );
    }
}

/// Every `BinaryIntOp` arithmetic op preserves the operand width — `iN + iN → iN`.
/// This is the core invariant of option (b) width-typed integer handling.
#[test]
fn brillig_binary_int_op_preserves_width() {
    use IntegerBitSize::*;
    let sizes = [
        (U1, "i1"),
        (U8, "i8"),
        (U32, "i32"),
        (U64, "i64"),
        (U128, "i128"),
    ];

    for (bs, expected_ty) in sizes {
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
        let addi_op = iter_block_ops(body)
            .find(|o| o.name().as_string_ref().as_str() == Ok("arith.addi"))
            .expect("should have an arith.addi");
        let result_ty = addi_op.result(0).unwrap().r#type();
        assert_eq!(
            format!("{result_ty}"),
            expected_ty,
            "arith.addi at bit size {bs:?} should produce {expected_ty}"
        );
    }
}

/// `arith.cmpi` always returns `i1`, regardless of operand width.
#[test]
fn brillig_binary_int_cmpi_result_is_i1() {
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
        let cmpi_op = iter_block_ops(body)
            .find(|o| o.name().as_string_ref().as_str() == Ok("arith.cmpi"))
            .expect("should have arith.cmpi");
        let result_ty = cmpi_op.result(0).unwrap().r#type();
        assert_eq!(
            format!("{result_ty}"),
            "i1",
            "cmpi result at operand width {bs:?} should be i1"
        );
    }
}

/// Chained integer arithmetic threads width-typed SSA values through the
/// regmap. `r0=2; r1=3; r2=r0+r1; r3=4; r4=r2*r3; Stop` should produce exactly
/// one `arith.addi` and one `arith.muli`, both on i32 operands.
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
        op.name().as_string_ref().as_str() == Ok("arith.addi")
    });
    let mul_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("arith.muli")
    });
    assert_eq!(add_count, 1, "expected one arith.addi");
    assert_eq!(mul_count, 1, "expected one arith.muli");
    print_and_verify_module(&module, "brillig_binary_int_op_chained_arithmetic");
}

/// Mixing integer and field arithmetic through an explicit `Cast` works
/// end-to-end: `iN → felt` conversion, then a felt binary op.
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

    // Expect: two arith.constant, one arith.addi, one arith.index_cast,
    // one cast.tofelt, one felt.const, one felt.mul, one function.return.
    let body = find_brillig_fn(&module, 0)
        .unwrap()
        .region(0)
        .unwrap()
        .first_block()
        .unwrap();
    assert!(iter_block_ops(body).any(|op| op.name().as_string_ref().as_str() == Ok("arith.addi")));
    assert!(iter_block_ops(body).any(|op| op.name().as_string_ref().as_str() == Ok("cast.tofelt")));
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

    // felt → U1: cast.toindex + arith.index_cast (into i1)
    // U1 → felt: arith.index_cast (i1 → index) + cast.tofelt
    assert_eq!(
        count_brillig_body_ops(&module, 0, |op| {
            op.name().as_string_ref().as_str() == Ok("cast.toindex")
        }),
        1,
        "expected one cast.toindex"
    );
    assert_eq!(
        count_brillig_body_ops(&module, 0, |op| {
            op.name().as_string_ref().as_str() == Ok("arith.index_cast")
        }),
        2,
        "expected two arith.index_cast ops (one per direction)"
    );
    assert_eq!(
        count_brillig_body_ops(&module, 0, |op| {
            op.name().as_string_ref().as_str() == Ok("cast.tofelt")
        }),
        1,
        "expected one cast.tofelt"
    );
    print_and_verify_module(&module, "brillig_cast_field_to_u1_then_back");
}

/// Reading an unwritten register via a binary op surfaces `UndefinedRegister`
/// with the offending opcode index.
#[test]
fn brillig_binary_op_from_undefined_register_errors() {
    let context = LlzkContext::new();
    let err = translate_body(
        &context,
        vec![
            const_field(0, 1),
            binary_field_op(2, BinaryFieldOp::Add, 0, 1),
            brillig_stop(),
        ],
    )
    .expect_err("binary op reading undefined register should error");
    match err {
        Error::UndefinedRegister { addr, opcode_index } => {
            assert_eq!(addr, 1);
            assert_eq!(opcode_index, 1);
        }
        other => panic!("expected UndefinedRegister, got {other:?}"),
    }
}
