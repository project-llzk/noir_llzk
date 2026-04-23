//! Tests for `MemoryAddress::Relative` resolution in the Brillig translator.

use acir::FieldElement;
use acir::brillig::{BinaryIntOp, BitSize, IntegerBitSize, Opcode as BrilligOpcode};
use llzk::prelude::{LlzkContext, OperationLike};

use super::{addr, binary_int_op, brillig_stop, const_field, const_int, rel, translate_body};
use crate::Error;

#[test]
fn relative_address_aliases_with_direct_after_sp_init() {
    let context = LlzkContext::new();
    let module = translate_body(
        &context,
        vec![
            // SP = 10
            const_int(0, IntegerBitSize::U32, 10),
            // Direct(15) = 42  (== Relative(5) once SP=10)
            const_field(15, 42),
            // Mov Relative(5) -> Direct(20)
            BrilligOpcode::Mov {
                destination: addr(20),
                source: rel(5),
            },
            brillig_stop(),
        ],
    )
    .expect("translation should succeed once SP is set");
    assert!(module.as_operation().verify());

    // Relative(5) with SP=10 must resolve to Direct(15). The slot-index
    // constants used by ram.load/ram.store are emitted as `arith.constant N
    // : index`, so the IR should contain `arith.constant 15 : index` (the
    // resolved Mov source) and MUST NOT contain `arith.constant 5 : index`
    // (which would indicate the translator read from the unresolved slot).
    let ir = format!("{}", module.as_operation());
    assert!(
        ir.contains("arith.constant 15 : index"),
        "IR should address slot 15 (Relative(5) + SP=10):\n{ir}"
    );
    assert!(
        !ir.contains("arith.constant 5 : index"),
        "IR must not address raw slot 5 — Relative(5) should have resolved:\n{ir}"
    );
}

#[test]
fn relative_const_without_sp_init_errors() {
    let context = LlzkContext::new();
    let err = translate_body(
        &context,
        vec![
            BrilligOpcode::Const {
                destination: rel(5),
                bit_size: BitSize::Field,
                value: FieldElement::from(42u128),
            },
            brillig_stop(),
        ],
    )
    .expect_err("Relative write without SP init should fail");
    assert!(
        matches!(err, Error::UnresolvedStackPointer { offset: 5 }),
        "expected UnresolvedStackPointer {{ offset: 5 }}, got {err:?}"
    );
}

#[test]
fn sp_prologue_add_updates_stack_pointer() {
    // Brillig's call-frame prologue advances SP via `BinaryIntOp::Add` on
    // slot 0 rather than a fresh `Const`. If the handler doesn't fold this
    // into the frame stack, subsequent `Relative(_)` accesses resolve
    // against the caller's SP.
    let context = LlzkContext::new();
    let module = translate_body(
        &context,
        vec![
            // SP = 10
            const_int(0, IntegerBitSize::U32, 10),
            // register 5 = 3 (frame-size constant)
            const_int(5, IntegerBitSize::U32, 3),
            // slot 0 += register 5  → SP = 13
            binary_int_op(0, BinaryIntOp::Add, IntegerBitSize::U32, 0, 5),
            // Direct(13) = 42  (== Relative(0) once SP=13)
            const_field(13, 42),
            // Mov Relative(0) -> Direct(20)
            BrilligOpcode::Mov {
                destination: addr(20),
                source: rel(0),
            },
            brillig_stop(),
        ],
    )
    .expect("translation should succeed once SP prologue is folded");
    assert!(module.as_operation().verify());

    let ir = format!("{}", module.as_operation());
    assert!(
        ir.contains("arith.constant 13 : index"),
        "IR should address slot 13 (Relative(0) + SP=13):\n{ir}"
    );
}

#[test]
fn sp_prologue_add_with_unknown_rhs_leaves_sp_invalid() {
    // If the prologue's RHS isn't a tracked integer constant, the handler
    // cannot fold and SP is left invalidated — any later `Relative(_)` access
    // must error rather than resolve against a stale SP.
    let context = LlzkContext::new();
    let err = translate_body(
        &context,
        vec![
            // SP = 10
            const_int(0, IntegerBitSize::U32, 10),
            // register 5 holds a computed (non-Const-tracked) value
            const_field(5, 3),
            // slot 0 += register 5  → can't fold; SP invalidated
            binary_int_op(0, BinaryIntOp::Add, IntegerBitSize::U32, 0, 5),
            // Mov Relative(0) -> Direct(20)  — should now fail
            BrilligOpcode::Mov {
                destination: addr(20),
                source: rel(0),
            },
            brillig_stop(),
        ],
    )
    .expect_err("Relative read after unfoldable SP prologue should fail");
    assert!(
        matches!(err, Error::UnresolvedStackPointer { offset: 0 }),
        "expected UnresolvedStackPointer {{ offset: 0 }}, got {err:?}"
    );
}

#[test]
fn relative_read_without_sp_init_errors() {
    let context = LlzkContext::new();
    let err = translate_body(
        &context,
        vec![
            // Stash a value somewhere first so the Mov has something to read.
            const_field(15, 42),
            // Mov Relative(5) -> Direct(20) without an SP-init Const above.
            BrilligOpcode::Mov {
                destination: addr(20),
                source: rel(5),
            },
            brillig_stop(),
        ],
    )
    .expect_err("Relative read without SP init should fail");
    assert!(
        matches!(err, Error::UnresolvedStackPointer { offset: 5 }),
        "expected UnresolvedStackPointer {{ offset: 5 }}, got {err:?}"
    );
}
