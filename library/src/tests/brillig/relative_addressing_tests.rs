//! Tests for `MemoryAddress::Relative` resolution in the Brillig translator.

use acir::FieldElement;
use acir::brillig::{BitSize, IntegerBitSize, Opcode as BrilligOpcode};
use llzk::prelude::{LlzkContext, OperationLike};

use super::{addr, brillig_stop, const_field, const_int, rel, translate_body};
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
