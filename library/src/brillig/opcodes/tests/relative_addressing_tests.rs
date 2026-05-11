//! Tests for `MemoryAddress::Relative` resolution in the Brillig translator.
use acir::brillig::{IntegerBitSize, Opcode as BrilligOpcode};
use llzk::prelude::{LlzkContext, OperationLike};

use crate::brillig::test_helpers::{
    addr, brillig_stop, const_field, const_int, rel, translate_body,
};

#[test]
fn relative_address_lowers_to_runtime_sp_load() {
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
    .expect("translation should succeed");
    assert!(module.as_operation().verify());

    // Relative(5) is no longer folded — it lowers to `ram.load @0` +
    // `cast.toindex` + `arith.constant 5 : index` + `arith.addi`.
    // Direct(15) still emits `arith.constant 15 : index` for the Const
    // store; we only assert the Relative slot's sentinel constant.
    let ir = format!("{}", module.as_operation());
    assert!(
        ir.contains("arith.constant 5 : index"),
        "Relative(5) should appear as a runtime offset constant:\n{ir}"
    );
}
