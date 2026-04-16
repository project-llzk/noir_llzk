//! The dialect models a single flat memory region with no allocation op and
//! no memory-handle operand: `ram.load %addr : type` and
//! `ram.store %addr, %val : type`. Pointer registers are coerced to `index`
//! type via `cast.toindex` (felt) or `arith.index_cast` (`iN`) before being
//! handed to the memory ops.

use acir::brillig::IntegerBitSize;
use llzk::prelude::{LlzkContext, OperationLike};

use super::super::print_and_verify_module;
use super::{
    brillig_stop, const_field, const_int, count_brillig_body_ops, load, store, translate_body,
};
use crate::Error;

/// `Store` followed by `Load` at the same pointer emits one `ram.store`
/// and one `ram.load`. There is no `ram.alloc`.
#[test]
fn brillig_store_then_load_emits_ram_ops() {
    let context = LlzkContext::new();
    let module = translate_body(
        &context,
        vec![
            const_int(0, IntegerBitSize::U32, 0), // r0 = pointer 0
            const_field(1, 99),                   // r1 = value 99
            store(0, 1),                          // mem[r0] = r1
            load(2, 0),                           // r2 = mem[r0]
            brillig_stop(),
        ],
    )
    .expect("translation should succeed");

    let store_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("ram.store")
    });
    let load_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("ram.load")
    });
    let alloc_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("ram.alloc")
    });
    assert_eq!(store_count, 1, "expected one ram.store");
    assert_eq!(load_count, 1, "expected one ram.load");
    assert_eq!(
        alloc_count, 0,
        "ram.alloc should never appear — the dialect has no allocation op"
    );

    print_and_verify_module(&module, "brillig_store_then_load_emits_ram_ops");
}

/// Two stores at distinct pointers each become a `ram.store` against the
/// shared anonymous memory region.
#[test]
fn brillig_two_stores_emit_two_ram_stores() {
    let context = LlzkContext::new();
    let module = translate_body(
        &context,
        vec![
            const_int(0, IntegerBitSize::U32, 0),
            const_int(1, IntegerBitSize::U32, 4),
            const_field(2, 11),
            const_field(3, 22),
            store(0, 2),
            store(1, 3),
            brillig_stop(),
        ],
    )
    .expect("translation should succeed");

    let store_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("ram.store")
    });
    assert_eq!(store_count, 2, "expected two ram.store ops");

    print_and_verify_module(&module, "brillig_two_stores_emit_two_ram_stores");
}

/// A felt-typed pointer register is coerced to `index` via `cast.toindex`
/// before `ram.load` consumes it.
#[test]
fn brillig_load_with_felt_pointer_emits_cast_toindex() {
    let context = LlzkContext::new();
    let module = translate_body(
        &context,
        vec![
            const_field(0, 0), // felt-typed pointer
            load(1, 0),
            brillig_stop(),
        ],
    )
    .expect("translation should succeed");

    let toindex_count = count_brillig_body_ops(&module, 0, |op| {
        op.name().as_string_ref().as_str() == Ok("cast.toindex")
    });
    assert_eq!(
        toindex_count, 1,
        "felt pointer should produce one cast.toindex"
    );
    print_and_verify_module(&module, "brillig_load_with_felt_pointer_emits_cast_toindex");
}

/// An `iN`-typed pointer register goes through `arith.index_cast` (not
/// `cast.toindex`, which is the felt→index path).
#[test]
fn brillig_load_with_int_pointer_emits_arith_index_cast() {
    let context = LlzkContext::new();
    let module = translate_body(
        &context,
        vec![
            const_int(0, IntegerBitSize::U32, 0),
            load(1, 0),
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
    assert_eq!(toindex_count, 0, "iN pointer must not use cast.toindex");
    assert_eq!(
        index_cast_count, 1,
        "iN pointer should produce one arith.index_cast"
    );
    print_and_verify_module(
        &module,
        "brillig_load_with_int_pointer_emits_arith_index_cast",
    );
}

/// Reading an unwritten pointer register via `Load` surfaces an
/// `UndefinedRegister` error with the offending bytecode index.
#[test]
fn brillig_load_with_undefined_pointer_errors() {
    let context = LlzkContext::new();
    let err = translate_body(&context, vec![load(1, 0), brillig_stop()])
        .expect_err("Load from undefined pointer should error");
    match err {
        Error::UndefinedRegister { addr, opcode_index } => {
            assert_eq!(addr, 0);
            assert_eq!(opcode_index, 0);
        }
        other => panic!("expected UndefinedRegister, got {other:?}"),
    }
}

/// Reading an unwritten source register via `Store` surfaces an
/// `UndefinedRegister` error with the offending bytecode index.
#[test]
fn brillig_store_with_undefined_source_errors() {
    let context = LlzkContext::new();
    let err = translate_body(
        &context,
        vec![
            const_int(0, IntegerBitSize::U32, 0), // pointer is defined
            store(0, 1),                          // but source r1 isn't
            brillig_stop(),
        ],
    )
    .expect_err("Store from undefined source should error");
    match err {
        Error::UndefinedRegister { addr, opcode_index } => {
            assert_eq!(addr, 1);
            assert_eq!(opcode_index, 1);
        }
        other => panic!("expected UndefinedRegister, got {other:?}"),
    }
}
