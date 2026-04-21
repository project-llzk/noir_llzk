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
    // Every register write is backed by a ram.store and every register read
    // by a ram.load. So:
    //   ram.store: 1 per const_int, 1 per const_field, 1 for the Store opcode
    //              itself, and 1 for the Load's write_constant_address of
    //              the destination register = 4.
    //   ram.load:  2 from the Store (source slot + pointer slot),
    //              2 from the Load (pointer slot + dynamic load) = 4.
    assert_eq!(store_count, 4, "expected four ram.store ops");
    assert_eq!(load_count, 4, "expected four ram.load ops");
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
    // Every register write is backed by a ram.store, so each of the 4
    // Const opcodes emits one, plus one per actual Store opcode = 6.
    assert_eq!(store_count, 6, "expected six ram.store ops");

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

/// Pointer registers are felts regardless of how the Brillig opcode
/// declares them. A `Load` through an `iN`-declared pointer just emits
/// `cast.toindex` on the felt to feed it into `ram.load`. No
/// `arith.index_cast` is involved — there are no `iN`-typed values in
/// the emitted IR.
#[test]
fn brillig_load_with_int_pointer_emits_cast_toindex() {
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
    assert_eq!(
        toindex_count, 1,
        "felt pointer should produce one cast.toindex"
    );
    assert_eq!(index_cast_count, 0, "no arith.index_cast — no iN types");
    print_and_verify_module(&module, "brillig_load_with_int_pointer_emits_cast_toindex");
}
