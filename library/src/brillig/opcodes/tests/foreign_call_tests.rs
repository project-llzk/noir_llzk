//! Tests for `BrilligOpcode::ForeignCall` lowering.
//!
//! Empty `destinations` (the production-path debug/print hooks) emit
//! nothing; non-empty destinations turn each output slot into one
//! `llzk.nondet` plus a `ram.store`.

use acir::brillig::lengths::{SemanticLength, SemiFlattenedLength};
use acir::brillig::{
    BitSize, HeapArray, HeapValueType, HeapVector, IntegerBitSize, Opcode as BrilligOpcode,
    ValueOrArray,
};
use llzk::prelude::LlzkContext;

use crate::brillig::test_helpers::{
    addr, brillig_stop, const_int, count_loads, count_op, count_stores, store, translate_body,
};
use crate::tests::print_and_verify_module;

fn foreign_call_empty(name: &str) -> BrilligOpcode<acir::FieldElement> {
    BrilligOpcode::ForeignCall {
        function: name.into(),
        destinations: vec![],
        destination_value_types: vec![],
        inputs: vec![],
        input_value_types: vec![],
    }
}

fn foreign_call(
    name: &str,
    destinations: Vec<ValueOrArray>,
    destination_value_types: Vec<HeapValueType>,
) -> BrilligOpcode<acir::FieldElement> {
    BrilligOpcode::ForeignCall {
        function: name.into(),
        destinations,
        destination_value_types,
        inputs: vec![],
        input_value_types: vec![],
    }
}

/// `print` and the `__debug_*` family compile to ForeignCall ops with
/// empty destinations — they must be a no-op in LLZK output.
#[test]
fn foreign_call_empty_destinations_emits_nothing() {
    let context = LlzkContext::new();
    let module = translate_body(&context, vec![foreign_call_empty("print"), brillig_stop()])
        .expect("translation should succeed");

    assert_eq!(
        count_op(&module, 0, "llzk.nondet"),
        0,
        "empty-destination ForeignCall must not emit any nondet"
    );

    print_and_verify_module(&module, "foreign_call_empty_destinations_emits_nothing");
}

/// A single `MemoryAddress` destination of field type emits one
/// `llzk.nondet` and one `ram.store` for that slot.
#[test]
fn foreign_call_single_field_destination_emits_one_nondet() {
    let context = LlzkContext::new();
    let baseline = count_stores(
        &translate_body(&context, vec![brillig_stop()])
            .expect("baseline translation should succeed"),
        0,
    );

    let module = translate_body(
        &context,
        vec![
            foreign_call(
                "oracle_field",
                vec![ValueOrArray::MemoryAddress(addr(7))],
                vec![HeapValueType::Simple(BitSize::Field)],
            ),
            brillig_stop(),
        ],
    )
    .expect("translation should succeed");

    assert_eq!(
        count_op(&module, 0, "llzk.nondet"),
        1,
        "one MemoryAddress destination should emit exactly one nondet"
    );
    assert_eq!(
        count_stores(&module, 0),
        baseline + 1,
        "the nondet should be backed by exactly one ram.store"
    );
    // No mask is needed for a Field-typed destination.
    assert_eq!(
        count_op(&module, 0, "felt.bit_and"),
        0,
        "Field destination must not emit a mask"
    );

    print_and_verify_module(
        &module,
        "foreign_call_single_field_destination_emits_one_nondet",
    );
}

/// `HeapArray` destination with statically-known size emits one nondet
/// + one store per slot at base..base+size.
#[test]
fn foreign_call_heap_array_destination_emits_per_slot_nondet() {
    let context = LlzkContext::new();
    // r10 = pointer (base address 100) for the destination array.
    let prelude = [const_int(10, IntegerBitSize::U32, 100)];
    let baseline = translate_body(
        &context,
        prelude
            .iter()
            .cloned()
            .chain(std::iter::once(brillig_stop()))
            .collect(),
    )
    .expect("baseline translation should succeed");
    let baseline_stores = count_stores(&baseline, 0);

    let body = prelude
        .iter()
        .cloned()
        .chain([
            foreign_call(
                "oracle_array",
                vec![ValueOrArray::HeapArray(HeapArray {
                    pointer: addr(10),
                    size: SemiFlattenedLength(3),
                })],
                vec![HeapValueType::Array {
                    value_types: vec![HeapValueType::Simple(BitSize::Field)],
                    size: SemanticLength(3),
                }],
            ),
            brillig_stop(),
        ])
        .collect();

    let module = translate_body(&context, body).expect("translation should succeed");

    assert_eq!(
        count_op(&module, 0, "llzk.nondet"),
        3,
        "one nondet per array slot"
    );
    assert_eq!(
        count_stores(&module, 0),
        baseline_stores + 3,
        "three additional ram.stores for the three array slots"
    );

    print_and_verify_module(
        &module,
        "foreign_call_heap_array_destination_emits_per_slot_nondet",
    );
}

/// `HeapArray` whose elements are themselves arrays follows the
/// inner pointer at runtime and recurses, emitting one nondet+store
/// per *leaf* slot (`outer_count × inner_count` total).
#[test]
fn foreign_call_nested_array_destination_recurses() {
    let context = LlzkContext::new();
    // Outer array of 2 elements at base 100 (slots 100..101). Each
    // outer slot is a pointer to a separately-allocated inner array of
    // 3 fields:
    //   slot 100 → 200 (inner #0 at base 200..202)
    //   slot 101 → 300 (inner #1 at base 300..302)
    let body = vec![
        const_int(10, IntegerBitSize::U32, 100), // r10 = outer base pointer
        const_int(11, IntegerBitSize::U32, 101), // r11 = address of outer slot 1
        const_int(19, IntegerBitSize::U32, 200), // r19 = inner #0 base
        const_int(29, IntegerBitSize::U32, 300), // r29 = inner #1 base
        store(10, 19),                           // mem[100] = 200
        store(11, 29),                           // mem[101] = 300
        foreign_call(
            "oracle_nested",
            vec![ValueOrArray::HeapArray(HeapArray {
                pointer: addr(10),
                size: SemiFlattenedLength(2),
            })],
            vec![HeapValueType::Array {
                value_types: vec![HeapValueType::Array {
                    value_types: vec![HeapValueType::Simple(BitSize::Field)],
                    size: SemanticLength(3),
                }],
                size: SemanticLength(2),
            }],
        ),
        brillig_stop(),
    ];

    let module = translate_body(&context, body).expect("translation should succeed");

    assert_eq!(
        count_op(&module, 0, "llzk.nondet"),
        6,
        "two outer × three inner = six leaf nondets"
    );

    print_and_verify_module(&module, "foreign_call_nested_array_destination_recurses");
}

/// HeapArray whose pointer register isn't a tracked compile-time
/// constant lowers via the dynamic path: the pointer is read at runtime
/// via `ram.load` + `cast.toindex`, and the per-slot nondet+store
/// sequence runs against the resulting base index. The slot count is
/// fixed at compile time so no loop is emitted.
#[test]
fn foreign_call_heap_array_runtime_pointer_emits_per_slot_nondet() {
    let context = LlzkContext::new();
    // r10 is the pointer register but its value is intentionally not a
    // tracked compile-time constant.
    let baseline = translate_body(&context, vec![brillig_stop()])
        .expect("baseline translation should succeed");
    let baseline_loads = count_loads(&baseline, 0);

    let body = vec![
        foreign_call(
            "oracle_array",
            vec![ValueOrArray::HeapArray(HeapArray {
                pointer: addr(10),
                size: SemiFlattenedLength(3),
            })],
            vec![HeapValueType::Array {
                value_types: vec![HeapValueType::Simple(BitSize::Field)],
                size: SemanticLength(3),
            }],
        ),
        brillig_stop(),
    ];

    let module = translate_body(&context, body).expect("translation should succeed");

    assert_eq!(
        count_op(&module, 0, "llzk.nondet"),
        3,
        "one nondet per array slot regardless of pointer tracking"
    );
    assert_eq!(
        count_op(&module, 0, "scf.while"),
        0,
        "compile-time-known size must not introduce a loop"
    );
    assert_eq!(
        count_loads(&module, 0),
        baseline_loads + 1,
        "dynamic-pointer path must dereference the pointer with one ram.load"
    );

    print_and_verify_module(
        &module,
        "foreign_call_heap_array_runtime_pointer_emits_per_slot_nondet",
    );
}

/// HeapVector whose size register isn't a tracked compile-time
/// constant lowers to a single `scf.while`: the slot count is read at
/// runtime and the per-slot nondet+store work runs inside the loop
/// body, so no `llzk.nondet` appears at the top level.
#[test]
fn foreign_call_heap_vector_dynamic_size_emits_while_loop() {
    let context = LlzkContext::new();
    // r10 = pointer (200). r11 (size) is intentionally not a tracked const.
    let body = vec![
        const_int(10, IntegerBitSize::U32, 200),
        foreign_call(
            "oracle_vec",
            vec![ValueOrArray::HeapVector(HeapVector {
                pointer: addr(10),
                size: addr(11),
            })],
            vec![HeapValueType::Vector {
                value_types: vec![HeapValueType::Simple(BitSize::Field)],
            }],
        ),
        brillig_stop(),
    ];

    let module = translate_body(&context, body).expect("translation should succeed");

    assert_eq!(
        count_op(&module, 0, "scf.while"),
        1,
        "dynamic-size HeapVector should emit one scf.while"
    );
    assert_eq!(
        count_op(&module, 0, "llzk.nondet"),
        0,
        "all nondets should live inside the scf.while body, not at the top level"
    );

    print_and_verify_module(
        &module,
        "foreign_call_heap_vector_dynamic_size_emits_while_loop",
    );
}
