//! Tests for `BrilligOpcode::BlackBox` lowering.
//!
//! Each `BlackBoxOp` variant routes through the same module-level
//! helper used by ACIR `BlackBoxFuncCall`. The handler reads the
//! source `HeapArray`'s slots into felts, calls the helper, and
//! writes the result felts back into the destination's slots.

use acir::brillig::lengths::SemiFlattenedLength;
use acir::brillig::{BlackBoxOp, HeapArray, IntegerBitSize, Opcode as BrilligOpcode};
use llzk::prelude::{LlzkContext, OperationLike};

use super::super::{count_occurrences, print_and_verify_module};
use super::{addr, brillig_stop, const_int, count_op, count_stores, translate_body};

fn poseidon2_blackbox(message: HeapArray, output: HeapArray) -> BrilligOpcode<acir::FieldElement> {
    BrilligOpcode::BlackBox(BlackBoxOp::Poseidon2Permutation { message, output })
}

fn heap_array(pointer: u32, size: u32) -> HeapArray {
    HeapArray {
        pointer: addr(pointer),
        size: SemiFlattenedLength(size),
    }
}

/// `BlackBox(Poseidon2Permutation)` lowers to: load each pointer
/// register's felt + cast.toindex, 4 ram.loads for the inputs, one
/// `function.call @poseidon2_permutation`, and 4 ram.stores for the
/// outputs. The shared `@poseidon2_permutation` helper is registered
/// once at module scope.
#[test]
fn poseidon2_blackbox_lowers_to_helper_call() {
    let context = LlzkContext::new();
    // r10 holds the input base, r11 holds the output base. The handler
    // reads each register's felt at runtime — the `const_int` prelude
    // here just makes the pointers concrete so the IR verifies.
    let prelude = [
        const_int(10, IntegerBitSize::U32, 100),
        const_int(11, IntegerBitSize::U32, 200),
    ];
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
    let baseline_loads = count_op(&baseline, 0, "ram.load");
    let baseline_casts = count_op(&baseline, 0, "cast.toindex");

    let body = prelude
        .iter()
        .cloned()
        .chain([
            poseidon2_blackbox(heap_array(10, 4), heap_array(11, 4)),
            brillig_stop(),
        ])
        .collect();

    let module = translate_body(&context, body).expect("translation should succeed");
    let ir = format!("{}", module.as_operation());

    assert!(module.as_operation().verify(), "Module should verify");
    assert_eq!(
        count_occurrences(&ir, "function.def @poseidon2_permutation"),
        1,
        "shared poseidon2 helper must be emitted exactly once"
    );
    assert_eq!(
        count_occurrences(&ir, "function.call @poseidon2_permutation"),
        1,
        "the BlackBox op should emit one call to the helper"
    );
    // 2 pointer felts + 4 input slots = 6 additional ram.loads.
    assert_eq!(
        count_op(&module, 0, "ram.load"),
        baseline_loads + 6,
        "two pointer reads + four input reads = six additional ram.loads"
    );
    assert_eq!(
        count_op(&module, 0, "cast.toindex"),
        baseline_casts + 2,
        "one cast.toindex per pointer felt"
    );
    assert_eq!(
        count_stores(&module, 0),
        baseline_stores + 4,
        "four output slots should be written to RAM on top of the prelude"
    );

    print_and_verify_module(&module, "poseidon2_blackbox_lowers_to_helper_call");
}

/// Two independent Poseidon2 BlackBox sites in one Brillig body share
/// the helper definition but each emits its own call.
#[test]
fn poseidon2_blackbox_shares_helper_across_call_sites() {
    let context = LlzkContext::new();
    let body = vec![
        const_int(10, IntegerBitSize::U32, 100), // input #1 base
        const_int(11, IntegerBitSize::U32, 200), // output #1 base
        const_int(12, IntegerBitSize::U32, 300), // input #2 base
        const_int(13, IntegerBitSize::U32, 400), // output #2 base
        poseidon2_blackbox(heap_array(10, 4), heap_array(11, 4)),
        poseidon2_blackbox(heap_array(12, 4), heap_array(13, 4)),
        brillig_stop(),
    ];

    let module = translate_body(&context, body).expect("translation should succeed");
    let ir = format!("{}", module.as_operation());

    assert_eq!(
        count_occurrences(&ir, "function.def @poseidon2_permutation"),
        1,
        "helper definition should be emitted exactly once across call sites"
    );
    assert_eq!(
        count_occurrences(&ir, "function.call @poseidon2_permutation"),
        2,
        "each BlackBox op should emit its own call"
    );

    print_and_verify_module(
        &module,
        "poseidon2_blackbox_shares_helper_across_call_sites",
    );
}

/// A BlackBox op whose pointer register isn't seeded by a tracked
/// constant still lowers cleanly — the handler reads the pointer's
/// felt from RAM at runtime rather than relying on translation-time
/// pointer tracking.
#[test]
fn poseidon2_blackbox_handles_runtime_pointer() {
    let context = LlzkContext::new();
    // No const_int prelude — neither r10 nor r11 is a tracked const.
    let body = vec![
        poseidon2_blackbox(heap_array(10, 4), heap_array(11, 4)),
        brillig_stop(),
    ];

    let module = translate_body(&context, body).expect("translation should succeed");
    let ir = format!("{}", module.as_operation());

    assert!(module.as_operation().verify(), "Module should verify");
    assert_eq!(
        count_occurrences(&ir, "function.call @poseidon2_permutation"),
        1,
        "runtime-only pointers should still call the helper"
    );
    assert_eq!(
        count_op(&module, 0, "cast.toindex"),
        2,
        "each HeapArray pointer felt gets cast to index"
    );
}

/// `Poseidon2Permutation` requires HeapArrays of size `STATE_WIDTH` (4)
/// on both sides — anything else is rejected before any IR is emitted.
#[test]
fn poseidon2_blackbox_rejects_wrong_arity() {
    let context = LlzkContext::new();
    let body = vec![
        const_int(10, IntegerBitSize::U32, 100),
        const_int(11, IntegerBitSize::U32, 200),
        poseidon2_blackbox(heap_array(10, 3), heap_array(11, 4)),
        brillig_stop(),
    ];

    let result = translate_body(&context, body);
    assert!(matches!(
        result,
        Err(crate::Error::UnsupportedBrillig { .. })
    ));
}

/// A BlackBox variant we don't yet lower (e.g. `ToRadix`, which is
/// Brillig-only and has no shared helper) errors with
/// `UnsupportedBrillig` rather than silently producing nothing.
#[test]
fn unsupported_blackbox_variant_errors_cleanly() {
    let context = LlzkContext::new();
    let body = vec![
        BrilligOpcode::BlackBox(BlackBoxOp::ToRadix {
            input: addr(10),
            radix: addr(11),
            output_pointer: addr(12),
            num_limbs: addr(13),
            output_bits: addr(14),
        }),
        brillig_stop(),
    ];

    let result = translate_body(&context, body);
    assert!(matches!(
        result,
        Err(crate::Error::UnsupportedBrillig { .. })
    ));
}
