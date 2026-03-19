use acir::{
    FieldElement,
    circuit::Opcode,
    circuit::opcodes::{BlockId, BlockType},
    native_types::Witness,
};
use llzk::prelude::LlzkContext;

use super::{make_circuit_with_opcodes, translate_single_circuit, verify_struct_in_module};

fn memory_init(block_id: u32, init: &[u32], block_type: BlockType) -> Opcode<FieldElement> {
    Opcode::MemoryInit {
        block_id: BlockId(block_id),
        init: init.iter().map(|&w| Witness(w)).collect(),
        block_type,
    }
}

/// Single `MemoryInit` with 3 witnesses → struct has `@mem0 : !array.type<!felt.type, 3>`,
/// compute initializes all three slots.
#[test]
fn single_memory_init_three_witnesses() {
    let context = LlzkContext::new();
    let opcodes = vec![memory_init(0, &[2, 3, 4], BlockType::Memory)];
    // witnesses 2, 3, 4 are inputs (private parameters)
    let circuit = make_circuit_with_opcodes(4, &[2, 3, 4], &[], &[], opcodes);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();
    verify_struct_in_module(&context, struct_def, "single_memory_init_three_witnesses");
}

/// Two `MemoryInit` blocks with different `block_id`s → two distinct array members.
#[test]
fn two_memory_init_blocks() {
    let context = LlzkContext::new();
    let opcodes = vec![
        memory_init(0, &[2, 3], BlockType::Memory),
        memory_init(1, &[4, 5, 6], BlockType::Memory),
    ];
    let circuit = make_circuit_with_opcodes(6, &[2, 3, 4, 5, 6], &[], &[], opcodes);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();
    verify_struct_in_module(&context, struct_def, "two_memory_init_blocks");
}

/// `MemoryInit` where init witnesses overlap with input parameters → values are read
/// from the function-argument cache, not from struct members.
#[test]
fn memory_init_witnesses_overlap_with_inputs() {
    let context = LlzkContext::new();
    // Witnesses 0, 1, 2 are private inputs AND the init vector; no struct members for them.
    let opcodes = vec![memory_init(0, &[0, 1, 2], BlockType::Memory)];
    let circuit = make_circuit_with_opcodes(2, &[0, 1, 2], &[], &[], opcodes);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();
    verify_struct_in_module(
        &context,
        struct_def,
        "memory_init_witnesses_overlap_with_inputs",
    );
}

/// Empty init vector (length 0) → zero-length array member, no writes in compute.
#[test]
fn memory_init_empty_init_vector() {
    let context = LlzkContext::new();
    let opcodes = vec![memory_init(0, &[], BlockType::Memory)];
    let circuit = make_circuit_with_opcodes(0, &[], &[], &[], opcodes);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();
    verify_struct_in_module(&context, struct_def, "memory_init_empty_init_vector");
}

/// `BlockType::CallData` → returns `UnsupportedOpcode` error.
#[test]
fn memory_init_call_data_unsupported() {
    let context = LlzkContext::new();
    let opcodes = vec![memory_init(0, &[0], BlockType::CallData(0))];
    let circuit = make_circuit_with_opcodes(0, &[0], &[], &[], opcodes);
    let result = translate_single_circuit(&context, circuit);
    assert!(
        matches!(result, Err(crate::Error::UnsupportedOpcode(_))),
        "expected UnsupportedOpcode for CallData, got {result:?}"
    );
}

/// `BlockType::ReturnData` → returns `UnsupportedOpcode` error.
#[test]
fn memory_init_return_data_unsupported() {
    let context = LlzkContext::new();
    let opcodes = vec![memory_init(0, &[0], BlockType::ReturnData)];
    let circuit = make_circuit_with_opcodes(0, &[0], &[], &[], opcodes);
    let result = translate_single_circuit(&context, circuit);
    assert!(
        matches!(result, Err(crate::Error::UnsupportedOpcode(_))),
        "expected UnsupportedOpcode for ReturnData, got {result:?}"
    );
}
