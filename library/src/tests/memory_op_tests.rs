use acir::{
    AcirField, FieldElement,
    circuit::Opcode,
    circuit::opcodes::{BlockId, BlockType, MemOp},
    native_types::{Expression, Witness},
};
use llzk::prelude::LlzkContext;

use super::{make_circuit_with_opcodes, print_and_verify_module, translate_circuit_to_module};

// ── Helpers ────────────────────────────────────────────────────────────

fn memory_init(block_id: u32, init: &[u32]) -> Opcode<FieldElement> {
    Opcode::MemoryInit {
        block_id: BlockId(block_id),
        init: init.iter().map(|&w| Witness(w)).collect(),
        block_type: BlockType::Memory,
    }
}

/// Creates a MemoryOp read: `value_witness = block[index_witness]`
fn memory_read(block_id: u32, index_witness: u32, value_witness: u32) -> Opcode<FieldElement> {
    Opcode::MemoryOp {
        block_id: BlockId(block_id),
        op: MemOp {
            operation: Expression::zero(),
            index: Expression::from(Witness(index_witness)),
            value: Expression::from(Witness(value_witness)),
        },
    }
}

/// Creates a MemoryOp read with a constant index.
fn memory_read_const_index(block_id: u32, index: u32, value_witness: u32) -> Opcode<FieldElement> {
    Opcode::MemoryOp {
        block_id: BlockId(block_id),
        op: MemOp {
            operation: Expression::zero(),
            index: Expression {
                mul_terms: vec![],
                linear_combinations: vec![],
                q_c: FieldElement::from(index as u128),
            },
            value: Expression::from(Witness(value_witness)),
        },
    }
}

/// Creates a MemoryOp write: `block[index_witness] = value_witness`
fn memory_write(block_id: u32, index_witness: u32, value_witness: u32) -> Opcode<FieldElement> {
    Opcode::MemoryOp {
        block_id: BlockId(block_id),
        op: MemOp {
            operation: Expression::one(),
            index: Expression::from(Witness(index_witness)),
            value: Expression::from(Witness(value_witness)),
        },
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

/// Read from initialized array at constant index → `MemRead` subcomponent
/// emitted, value witness solved, single constraint in constrain.
#[test]
fn read_at_constant_index() {
    let context = LlzkContext::new();
    // block 0: init with witnesses 2, 3, 4 (array of length 3)
    // read at constant index 1, result in witness 5
    let opcodes = vec![memory_init(0, &[2, 3, 4]), memory_read_const_index(0, 1, 5)];
    // w0..=4 are inputs, w5 is the output
    let circuit = make_circuit_with_opcodes(5, &[0, 1, 2, 3, 4], &[], &[], opcodes);
    let module = translate_circuit_to_module(&context, circuit).unwrap();
    print_and_verify_module(&module, "read_at_constant_index");
}

/// Read at witness-derived (dynamic) index → dynamic `array.read` in both
/// compute and constrain.
#[test]
fn read_at_dynamic_index() {
    let context = LlzkContext::new();
    // block 0: init with witnesses 2, 3, 4, 5, 6 (array of length 5)
    // read at witness 0, result in witness 8
    let opcodes = vec![memory_init(0, &[2, 3, 4, 5, 6]), memory_read(0, 0, 8)];
    let circuit = make_circuit_with_opcodes(8, &[0, 1, 2, 3, 4, 5, 6], &[], &[], opcodes);
    let module = translate_circuit_to_module(&context, circuit).unwrap();
    print_and_verify_module(&module, "read_at_dynamic_index");
}

/// Write to array then read back same index → read receives `write.new_data`
/// (v1), not `block.data` (v0).
#[test]
fn write_then_read() {
    let context = LlzkContext::new();
    // block 0: init with w2, w3, w4, w5 (length 4)
    // write at w0 with value w10
    // read at w0 into w15
    let opcodes = vec![
        memory_init(0, &[2, 3, 4, 5]),
        memory_write(0, 0, 10),
        memory_read(0, 0, 15),
    ];
    let circuit = make_circuit_with_opcodes(15, &[0, 1, 2, 3, 4, 5, 10], &[], &[], opcodes);
    let module = translate_circuit_to_module(&context, circuit).unwrap();
    print_and_verify_module(&module, "write_then_read");
}

/// Multiple reads from same block (no writes) → both read from v0.
#[test]
fn multiple_reads_no_writes() {
    let context = LlzkContext::new();
    // block 0: init with w2, w3, w4, w5, w6 (length 5)
    // read at w0 → w8
    // read at w1 → w14
    let opcodes = vec![
        memory_init(0, &[2, 3, 4, 5, 6]),
        memory_read(0, 0, 8),
        memory_read(0, 1, 14),
    ];
    let circuit = make_circuit_with_opcodes(14, &[0, 1, 2, 3, 4, 5, 6], &[], &[], opcodes);
    let module = translate_circuit_to_module(&context, circuit).unwrap();
    print_and_verify_module(&module, "multiple_reads_no_writes");
}

/// Multiple writes to same block → version chain: v0 → v1 → v2.
#[test]
fn multiple_writes() {
    let context = LlzkContext::new();
    // block 0: init with w2, w3, w4 (length 3)
    // write at w0 with value w10: v0 → v1
    // write at w1 with value w11: v1 → v2
    // read at w0 → w20 (from v2)
    let opcodes = vec![
        memory_init(0, &[2, 3, 4]),
        memory_write(0, 0, 10),
        memory_write(0, 1, 11),
        memory_read(0, 0, 20),
    ];
    let circuit = make_circuit_with_opcodes(20, &[0, 1, 2, 3, 4, 10, 11], &[], &[], opcodes);
    let module = translate_circuit_to_module(&context, circuit).unwrap();
    print_and_verify_module(&module, "multiple_writes");
}

/// Interleaved reads and writes to same block → correct version at each
/// operation.
#[test]
fn interleaved_reads_and_writes() {
    let context = LlzkContext::new();
    // block 0: init with w2, w3, w4 (length 3)
    // read at w0 → w10 (reads from v0)
    // write at w1 with value w11: v0 → v1
    // read at w0 → w12 (reads from v1)
    let opcodes = vec![
        memory_init(0, &[2, 3, 4]),
        memory_read(0, 0, 10),
        memory_write(0, 1, 11),
        memory_read(0, 0, 12),
    ];
    let circuit = make_circuit_with_opcodes(12, &[0, 1, 2, 3, 4, 11], &[], &[], opcodes);
    println!("ACIR: \n{:?}", circuit);
    let module = translate_circuit_to_module(&context, circuit).unwrap();
    print_and_verify_module(&module, "interleaved_reads_and_writes");
}

/// Operation expression is not 0 or 1 → error.
#[test]
fn non_constant_operation_errors() {
    let context = LlzkContext::new();
    let opcodes = vec![
        memory_init(0, &[2, 3]),
        Opcode::MemoryOp {
            block_id: BlockId(0),
            op: MemOp {
                // operation is a witness, not a constant
                operation: Expression::from(Witness(0)),
                index: Expression::from(Witness(1)),
                value: Expression::from(Witness(5)),
            },
        },
    ];
    let circuit = make_circuit_with_opcodes(5, &[0, 1, 2, 3], &[], &[], opcodes);
    let result = translate_circuit_to_module(&context, circuit);
    assert!(
        matches!(result, Err(crate::Error::NonConstantMemoryOperation { .. })),
        "expected NonConstantMemoryOperation, got {result:?}"
    );
}

/// MemRead and MemWrite struct defs are deduplicated by array size.
/// Two reads from same-sized array → single MemRead_N struct def.
#[test]
fn struct_defs_deduplicated_by_size() {
    let context = LlzkContext::new();
    // Two blocks, both length 3
    let opcodes = vec![
        memory_init(0, &[2, 3, 4]),
        memory_init(1, &[5, 6, 7]),
        memory_read(0, 0, 10),
        memory_read(1, 1, 11),
        memory_write(0, 0, 12),
        memory_write(1, 1, 13),
    ];
    let circuit =
        make_circuit_with_opcodes(13, &[0, 1, 2, 3, 4, 5, 6, 7, 12, 13], &[], &[], opcodes);
    let module = translate_circuit_to_module(&context, circuit).unwrap();
    // Should have Circuit0, MemRead_3, MemWrite_3 — NOT two of each
    let ir = format!("{}", module.as_operation());

    // Count occurrences of struct.def @MemRead_3 and @MemWrite_3
    let read_count = ir.matches("struct.def @MemRead_3").count();
    let write_count = ir.matches("struct.def @MemWrite_3").count();
    assert_eq!(read_count, 1, "Expected exactly one MemRead_3 struct def");
    assert_eq!(write_count, 1, "Expected exactly one MemWrite_3 struct def");
    print_and_verify_module(&module, "struct_defs_deduplicated_by_size");
}

/// Read value feeds into subsequent `AssertZero` → value witness available
/// for constraint solving.
#[test]
fn read_value_feeds_assert_zero() {
    let context = LlzkContext::new();
    // block 0: init with w2, w3 (length 2)
    // read at w0 → w5 (solves w5)
    // AssertZero: w5 - w1 = 0 (constrains w5 == w1)
    let opcodes = vec![
        memory_init(0, &[2, 3]),
        memory_read(0, 0, 5),
        Opcode::AssertZero(Expression {
            mul_terms: vec![],
            linear_combinations: vec![
                (FieldElement::one(), Witness(5)),
                (-FieldElement::one(), Witness(1)),
            ],
            q_c: FieldElement::zero(),
        }),
    ];
    let circuit = make_circuit_with_opcodes(5, &[0, 1, 2, 3], &[], &[], opcodes);
    let module = translate_circuit_to_module(&context, circuit).unwrap();
    print_and_verify_module(&module, "read_value_feeds_assert_zero");
}

/// MemoryOp on uninitialized block → error.
#[test]
fn uninitialized_block_errors() {
    let context = LlzkContext::new();
    // No MemoryInit for block 0, but we try to read from it
    let opcodes = vec![memory_read(0, 0, 5)];
    let circuit = make_circuit_with_opcodes(5, &[0], &[], &[], opcodes);
    let result = translate_circuit_to_module(&context, circuit);
    assert!(
        matches!(
            result,
            Err(crate::Error::UninitializedMemoryBlock { block_id: 0, .. })
        ),
        "expected UninitializedMemoryBlock, got {result:?}"
    );
}
