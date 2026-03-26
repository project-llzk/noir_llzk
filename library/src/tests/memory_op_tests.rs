use acir::{
    AcirField, FieldElement,
    circuit::Opcode,
    circuit::opcodes::{BlockId, BlockType, MemOp},
    native_types::{Expression, Witness},
};
use llzk::prelude::{LlzkContext, OperationLike};

use crate::tests::count_occurrences;

use super::{make_circuit_with_opcodes, translate_single_circuit, wrap_struct_in_module};

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Single-witness expression `1 * w + 0`.
fn wexpr(w: u32) -> Expression<FieldElement> {
    Expression {
        mul_terms: vec![],
        linear_combinations: vec![(FieldElement::one(), Witness(w))],
        q_c: FieldElement::zero(),
    }
}

fn memory_init(block_id: u32, init: &[u32]) -> Opcode<FieldElement> {
    Opcode::MemoryInit {
        block_id: BlockId(block_id),
        init: init.iter().map(|&w| Witness(w)).collect(),
        block_type: BlockType::Memory,
    }
}

fn memory_read(block_id: u32, index_witness: u32, value_witness: u32) -> Opcode<FieldElement> {
    Opcode::MemoryOp {
        block_id: BlockId(block_id),
        op: MemOp::read_at_mem_index(wexpr(index_witness), Witness(value_witness)),
    }
}

fn memory_write(block_id: u32, index_witness: u32, value_witness: u32) -> Opcode<FieldElement> {
    Opcode::MemoryOp {
        block_id: BlockId(block_id),
        op: MemOp::write_to_mem_index(wexpr(index_witness), wexpr(value_witness)),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// MemoryInit + single read → value witness solved in compute, one `constrain.eq` in constrain.
///
/// block[0..3] = [w2, w3, w4]; read at index w0 → w5
#[test]
fn single_read_verifies() {
    let context = LlzkContext::new();
    let opcodes = vec![memory_init(0, &[2, 3, 4]), memory_read(0, 0, 5)];
    // w0: private index input; w2,w3,w4: private array inputs; w5: solved by read
    let circuit = make_circuit_with_opcodes(5, &[0, 2, 3, 4], &[], &[], opcodes);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();
    let module = wrap_struct_in_module(&context, struct_def);
    let ir = format!("{}", module.as_operation());

    // Init(3): 3 writes in compute + 3 in constrain = 6
    assert_eq!(
        count_occurrences(&ir, "array.write"),
        6,
        "expected 6 array.write ops (3 init × 2)"
    );
    // Read(1): 1 read in compute + 1 in constrain = 2
    assert_eq!(
        count_occurrences(&ir, "array.read"),
        2,
        "expected 2 array.read ops (1 read × 2)"
    );
    // Read emits 1 constrain.eq in constrain
    assert_eq!(
        count_occurrences(&ir, "constrain.eq"),
        1,
        "expected 1 constrain.eq from the read"
    );

    assert!(module.as_operation().verify(), "module should verify");
}

/// Two reads from the same block both see the initial version.
///
/// block[0..3] = [w2, w3, w4]; read at w0 → w5; read at w1 → w6
#[test]
fn two_reads_same_block_verifies() {
    let context = LlzkContext::new();
    let opcodes = vec![
        memory_init(0, &[2, 3, 4]),
        memory_read(0, 0, 5),
        memory_read(0, 1, 6),
    ];
    let circuit = make_circuit_with_opcodes(6, &[0, 1, 2, 3, 4], &[], &[], opcodes);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();
    let module = wrap_struct_in_module(&context, struct_def);
    let ir = format!("{}", module.as_operation());

    println!("two_reads_same_block:\n{ir}");

    // Init(3): 6 writes
    assert_eq!(
        count_occurrences(&ir, "array.write"),
        6,
        "expected 6 array.write ops (3 init × 2)"
    );
    // Read(2): 4 reads
    assert_eq!(
        count_occurrences(&ir, "array.read"),
        4,
        "expected 4 array.read ops (2 reads × 2)"
    );
    // 2 reads → 2 constrain.eq
    assert_eq!(
        count_occurrences(&ir, "constrain.eq"),
        2,
        "expected 2 constrain.eq from 2 reads"
    );

    assert!(module.as_operation().verify(), "module should verify");
}

/// Write then read from the same block.
///
/// block[0..3] = [w3, w4, w5]; write arr[w0] = w1; read arr[w0] → w6
///
/// The read sees the post-write state in both compute and constrain.
#[test]
fn write_then_read_verifies() {
    let context = LlzkContext::new();
    let opcodes = vec![
        memory_init(0, &[3, 4, 5]),
        memory_write(0, 0, 1),
        memory_read(0, 0, 6),
    ];
    // w0,w1: index/value inputs; w3,w4,w5: array inputs; w6: solved by read
    let circuit = make_circuit_with_opcodes(6, &[0, 1, 3, 4, 5], &[], &[], opcodes);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();
    let module = wrap_struct_in_module(&context, struct_def);
    let ir = format!("{}", module.as_operation());

    println!("write_then_read:\n{ir}");

    // Init(3) + Write(1): (3+1) × 2 = 8 writes
    assert_eq!(
        count_occurrences(&ir, "array.write"),
        8,
        "expected 8 array.write ops (3 init + 1 write) × 2"
    );
    // Read(1): 2 reads
    assert_eq!(
        count_occurrences(&ir, "array.read"),
        2,
        "expected 2 array.read ops (1 read × 2)"
    );
    // Only the read emits a constraint; writes are constraint-free.
    assert_eq!(
        count_occurrences(&ir, "constrain.eq"),
        1,
        "expected 1 constrain.eq from the read"
    );

    assert!(module.as_operation().verify(), "module should verify");
}

/// Writes emit no constraints themselves.
///
/// block[0..2] = [w2, w3]; write arr[w0] = w1  — no reads.
#[test]
fn write_only_no_constrain_eq() {
    let context = LlzkContext::new();
    let opcodes = vec![memory_init(0, &[2, 3]), memory_write(0, 0, 1)];
    let circuit = make_circuit_with_opcodes(3, &[0, 1, 2, 3], &[], &[], opcodes);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();
    let module = wrap_struct_in_module(&context, struct_def);
    let ir = format!("{}", module.as_operation());

    println!("write_only:\n{ir}");

    // Init(2) + Write(1): (2+1) × 2 = 6 writes
    assert_eq!(
        count_occurrences(&ir, "array.write"),
        6,
        "expected 6 array.write ops (2 init + 1 write) × 2"
    );
    // No reads
    assert_eq!(
        count_occurrences(&ir, "array.read"),
        0,
        "expected 0 array.read ops"
    );
    // No constraints
    assert_eq!(
        count_occurrences(&ir, "constrain.eq"),
        0,
        "expected 0 constrain.eq ops"
    );

    assert!(module.as_operation().verify(), "module should verify");
}

/// Multiple writes chain: v0 → v1 → v2; read from v2.
///
/// block[0..3] = [w4, w5, w6]; write arr[w0]=w1; write arr[w1]=w2; read arr[w0] → w7
#[test]
fn multiple_writes_then_read_verifies() {
    let context = LlzkContext::new();
    let opcodes = vec![
        memory_init(0, &[4, 5, 6]),
        memory_write(0, 0, 1),
        memory_write(0, 1, 2),
        memory_read(0, 0, 7),
    ];
    let circuit = make_circuit_with_opcodes(7, &[0, 1, 2, 4, 5, 6], &[], &[], opcodes);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();
    let module = wrap_struct_in_module(&context, struct_def);
    let ir = format!("{}", module.as_operation());

    println!("multiple_writes_then_read:\n{ir}");

    // Init(3) + Write(2): (3+2) × 2 = 10 writes
    assert_eq!(
        count_occurrences(&ir, "array.write"),
        10,
        "expected 10 array.write ops (3 init + 2 writes) × 2"
    );
    // Read(1): 2 reads
    assert_eq!(
        count_occurrences(&ir, "array.read"),
        2,
        "expected 2 array.read ops (1 read × 2)"
    );
    // 1 read → 1 constrain.eq
    assert_eq!(
        count_occurrences(&ir, "constrain.eq"),
        1,
        "expected 1 constrain.eq from the read"
    );

    assert!(module.as_operation().verify(), "module should verify");
}

/// Two separate memory blocks, one read each.
///
/// block0[0..2]=[w2,w3]; block1[0..2]=[w4,w5]; read block0[w0]→w6; read block1[w1]→w7
#[test]
fn two_blocks_independent_reads_verifies() {
    let context = LlzkContext::new();
    let opcodes = vec![
        memory_init(0, &[2, 3]),
        memory_init(1, &[4, 5]),
        memory_read(0, 0, 6),
        memory_read(1, 1, 7),
    ];
    let circuit = make_circuit_with_opcodes(7, &[0, 1, 2, 3, 4, 5], &[], &[], opcodes);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();
    let module = wrap_struct_in_module(&context, struct_def);
    let ir = format!("{}", module.as_operation());

    println!("two_blocks_independent_reads:\n{ir}");

    // Init(2) + Init(2): (2+2) × 2 = 8 writes
    assert_eq!(
        count_occurrences(&ir, "array.write"),
        8,
        "expected 8 array.write ops (2+2 init) × 2"
    );
    // Read(2): 4 reads
    assert_eq!(
        count_occurrences(&ir, "array.read"),
        4,
        "expected 4 array.read ops (2 reads × 2)"
    );
    // 2 reads → 2 constrain.eq
    assert_eq!(
        count_occurrences(&ir, "constrain.eq"),
        2,
        "expected 2 constrain.eq from 2 reads"
    );

    assert!(module.as_operation().verify(), "module should verify");
}

/// MemoryOp on a block that was never initialised → `UnsupportedOpcode` error.
#[test]
fn memory_op_before_init_is_error() {
    let context = LlzkContext::new();
    let opcodes = vec![memory_read(0, 0, 1)]; // no MemoryInit for block 0
    let circuit = make_circuit_with_opcodes(1, &[0], &[], &[], opcodes);
    let result = translate_single_circuit(&context, circuit);
    assert!(
        matches!(result, Err(crate::Error::UnsupportedOpcode(_))),
        "expected UnsupportedOpcode, got {result:?}"
    );
}

/// Interleaved reads and writes across two blocks.
///
/// block0[0..2]=[w4,w5]; block1[0..2]=[w6,w7]
/// write block0[w0]=w1; read block1[w1]→w8; write block1[w0]=w2; read block0[w0]→w9
#[test]
fn interleaved_two_blocks_verifies() {
    let context = LlzkContext::new();
    let opcodes = vec![
        memory_init(0, &[4, 5]),
        memory_init(1, &[6, 7]),
        memory_write(0, 0, 1),
        memory_read(1, 1, 8),
        memory_write(1, 0, 2),
        memory_read(0, 0, 9),
    ];
    let circuit = make_circuit_with_opcodes(9, &[0, 1, 2, 4, 5, 6, 7], &[], &[], opcodes);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();
    let module = wrap_struct_in_module(&context, struct_def);
    let ir = format!("{}", module.as_operation());

    println!("interleaved_two_blocks:\n{ir}");

    // Init(2+2) + Write(2): (2+2+2) × 2 = 12 writes
    assert_eq!(
        count_occurrences(&ir, "array.write"),
        12,
        "expected 12 array.write ops (2+2 init + 2 writes) × 2"
    );
    // Read(2): 4 reads
    assert_eq!(
        count_occurrences(&ir, "array.read"),
        4,
        "expected 4 array.read ops (2 reads × 2)"
    );
    // 2 reads → 2 constrain.eq
    assert_eq!(
        count_occurrences(&ir, "constrain.eq"),
        2,
        "expected 2 constrain.eq from 2 reads"
    );

    assert!(module.as_operation().verify(), "module should verify");
}
