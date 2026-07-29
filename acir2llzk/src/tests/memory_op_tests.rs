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

/// Expected IR-op counts for memory ops emitted by the selector-mux gadget
/// (see [`select.rs`]). Each access on a size-`N` block unrolls to `N`
/// constant-indexed array ops per phase plus, in `@constrain` only, `N`
/// nondet selectors and `2N + 1` soundness constraints (reads add `+1` more).
#[derive(Default)]
struct ExpectedCounts {
    array_write: usize,
    array_read: usize,
    constrain_eq: usize,
    nondet: usize,
}

impl ExpectedCounts {
    fn init(mut self, n: usize) -> Self {
        self.array_write += 2 * n;
        self
    }

    fn read(mut self, n: usize) -> Self {
        self.array_read += 2 * n;
        self.constrain_eq += 2 * n + 2;
        self.nondet += n;
        self
    }

    fn write(mut self, n: usize) -> Self {
        self.array_write += 2 * n;
        self.array_read += 2 * n;
        self.constrain_eq += 2 * n + 1;
        self.nondet += n;
        self
    }

    fn assert_matches(&self, ir: &str) {
        assert_eq!(
            count_occurrences(ir, "array.write"),
            self.array_write,
            "array.write count"
        );
        assert_eq!(
            count_occurrences(ir, "array.read"),
            self.array_read,
            "array.read count"
        );
        assert_eq!(
            count_occurrences(ir, "constrain.eq"),
            self.constrain_eq,
            "constrain.eq count"
        );
        assert_eq!(
            count_occurrences(ir, "llzk.nondet"),
            self.nondet,
            "llzk.nondet count"
        );
    }
}

fn translate_and_verify(
    opcodes: Vec<Opcode<FieldElement>>,
    witness_count: u32,
    inputs: &[u32],
) -> String {
    let context = LlzkContext::new();
    let circuit = make_circuit_with_opcodes(witness_count, inputs, &[], &[], opcodes);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();
    let module = wrap_struct_in_module(&context, struct_def);
    let ir = format!("{}", module.as_operation());
    assert!(module.as_operation().verify(), "module should verify");
    ir
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// MemoryInit + single read → constant-indexed mux over the 3 slots, plus
/// the selector witness/constraint gadget that pins `s_i = 1` iff `idx = i`.
///
/// block[0..3] = [w2, w3, w4]; read at index w0 → w5
#[test]
fn single_read_verifies() {
    let opcodes = vec![memory_init(0, &[2, 3, 4]), memory_read(0, 0, 5)];
    let ir = translate_and_verify(opcodes, 5, &[0, 2, 3, 4]);
    ExpectedCounts::default()
        .init(3)
        .read(3)
        .assert_matches(&ir);
}

/// Two reads from the same block both see the initial version.
///
/// block[0..3] = [w2, w3, w4]; read at w0 → w5; read at w1 → w6
#[test]
fn two_reads_same_block_verifies() {
    let opcodes = vec![
        memory_init(0, &[2, 3, 4]),
        memory_read(0, 0, 5),
        memory_read(0, 1, 6),
    ];
    let ir = translate_and_verify(opcodes, 6, &[0, 1, 2, 3, 4]);
    ExpectedCounts::default()
        .init(3)
        .read(3)
        .read(3)
        .assert_matches(&ir);
}

/// Write then read from the same block.
///
/// block[0..3] = [w3, w4, w5]; write arr[w0] = w1; read arr[w0] → w6
///
/// The read sees the post-write state in both compute and constrain.
#[test]
fn write_then_read_verifies() {
    let opcodes = vec![
        memory_init(0, &[3, 4, 5]),
        memory_write(0, 0, 1),
        memory_read(0, 0, 6),
    ];
    let ir = translate_and_verify(opcodes, 6, &[0, 1, 3, 4, 5]);
    ExpectedCounts::default()
        .init(3)
        .write(3)
        .read(3)
        .assert_matches(&ir);
}

/// A bare write still emits selector-soundness constraints (the gadget always
/// pins the witness index), but no `stored == result` equality.
///
/// block[0..2] = [w2, w3]; write arr[w0] = w1  — no reads.
#[test]
fn write_only_emits_selector_constraints() {
    let opcodes = vec![memory_init(0, &[2, 3]), memory_write(0, 0, 1)];
    let ir = translate_and_verify(opcodes, 3, &[0, 1, 2, 3]);
    ExpectedCounts::default()
        .init(2)
        .write(2)
        .assert_matches(&ir);
}

/// Multiple writes chain: v0 → v1 → v2; read from v2.
///
/// block[0..3] = [w4, w5, w6]; write arr[w0]=w1; write arr[w1]=w2; read arr[w0] → w7
#[test]
fn multiple_writes_then_read_verifies() {
    let opcodes = vec![
        memory_init(0, &[4, 5, 6]),
        memory_write(0, 0, 1),
        memory_write(0, 1, 2),
        memory_read(0, 0, 7),
    ];
    let ir = translate_and_verify(opcodes, 7, &[0, 1, 2, 4, 5, 6]);
    ExpectedCounts::default()
        .init(3)
        .write(3)
        .write(3)
        .read(3)
        .assert_matches(&ir);
}

/// Two separate memory blocks, one read each.
///
/// block0[0..2]=[w2,w3]; block1[0..2]=[w4,w5]; read block0[w0]→w6; read block1[w1]→w7
#[test]
fn two_blocks_independent_reads_verifies() {
    let opcodes = vec![
        memory_init(0, &[2, 3]),
        memory_init(1, &[4, 5]),
        memory_read(0, 0, 6),
        memory_read(1, 1, 7),
    ];
    let ir = translate_and_verify(opcodes, 7, &[0, 1, 2, 3, 4, 5]);
    ExpectedCounts::default()
        .init(2)
        .init(2)
        .read(2)
        .read(2)
        .assert_matches(&ir);
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
    let opcodes = vec![
        memory_init(0, &[4, 5]),
        memory_init(1, &[6, 7]),
        memory_write(0, 0, 1),
        memory_read(1, 1, 8),
        memory_write(1, 0, 2),
        memory_read(0, 0, 9),
    ];
    let ir = translate_and_verify(opcodes, 9, &[0, 1, 2, 4, 5, 6, 7]);
    ExpectedCounts::default()
        .init(2)
        .init(2)
        .write(2)
        .read(2)
        .write(2)
        .read(2)
        .assert_matches(&ir);
}

/// Sanity check the gadget structure: a single read over an N=4 block must
/// produce N=4 `llzk.nondet` selectors and 2N=8 constant-indexed `array.read`s.
/// This pins the field-native soundness gadget against accidental regressions
/// to a dynamic-index `array.read`.
#[test]
fn read_gadget_uses_constant_indexed_array_reads() {
    let opcodes = vec![memory_init(0, &[2, 3, 4, 5]), memory_read(0, 0, 6)];
    let ir = translate_and_verify(opcodes, 6, &[0, 2, 3, 4, 5]);

    // 4 selector witnesses (only in @constrain).
    assert_eq!(count_occurrences(&ir, "llzk.nondet"), 4);
    // No dynamic-index access survives: every array.read uses an arith.constant
    // index (`%c0..%c3`), never a felt-cast.
    assert_eq!(count_occurrences(&ir, "cast.toindex"), 0);
}
