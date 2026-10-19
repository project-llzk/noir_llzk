//! Forged-witness soundness tests for core opcodes (AssertZero, RANGE, memory).
//!
//! The existing forged-witness coverage (`assert_constrain_rejects_corrupted_witness`)
//! is applied only to blackbox hashes, ciphers and curve-add. The core
//! soundness-critical opcodes had no equivalent test. Each test here builds a
//! valid circuit, confirms the honest witness is accepted (and matches the ACVM
//! reference via `run_e2e`), then corrupts a constrained witness and asserts
//! that `@constrain` rejects it. Acceptance of a corrupted witness would mean
//! the circuit is under-constrained.

use crate::tests::e2e::{
    assert_constrain_accepts, assert_constrain_rejects_corrupted_witness,
    assert_constrain_rejects_input, assert_witness_eq, felt_u64, run_e2e,
};
use crate::tests::{make_circuit_with_opcodes, mul_constraint, range_blackbox};
use acir::circuit::opcodes::{BlockId, BlockType, MemOp};
use acir::native_types::{Expression, Witness};
use acir::{AcirField, FieldElement};

/// AssertZero multiplication gate: `w2 = w0 * w1`.
/// Corrupting the constrained output `w2` must be rejected by `@constrain`.
#[test]
fn assert_zero_mul_gate_rejects_corrupted_output() {
    // highest witness index is 2, so current_witness_index = 2.
    let circuit = make_circuit_with_opcodes(
        2,
        &[0, 1], // private inputs w0, w1
        &[],     // no public inputs
        &[2],    // return w2
        vec![mul_constraint(0, 1, 2)],
    );

    // Honest witness: 3 * 4 = 12, accepted and matches the ACVM reference.
    let computed = run_e2e(circuit.clone(), &[felt_u64(3), felt_u64(4)]);
    assert_witness_eq(&computed.members, "w2", "12");

    // Forge the output: @constrain must reject (w2 no longer equals w0*w1).
    assert_constrain_rejects_corrupted_witness(circuit, &[felt_u64(3), felt_u64(4)], "w2");
}

/// RANGE: constrain `w0 < 2^8`. An out-of-range witness must be rejected.
/// (Experimental probe: observes whether a pure range-checked witness corruption
/// is caught, and what error the interpreter reports.)
#[test]
fn range_rejects_out_of_range_witness() {
    let circuit = make_circuit_with_opcodes(0, &[0], &[], &[0], vec![range_blackbox(0, 8)]);
    // honest: 100 < 256, accepted (bare RANGE has no internal witness, so skip
    // the ACVM differential and just assert @constrain accepts).
    assert_constrain_accepts(circuit.clone(), &[felt_u64(100)]);
    // out-of-range INPUT: 256 = 2^8 (@constrain reads range inputs, not the
    // computed struct), must be rejected. The range bit-check surfaces as a
    // `felt(0) != felt(1)` violation.
    assert_constrain_rejects_input(circuit, &[felt_u64(256)], "!=");
}

// Memory opcode tests.

fn wexpr(w: u32) -> Expression<FieldElement> {
    Expression {
        mul_terms: vec![],
        linear_combinations: vec![(FieldElement::one(), Witness(w))],
        q_c: FieldElement::zero(),
    }
}
fn mem_init(block: u32, init: &[u32]) -> acir::circuit::Opcode<FieldElement> {
    acir::circuit::Opcode::MemoryInit {
        block_id: BlockId(block),
        init: init.iter().map(|&w| Witness(w)).collect(),
        block_type: BlockType::Memory,
    }
}
fn mem_read(block: u32, index_w: u32, value_w: u32) -> acir::circuit::Opcode<FieldElement> {
    acir::circuit::Opcode::MemoryOp {
        block_id: BlockId(block),
        op: MemOp::read_at_mem_index(wexpr(index_w), Witness(value_w)),
    }
}
fn mem_write(block: u32, index_w: u32, value_w: u32) -> acir::circuit::Opcode<FieldElement> {
    acir::circuit::Opcode::MemoryOp {
        block_id: BlockId(block),
        op: MemOp::write_to_mem_index(wexpr(index_w), wexpr(value_w)),
    }
}

/// Memory read soundness: read `mem[0]` into `w3`, then corrupt `w3` and assert
/// `@constrain` rejects it (the read-soundness constraint pins `w3 == mem[0]`).
/// Memory reads consume a nondet one-hot selector for the index, so both phases
/// are given the selector `[1,0]` (index 0 of a size-2 block).
#[test]
fn memory_read_rejects_corrupted_value() {
    use crate::tests::e2e::{assert_constrain_rejects_with_nondet, run_e2e_with_phase_nondets};
    use llzk_interpreter::Felt;

    // w0,w1 = init values; w2 = index; w3 = read value (output)
    let circuit = make_circuit_with_opcodes(
        3,
        &[0, 1, 2],
        &[],
        &[3],
        vec![mem_init(0, &[0, 1]), mem_read(0, 2, 3)],
    );
    let inputs = [felt_u64(42), felt_u64(99), felt_u64(0)];
    let selector = [Felt::from_u64(1), Felt::from_u64(0)]; // one-hot index 0

    // Honest: read index 0 -> init[0] = 42, accepted.
    let computed = run_e2e_with_phase_nondets(circuit.clone(), &inputs, &[], &selector);
    assert_witness_eq(&computed.members, "w3", "42");

    // Forge the read-out value: @constrain must reject (w3 no longer equals mem[0]).
    assert_constrain_rejects_with_nondet(
        circuit,
        &inputs,
        "w3",
        felt_u64(0xdead),
        "!=",
        &[],
        &selector,
    );
}

/// More indices: read `mem[1]` of a size-2 block (selector one-hot [0,1]).
#[test]
fn memory_read_index1_rejects_corrupted_value() {
    use crate::tests::e2e::{assert_constrain_rejects_with_nondet, run_e2e_with_phase_nondets};
    use llzk_interpreter::Felt;

    let circuit = make_circuit_with_opcodes(
        3,
        &[0, 1, 2],
        &[],
        &[3],
        vec![mem_init(0, &[0, 1]), mem_read(0, 2, 3)],
    );
    let inputs = [felt_u64(42), felt_u64(99), felt_u64(1)]; // index = 1
    let selector = [Felt::from_u64(0), Felt::from_u64(1)]; // one-hot index 1

    let computed = run_e2e_with_phase_nondets(circuit.clone(), &inputs, &[], &selector);
    assert_witness_eq(&computed.members, "w3", "99"); // mem[1] = 99
    assert_constrain_rejects_with_nondet(
        circuit,
        &inputs,
        "w3",
        felt_u64(0xdead),
        "!=",
        &[],
        &selector,
    );
}

/// Memory WRITE soundness: write a new value to index 1, read it back, and
/// assert the read reflects the write; corrupting the read-out must be rejected.
#[test]
fn memory_write_then_read_rejects_corrupted_value() {
    use crate::tests::e2e::{assert_constrain_rejects_with_nondet, run_e2e_with_phase_nondets};
    use llzk_interpreter::Felt;

    // w0,w1 init; w2 = value to write; w3 = write index; w4 = read index; w5 = read out
    let circuit = make_circuit_with_opcodes(
        5,
        &[0, 1, 2, 3, 4],
        &[],
        &[5],
        vec![mem_init(0, &[0, 1]), mem_write(0, 3, 2), mem_read(0, 4, 5)],
    );
    // write 77 to index 1, then read index 1 -> 77 (overwrote init[1]=99)
    let inputs = [
        felt_u64(42),
        felt_u64(99),
        felt_u64(77),
        felt_u64(1),
        felt_u64(1),
    ];
    // constrain nondet: write selector (idx 1) then read selector (idx 1)
    let selector = [
        Felt::from_u64(0),
        Felt::from_u64(1),
        Felt::from_u64(0),
        Felt::from_u64(1),
    ];

    let computed = run_e2e_with_phase_nondets(circuit.clone(), &inputs, &[], &selector);
    assert_witness_eq(&computed.members, "w5", "77");
    assert_constrain_rejects_with_nondet(
        circuit,
        &inputs,
        "w5",
        felt_u64(0xdead),
        "!=",
        &[],
        &selector,
    );
}

/// Dishonest selector on a read: index 0, but the nondet one-hot points at
/// slot 1 and the read-out carries slot 1's value. `w3 == Σ s_i * mem[i]`
/// holds, so only the match constraint `s_i * (idx - i) == 0` can reject.
#[test]
fn memory_read_rejects_dishonest_selector() {
    use crate::tests::e2e::assert_constrain_rejects_with_nondet;
    use llzk_interpreter::Felt;

    let circuit = make_circuit_with_opcodes(
        3,
        &[0, 1, 2],
        &[],
        &[3],
        vec![mem_init(0, &[0, 1]), mem_read(0, 2, 3)],
    );
    let inputs = [felt_u64(42), felt_u64(99), felt_u64(0)]; // index 0
    let dishonest = [Felt::from_u64(0), Felt::from_u64(1)]; // points at slot 1

    assert_constrain_rejects_with_nondet(
        circuit,
        &inputs,
        "w3",
        felt_u64(99), // mem[1], consistent with the dishonest selector
        "!=",
        &[],
        &dishonest,
    );
}

/// All-zero selector on a read: every match constraint holds trivially and a
/// read-out of 0 equals `Σ 0 * mem[i]`, so only `Σ s_i == 1` can reject.
#[test]
fn memory_read_rejects_zero_selector() {
    use crate::tests::e2e::assert_constrain_rejects_with_nondet;
    use llzk_interpreter::Felt;

    let circuit = make_circuit_with_opcodes(
        3,
        &[0, 1, 2],
        &[],
        &[3],
        vec![mem_init(0, &[0, 1]), mem_read(0, 2, 3)],
    );
    let inputs = [felt_u64(42), felt_u64(99), felt_u64(0)];
    let zero = [Felt::from_u64(0), Felt::from_u64(0)];

    assert_constrain_rejects_with_nondet(circuit, &inputs, "w3", felt_u64(0), "!=", &[], &zero);
}

/// Dishonest selector on a write: write 77 at index 1 with a write selector
/// pointing at slot 0, then an honest read of index 0 returns 77. The read side
/// is fully consistent, so only the write selector's match constraint can reject.
#[test]
fn memory_write_rejects_dishonest_selector() {
    use crate::tests::e2e::assert_constrain_rejects_with_nondet;
    use llzk_interpreter::Felt;

    // w0,w1 init; w2 = value to write; w3 = write index; w4 = read index; w5 = read out
    let circuit = make_circuit_with_opcodes(
        5,
        &[0, 1, 2, 3, 4],
        &[],
        &[5],
        vec![mem_init(0, &[0, 1]), mem_write(0, 3, 2), mem_read(0, 4, 5)],
    );
    let inputs = [
        felt_u64(42),
        felt_u64(99),
        felt_u64(77),
        felt_u64(1), // write index
        felt_u64(0), // read index
    ];
    // constrain nondet: dishonest write selector (slot 0 for index 1), honest read selector (index 0)
    let selector = [
        Felt::from_u64(1),
        Felt::from_u64(0),
        Felt::from_u64(1),
        Felt::from_u64(0),
    ];

    assert_constrain_rejects_with_nondet(
        circuit,
        &inputs,
        "w5",
        felt_u64(77),
        "!=",
        &[],
        &selector,
    );
}
