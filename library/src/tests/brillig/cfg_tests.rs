//! Unit tests for the Brillig CFG recovery ([`crate::opcodes::brillig::cfg`]).

use acir::FieldElement;
use acir::brillig::{HeapVector, Label, MemoryAddress, Opcode as BrilligOpcode};

use crate::Error;
use crate::opcodes::brillig::cfg::{BlockId, Cfg, Terminator};

use super::{brillig_stop, mov};

// ── Fixture constructors ────────────────────────────────────────────────

fn jump(location: Label) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Jump { location }
}

fn jump_if(location: Label) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::JumpIf {
        condition: MemoryAddress::Direct(0),
        location,
    }
}

fn call(location: Label) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Call { location }
}

fn ret() -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Return
}

fn trap() -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Trap {
        revert_data: HeapVector {
            pointer: MemoryAddress::Direct(0),
            size: MemoryAddress::Direct(0),
        },
    }
}

/// Placeholder non-terminator body opcode.
fn body() -> BrilligOpcode<FieldElement> {
    mov(0, 0)
}

fn unsupported_reason(err: Error) -> String {
    match err {
        Error::UnsupportedBrillig { reason } => reason,
        other => panic!("expected UnsupportedBrillig, got {other:?}"),
    }
}

/// Minimal procedure-using fixture:
///   0: Call 2            (main: call site)
///   1: Stop              (main: continuation / exit)
///   2: body              (procedure entry)
///   3: Return
fn procedure_bytecode() -> Vec<BrilligOpcode<FieldElement>> {
    vec![call(2), brillig_stop(), body(), ret()]
}

// ── Block splitter + terminator classification ─────────────────────────

#[test]
fn cfg_build_single_stop() {
    let cfg = Cfg::build(&[brillig_stop()]).unwrap();
    assert_eq!(cfg.blocks.len(), 1);
    assert!(matches!(cfg.blocks[0].terminator, Terminator::Stop));
    assert_eq!(cfg.successors[0], vec![]);
    assert_eq!(cfg.predecessors[0], vec![]);
}

#[test]
fn cfg_build_jump_produces_two_blocks_one_edge() {
    // 0: Jump 1
    // 1: Stop
    let cfg = Cfg::build(&[jump(1), brillig_stop()]).unwrap();
    assert_eq!(cfg.blocks.len(), 2);
    assert!(matches!(cfg.blocks[0].terminator, Terminator::Jump(b) if b == BlockId(1)));
    assert!(matches!(cfg.blocks[1].terminator, Terminator::Stop));
    assert_eq!(cfg.successors[0], vec![BlockId(1)]);
    assert_eq!(cfg.successors[1], vec![]);
    assert_eq!(cfg.predecessors[1], vec![BlockId(0)]);
}

#[test]
fn cfg_build_return_terminator_has_no_successors() {
    let cfg = Cfg::build(&[ret()]).unwrap();
    assert!(matches!(cfg.blocks[0].terminator, Terminator::Return));
    assert_eq!(cfg.successors[0], vec![]);
}

#[test]
fn cfg_build_trap_terminator_has_no_successors() {
    let cfg = Cfg::build(&[trap()]).unwrap();
    assert!(matches!(cfg.blocks[0].terminator, Terminator::Trap));
    assert_eq!(cfg.successors[0], vec![]);
}

/// Idiomatic Noir diamond:
///   0: JumpIf cond, 4       <then>
///   1: Jump 2                <else>
///   2: body                  (else body)
///   3: Jump 6
///   4: body                  (then body)
///   5: Jump 6
///   6: Stop                  (join)
///
/// Produces 5 blocks (0, 1, 2, 4, 6 are the starts):
///   b0 = JumpIf(then=b3, else=b1)
///   b1 = Jump b2
///   b2 = Jump b4
///   b3 = Jump b4
///   b4 = Stop
fn diamond_bytecode() -> Vec<BrilligOpcode<FieldElement>> {
    vec![
        jump_if(4),
        jump(2),
        body(),
        jump(6),
        body(),
        jump(6),
        brillig_stop(),
    ]
}

#[test]
fn cfg_build_diamond_has_five_blocks_with_correct_edges() {
    let cfg = Cfg::build(&diamond_bytecode()).unwrap();
    assert_eq!(cfg.blocks.len(), 5);

    let Terminator::JumpIf {
        then_block,
        else_block,
        ..
    } = cfg.blocks[0].terminator
    else {
        panic!("expected JumpIf");
    };
    assert_eq!(then_block, BlockId(3));
    assert_eq!(else_block, BlockId(1));

    assert_eq!(cfg.successors[0], vec![BlockId(3), BlockId(1)]);
    assert_eq!(cfg.successors[1], vec![BlockId(2)]);
    assert_eq!(cfg.successors[2], vec![BlockId(4)]);
    assert_eq!(cfg.successors[3], vec![BlockId(4)]);
    assert_eq!(cfg.successors[4], vec![]);
    assert_eq!(cfg.predecessors[4], vec![BlockId(2), BlockId(3)]);
}

// ── Rejection paths ─────────────────────────────────────────────────────

#[test]
fn cfg_build_rejects_empty_bytecode() {
    let err = Cfg::build(&[]).unwrap_err();
    assert!(unsupported_reason(err).contains("empty"));
}

#[test]
fn cfg_build_rejects_out_of_range_jump_target() {
    let err = Cfg::build(&[jump(99), brillig_stop()]).unwrap_err();
    assert!(unsupported_reason(err).contains("out-of-range"));
}

#[test]
fn cfg_build_rejects_block_without_terminator() {
    // Body opcode as the last instruction — block can't be terminated.
    let err = Cfg::build(&[body()]).unwrap_err();
    assert!(unsupported_reason(err).contains("non-terminator"));
}

// ── Dominators ──────────────────────────────────────────────────────────

#[test]
fn dominator_linear_chain() {
    // 0 → 1 → 2 (via Jumps), terminated at 2 by Stop.
    let cfg = Cfg::build(&[jump(1), jump(2), brillig_stop()]).unwrap();
    assert_eq!(cfg.dominators.idom(BlockId(0)), None);
    assert_eq!(cfg.dominators.idom(BlockId(1)), Some(BlockId(0)));
    assert_eq!(cfg.dominators.idom(BlockId(2)), Some(BlockId(1)));
}

#[test]
fn dominator_diamond_join_is_dominated_by_branch() {
    let cfg = Cfg::build(&diamond_bytecode()).unwrap();
    // Join block (idx 4) is dominated by the branch block (idx 0), not by
    // either arm — both arms' common ancestor is the branch.
    assert_eq!(cfg.dominators.idom(BlockId(4)), Some(BlockId(0)));
    assert!(cfg.dominators.dominates(BlockId(0), BlockId(4)));
    assert!(!cfg.dominators.dominates(BlockId(2), BlockId(4)));
    assert!(!cfg.dominators.dominates(BlockId(3), BlockId(4)));
}

#[test]
fn dominator_dominates_is_reflexive() {
    let cfg = Cfg::build(&[brillig_stop()]).unwrap();
    assert!(cfg.dominators.dominates(BlockId(0), BlockId(0)));
}

// ── Post-dominators ─────────────────────────────────────────────────────

#[test]
fn post_dominator_linear_chain() {
    // 0 → 1 → 2. Every predecessor is post-dominated by the exit 2.
    let cfg = Cfg::build(&[jump(1), jump(2), brillig_stop()]).unwrap();
    assert_eq!(cfg.post_dominators.idom(BlockId(2)), None);
    assert_eq!(cfg.post_dominators.idom(BlockId(1)), Some(BlockId(2)));
    assert_eq!(cfg.post_dominators.idom(BlockId(0)), Some(BlockId(1)));
}

#[test]
fn post_dominator_diamond_finds_join() {
    let cfg = Cfg::build(&diamond_bytecode()).unwrap();
    // The branch block's post-dominator is the join — this is what the
    // structurer consults to locate an `scf.if`'s fan-in point.
    assert_eq!(cfg.post_dominators.idom(BlockId(0)), Some(BlockId(4)));
    assert_eq!(cfg.post_dominators.idom(BlockId(4)), None);
}

// ── Natural loops ──────────────────────────────────────────────────────

#[test]
fn no_natural_loops_in_acyclic_cfg() {
    let cfg = Cfg::build(&diamond_bytecode()).unwrap();
    assert!(cfg.loops.is_empty());
}

/// Single-exit while loop:
///   0: JumpIf cond, 2
///   1: Jump 4             (exit arm)
///   2: body
///   3: Jump 0             (back-edge to header)
///   4: Stop
fn simple_loop_bytecode() -> Vec<BrilligOpcode<FieldElement>> {
    vec![jump_if(2), jump(4), body(), jump(0), brillig_stop()]
}

#[test]
fn natural_loop_detected() {
    let cfg = Cfg::build(&simple_loop_bytecode()).unwrap();
    assert_eq!(cfg.loops.len(), 1);
    let l = &cfg.loops[0];
    assert_eq!(l.header, BlockId(0));
    // Body reached from the back-edge source back to the header.
    assert!(l.body.contains(&BlockId(0)));
    assert!(l.body.contains(&BlockId(2)));
    // Exit arm (block 1) and Stop block (3) are outside the loop body.
    assert!(!l.body.contains(&BlockId(1)));
    assert!(!l.body.contains(&BlockId(3)));
}

/// Nested loops — outer header at 0, inner header at 2, inner body at 4.
///   0: JumpIf cond, 2        (outer header: enter body)
///   1: Jump 8                (outer exit)
///   2: JumpIf cond, 4        (inner header: enter body)
///   3: Jump 6                (inner exit → back to outer)
///   4: body
///   5: Jump 2                (inner back-edge)
///   6: body
///   7: Jump 0                (outer back-edge)
///   8: Stop
fn nested_loop_bytecode() -> Vec<BrilligOpcode<FieldElement>> {
    vec![
        jump_if(2),
        jump(8),
        jump_if(4),
        jump(6),
        body(),
        jump(2),
        body(),
        jump(0),
        brillig_stop(),
    ]
}

#[test]
fn nested_natural_loops_detected() {
    let cfg = Cfg::build(&nested_loop_bytecode()).unwrap();
    assert_eq!(cfg.loops.len(), 2);
    let headers: Vec<BlockId> = cfg.loops.iter().map(|l| l.header).collect();
    assert!(headers.contains(&BlockId(0)));
    assert!(headers.contains(&BlockId(2)));
    // Outer loop's body must contain inner loop's blocks.
    let outer = cfg.loops.iter().find(|l| l.header == BlockId(0)).unwrap();
    let inner = cfg.loops.iter().find(|l| l.header == BlockId(2)).unwrap();
    for id in &inner.body {
        assert!(
            outer.body.contains(id),
            "inner-loop block {id:?} must be part of outer loop"
        );
    }
}

// ── Call / Return / procedures ──────────────────────────────────────────

#[test]
fn cfg_build_call_classifies_terminator_with_target_and_continuation() {
    let cfg = Cfg::build(&procedure_bytecode()).unwrap();
    let Terminator::Call {
        target,
        continuation,
    } = cfg.blocks[0].terminator
    else {
        panic!("expected Call terminator");
    };
    // Procedure entry (index 2) is BlockId(2); continuation (index 1) is BlockId(1).
    assert_eq!(target, BlockId(2));
    assert_eq!(continuation, BlockId(1));
    assert_eq!(cfg.successors[0], vec![BlockId(2), BlockId(1)]);
}

#[test]
fn procedure_identified_with_single_return() {
    let cfg = Cfg::build(&procedure_bytecode()).unwrap();
    assert_eq!(cfg.procedures.len(), 1);
    let proc = &cfg.procedures[0];
    assert_eq!(proc.entry, BlockId(2));
    assert_eq!(proc.return_block, Some(BlockId(2)));
    assert_eq!(proc.body.len(), 1);
    assert!(proc.body.contains(&BlockId(2)));
}

// The following tests hand-craft bytecode that violates invariants
// Noir's emitter preserves (Call as last opcode is never emitted;
// `compile_procedure` emits exactly one Return). Any `Return`-count
// other than one is rejected as unsupported.

#[test]
fn procedure_with_multiple_returns_is_rejected() {
    //   0: Call 2                 (main)
    //   1: Stop                    (main exit)
    //   2: JumpIf cond, 4          (procedure header, forks)
    //   3: Jump 5                  (else arm)
    //   4: Return                  (then arm)
    //   5: Return                  (else arm)
    let err = Cfg::build(&[call(2), brillig_stop(), jump_if(4), jump(5), ret(), ret()])
        .expect_err("procedure with multiple returns should be rejected");
    let reason = unsupported_reason(err);
    assert!(
        reason.contains("procedure at block 2") && reason.contains("found 2"),
        "expected multi-exit rejection, got: {reason}"
    );
}

#[test]
fn procedure_with_no_return_is_rejected() {
    //   0: Call 2
    //   1: Stop
    //   2: Stop                    (procedure body exits via Stop, not Return)
    let err = Cfg::build(&[call(2), brillig_stop(), brillig_stop()])
        .expect_err("procedure with no return should be rejected");
    let reason = unsupported_reason(err);
    assert!(
        reason.contains("procedure at block 2") && reason.contains("found 0"),
        "expected no-exit rejection, got: {reason}"
    );
}

#[test]
fn call_graph_with_mutual_recursion() {
    // Recursive call graph: main → A, A → B, B → A. The forward dom tree
    // is built over the caller-view edge set (`Call→target` edges removed),
    // so the cycle through procedure entries doesn't appear. Each procedure
    // is its own dom-tree component rooted at a virtual super-entry.
    //   0: Call 2         (main → A)
    //   1: Stop
    //   2: Call 4         (A → B)
    //   3: Return         (A's exit)
    //   4: Call 2         (B → A, cycle in the call graph)
    //   5: Return         (B's exit)
    let cfg = Cfg::build(&[call(2), brillig_stop(), call(4), ret(), call(2), ret()])
        .expect("cyclic call graph should now be accepted");
    let entries: Vec<_> = cfg.procedures.iter().map(|p| p.entry).collect();
    assert_eq!(entries, vec![BlockId(2), BlockId(4)]);
    // Procedure entries are roots in the multi-root forward dom tree.
    assert_eq!(cfg.dominators.idom(BlockId(2)), None);
    assert_eq!(cfg.dominators.idom(BlockId(4)), None);
}

#[test]
fn acyclic_call_graph_is_accepted() {
    //   0: Call 2         (main → A)
    //   1: Stop
    //   2: Call 4         (A → B)
    //   3: Return
    //   4: body           (B body)
    //   5: Return
    let cfg = Cfg::build(&[call(2), brillig_stop(), call(4), ret(), body(), ret()]).unwrap();
    assert_eq!(cfg.procedures.len(), 2);
    let entries: Vec<BlockId> = cfg.procedures.iter().map(|p| p.entry).collect();
    assert!(entries.contains(&BlockId(2)));
    assert!(entries.contains(&BlockId(4)));
}
