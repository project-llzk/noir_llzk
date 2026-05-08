use super::{Block, BlockId, Terminator};
use std::collections::BTreeSet;
// ── Successor / predecessor edges ──────────────────────────────────────

pub(super) fn compute_successors(blocks: &[Block]) -> Vec<Vec<BlockId>> {
    blocks
        .iter()
        .map(|b| match b.terminator {
            Terminator::Jump(target) | Terminator::Fallthrough(target) => vec![target],
            Terminator::JumpIf {
                then_block,
                else_block,
                ..
            } => vec![then_block, else_block],
            Terminator::Call {
                target,
                continuation,
            } => vec![target, continuation],
            Terminator::Return
            | Terminator::Stop
            | Terminator::Trap
            | Terminator::TrapReturn
            | Terminator::Unreachable => Vec::new(),
        })
        .collect()
}

pub(super) fn invert_edges(successors: &[Vec<BlockId>]) -> Vec<Vec<BlockId>> {
    let n = successors.len();
    let mut predecessors = vec![Vec::new(); n];
    for (from, succs) in successors.iter().enumerate() {
        for &BlockId(to) in succs {
            predecessors[to].push(BlockId(from));
        }
    }
    predecessors
}

/// Successors of `b` from the calling function's perspective: a non-divergent
/// `Call` yields only its `continuation` (the procedure body lives in another
/// region); a `Call` to a divergent procedure yields nothing (the continuation
/// is dead code — the procedure never resumes); everything else mirrors the
/// raw `successors` graph. Used by post-dom and loop-exit analyses, which
/// model caller flow rather than the call-graph union.
pub(super) fn caller_successors(
    blocks: &[Block],
    successors: &[Vec<BlockId>],
    divergent_entries: &BTreeSet<BlockId>,
    b: BlockId,
) -> Vec<BlockId> {
    match blocks[b.0].terminator {
        Terminator::Call {
            target,
            continuation,
        } => {
            if divergent_entries.contains(&target) {
                Vec::new()
            } else {
                vec![continuation]
            }
        }
        _ => successors[b.0].clone(),
    }
}

/// Collects every distinct `Call` target from `blocks`, in ascending
/// [`BlockId`] order.
pub(super) fn unique_call_targets(blocks: &[Block]) -> Vec<BlockId> {
    let mut seen: BTreeSet<BlockId> = BTreeSet::new();
    for b in blocks {
        if let Terminator::Call { target, .. } = b.terminator {
            seen.insert(target);
        }
    }
    seen.into_iter().collect()
}
