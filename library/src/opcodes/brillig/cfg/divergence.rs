use super::block_splitting::{Block, BlockId, Terminator};
use super::utils::unique_call_targets;
use std::collections::BTreeSet;

/// Returns the set of blocks where every forward path (in [`caller_successors`]
/// view) ends at a *divergent* leaf — `Trap`, `TrapReturn`, or `Call` to a
/// divergent procedure. `Return` and `Stop` count as non-divergent escapes,
/// so any block that can reach one is excluded.
///
/// Computed via backward fixed point: seed with the divergent leaves
/// themselves; a block is always-divergent iff its caller-successor set is
/// non-empty and every caller-successor is already divergent.
pub(super) fn compute_always_divergent(
    blocks: &[Block],
    caller_succ: &[Vec<BlockId>],
    caller_pred: &[Vec<BlockId>],
    divergent_entries: &BTreeSet<BlockId>,
) -> BTreeSet<BlockId> {
    // remaining[j] = caller-successors of j not yet known divergent.
    let mut remaining: Vec<usize> = caller_succ.iter().map(|s| s.len()).collect();

    // Seed: divergent leaves — `Trap`, `TrapReturn`, or `Call` to a
    // divergent procedure. `Return` and `Stop` are non-divergent escapes
    // and are deliberately excluded.
    let mut divergent: BTreeSet<BlockId> = BTreeSet::new();
    let mut worklist: Vec<BlockId> = Vec::new();
    for (i, block) in blocks.iter().enumerate() {
        let is_divergent_leaf = match block.terminator {
            Terminator::Trap | Terminator::TrapReturn => true,
            Terminator::Call { target, .. } => divergent_entries.contains(&target),
            _ => false,
        };
        if is_divergent_leaf {
            divergent.insert(BlockId(i));
            worklist.push(BlockId(i));
        }
    }

    // Propagate: each time x becomes divergent, decrement remaining[j] for
    // every j with x ∈ caller_succ[j]. When remaining[j] hits 0 and j had
    // at least one caller-successor to begin with, j is always-divergent.
    while let Some(x) = worklist.pop() {
        for &pred in &caller_pred[x.0] {
            remaining[pred.0] -= 1;
            if remaining[pred.0] == 0 {
                divergent.insert(pred);
                worklist.push(pred);
            }
        }
    }
    divergent
}

/// Retags the `Trap` followed by an orphan `Return` as
/// [`Terminator::TrapReturn`].
///
/// This shape is currently emitted by the Noir `RevertWithString`
/// procedure
pub(crate) fn rewrite_trap_return_pattern(blocks: &mut [Block], predecessors: &[Vec<BlockId>]) {
    for i in 0..blocks.len() {
        if !matches!(blocks[i].terminator, Terminator::Trap) {
            continue;
        }
        let next_idx = i + 1;
        let Some(next) = blocks.get(next_idx) else {
            continue;
        };

        let is_orphan_return = matches!(next.terminator, Terminator::Return)
            && next.len() == 1
            && predecessors[next_idx].is_empty();
        if is_orphan_return {
            blocks[i].terminator = Terminator::TrapReturn;
        }
    }
}

/// Drops the dead then-arm of a *dangling-constrain-skip*: a
/// `codegen_if_not(cond, trap_or_call_divergent())` emitted last in an
/// artifact, whose `end_label` links to the next artifact's entry — i.e.
/// another procedure.
///
/// Pattern: block A is `JumpIf cond, then=t, else=e` with
/// `e.start == A.end_exclusive`, `t.start == e.end_exclusive`, `e`
/// trap-emitting (`Trap`/`TrapReturn`/`Call <divergent>`), and `t` a
/// call target. Retags A as `Jump(e)`.
pub(super) fn rewrite_dangling_constrain_skips(
    blocks: &mut [Block],
    divergent_entries: &BTreeSet<BlockId>,
) {
    let entry_points: BTreeSet<BlockId> = blocks
        .iter()
        .filter_map(|b| match b.terminator {
            Terminator::Call { target, .. } => Some(target),
            _ => None,
        })
        .collect();

    let mut to_rewrite: Vec<(usize, BlockId)> = Vec::new();
    for (i, b) in blocks.iter().enumerate() {
        let Terminator::JumpIf {
            then_block,
            else_block,
            ..
        } = b.terminator
        else {
            continue;
        };
        // Linear-layout check: codegen_if_not lays out
        //   [A: JumpIf cond, end_label] [B: body] [end_label = T: …]
        // contiguously. A.end == B.start and B.end == T.start.
        if blocks[else_block.0].start != b.end_exclusive
            || blocks[then_block.0].start != blocks[else_block.0].end_exclusive
        {
            continue;
        }
        // T must be a procedure entry — that's what makes the skip-arm
        // a *dangling* edge (a layout coincidence, not real flow).
        if !entry_points.contains(&then_block) {
            continue;
        }
        // B must be a trap-emitting block: Trap, TrapReturn, or a Call
        // to a divergent procedure. Anything else means this is a
        // legitimate JumpIf, not a constrain-skip.
        let trap_emitting = match blocks[else_block.0].terminator {
            Terminator::Trap | Terminator::TrapReturn => true,
            Terminator::Call { target, .. } => divergent_entries.contains(&target),
            _ => false,
        };
        if !trap_emitting {
            continue;
        }
        to_rewrite.push((i, else_block));
    }

    for (i, jump_target) in to_rewrite {
        blocks[i].terminator = Terminator::Jump(jump_target);
    }
}

/// Procedure entries whose entry block terminates with
/// [`Terminator::TrapReturn`].
pub(crate) fn compute_non_returning_calls(blocks: &[Block]) -> BTreeSet<BlockId> {
    unique_call_targets(blocks)
        .into_iter()
        .filter(|e| matches!(blocks[e.0].terminator, Terminator::TrapReturn))
        .collect()
}
