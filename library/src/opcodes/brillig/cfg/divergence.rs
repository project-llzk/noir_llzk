use super::block_splitting::{Block, BlockId, Terminator};
use crate::Error;
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
            // `Unreachable` blocks are dead, not divergent.
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
/// [`Terminator::TrapReturn`], and retags the orphan `Return` itself as
/// [`Terminator::Unreachable`].
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
            blocks[next_idx].terminator = Terminator::Unreachable;
        }
    }
}

/// Drops every dead `JumpIf` arm whose target is another procedure's entry
/// block. Any non-`Call` edge into an entry is a Noir codegen artifact.
/// Retags such `JumpIf`s as `Jump(live_arm)` and patches `successors` /
/// `predecessors`.
///
/// Errors in following cases:
/// - a `JumpIf` with **both** arms targeting procedure entries, or
/// - a `Jump` / `Fallthrough` directly into a procedure entry.
pub(super) fn rewrite_dead_jumpif_to_procedure_entry(
    blocks: &mut [Block],
    successors: &mut [Vec<BlockId>],
    predecessors: &mut [Vec<BlockId>],
    call_targets: &[BlockId],
) -> Result<(), Error> {
    let entries: BTreeSet<BlockId> = call_targets.iter().copied().collect();
    let mut to_rewrite: Vec<(usize, BlockId, BlockId)> = Vec::new();
    for (i, b) in blocks.iter().enumerate() {
        match b.terminator {
            Terminator::JumpIf {
                then_block,
                else_block,
                ..
            } => {
                let then_dead = entries.contains(&then_block);
                let else_dead = entries.contains(&else_block);
                match (then_dead, else_dead) {
                    (true, false) => to_rewrite.push((i, else_block, then_block)),
                    (false, true) => to_rewrite.push((i, then_block, else_block)),
                    (true, true) => {
                        return Err(Error::UnsupportedBrillig {
                            reason: format!(
                                "Brillig block b{}: JumpIf has both arms targeting \
                                 procedure entries (b{} and b{}); no live continuation",
                                i, then_block.0, else_block.0
                            ),
                        });
                    }
                    (false, false) => {}
                }
            }
            Terminator::Jump(target) | Terminator::Fallthrough(target)
                if entries.contains(&target) =>
            {
                return Err(Error::UnsupportedBrillig {
                    reason: format!(
                        "Brillig block b{}: non-Call edge targets procedure entry b{}; \
                         procedures must be entered only via Call",
                        i, target.0
                    ),
                });
            }
            _ => {}
        }
    }

    for (i, live_arm, dead_arm) in to_rewrite {
        blocks[i].terminator = Terminator::Jump(live_arm);
        successors[i].retain(|&s| s != dead_arm);
        predecessors[dead_arm.0].retain(|&p| p != BlockId(i));
    }

    Ok(())
}

/// Procedure entries whose entry block terminates with
/// [`Terminator::TrapReturn`].
pub(crate) fn compute_non_returning_calls(
    blocks: &[Block],
    call_targets: &[BlockId],
) -> BTreeSet<BlockId> {
    call_targets
        .iter()
        .copied()
        .filter(|e| matches!(blocks[e.0].terminator, Terminator::TrapReturn))
        .collect()
}
