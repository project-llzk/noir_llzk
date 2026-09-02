use std::collections::BTreeSet;

use crate::Error;
use acir::brillig::{MemoryAddress, Opcode as B};
use acir::{FieldElement, brillig::Label};
use block_splitting::{classify, index_ranges, split_blocks};
use divergence::{
    compute_always_divergent, compute_non_returning_calls, rewrite_dead_jumpif_to_procedure_entry,
    rewrite_trap_return_pattern,
};
use dom_tree::check_reducible;
use loops::detect_natural_loops;
use procedures::identify_procedures;
use utils::{caller_successors, compute_successors, invert_edges, unique_call_targets};

// ── Cfg ─────────────────────────────────────────────────────────────────
mod block_splitting;
mod cfg_display;
mod divergence;
mod dom_tree;
mod loops;
mod procedures;
#[cfg(test)]
mod tests;
mod utils;

/// Control-flow graph recovered from Brillig bytecode.
///
/// Blocks are indexed by [`BlockId`]. Block `0` is always the entry.
pub(super) struct Cfg {
    pub(super) blocks: Vec<Block>,
    /// `successors[i]` — successor [`BlockId`]s of block `i`.
    pub(super) successors: Vec<Vec<BlockId>>,
    /// `predecessors[i]` — predecessor [`BlockId`]s of block `i`.
    pub(super) predecessors: Vec<Vec<BlockId>>,
    /// Caller-view successors: a non-divergent `Call` yields only its
    /// `continuation`; a divergent `Call` yields nothing; everything else
    /// mirrors `successors`. See [`utils::caller_successors`].
    pub(super) caller_succ: Vec<Vec<BlockId>>,
    /// Caller-view predecessors: inverse of `caller_succ`. Excludes
    /// divergent-`Call` continuations (the bytecode reserves a block
    /// after every `Call` even when the callee never returns; that edge
    /// is never traversed at runtime).
    pub(super) caller_pred: Vec<Vec<BlockId>>,
    pub(super) dominators: DomTree,
    /// Post-dominator tree built over the live caller view (edges into
    /// [`Self::divergent_blocks`] are dropped — see trap-peephole join finding).
    pub(super) post_dominators: DomTree,
    pub(super) loops: Vec<NaturalLoop>,
    /// One entry per distinct `Call` target.
    pub(super) procedures: Vec<Procedure>,
    /// Blocks where every forward path ends at a
    /// *divergent* leaf — `Trap`, `TrapReturn`, or `Call` to a divergent
    /// procedure.
    pub(super) divergent_blocks: BTreeSet<BlockId>,
}

impl Cfg {
    /// Builds the CFG for `bytecode`.
    pub(super) fn build(bytecode: &[B<FieldElement>]) -> Result<Self, Error> {
        let block_ranges = split_blocks(bytecode)?;
        let index_to_block = index_ranges(&block_ranges);
        let mut blocks = classify(bytecode, &block_ranges, &index_to_block)?;

        let mut successors = compute_successors(&blocks);
        let mut predecessors = invert_edges(&successors);

        rewrite_trap_return_pattern(&mut blocks, &predecessors);

        // `Call` terminators are stable across both rewrites — neither
        // adds nor removes them — so collect call targets once and reuse.
        let call_targets = unique_call_targets(&blocks);
        let divergent_entries = compute_non_returning_calls(&blocks, &call_targets);

        // Drop `JumpIf` arms whose target is another procedure's
        // entry.
        rewrite_dead_jumpif_to_procedure_entry(
            &mut blocks,
            &mut successors,
            &mut predecessors,
            &call_targets,
        )?;

        // Caller-view of the CFG, computed once and shared by post-dominator
        // construction and always-divergent analysis.
        let caller_succ: Vec<Vec<BlockId>> = (0..blocks.len())
            .map(|i| caller_successors(&blocks, &successors, &divergent_entries, BlockId(i)))
            .collect();
        let caller_pred = invert_edges(&caller_succ);

        let procedures = identify_procedures(&blocks, &successors, &caller_succ, &call_targets)?;

        // Forward dom tree uses the caller-view edge set with a virtual
        // super-entry seeded from `BlockId(0)` plus every procedure entry.
        let mut roots = Vec::with_capacity(procedures.len() + 1);
        roots.push(BlockId(0));
        roots.extend(procedures.iter().map(|p| p.entry));
        let dominators = DomTree::build_with_super_entry(&caller_succ, &caller_pred, &roots);

        // Blocks from which every forward path bottoms out at a divergent
        // leaf (`Trap`/`TrapReturn`/`Call`-divergent).
        let divergent_blocks =
            compute_always_divergent(&blocks, &caller_succ, &caller_pred, &divergent_entries);

        // Live caller view: caller_succ minus edges into divergent blocks.
        let live_caller_succ: Vec<Vec<BlockId>> = caller_succ
            .iter()
            .map(|succs| {
                succs
                    .iter()
                    .copied()
                    .filter(|s| !divergent_blocks.contains(s))
                    .collect()
            })
            .collect();
        let live_caller_pred = invert_edges(&live_caller_succ);

        let post_dominators = DomTree::build_post(&blocks, &live_caller_succ, &live_caller_pred);
        let loops = detect_natural_loops(&caller_pred, &dominators, blocks.len());

        check_reducible(&caller_succ, &dominators)?;

        Ok(Cfg {
            blocks,
            successors,
            predecessors,
            caller_succ,
            caller_pred,
            dominators,
            post_dominators,
            loops,
            procedures,
            divergent_blocks,
        })
    }
}

/// Identifier of a basic block in the recovered CFG. Entry is `BlockId(0)`;
/// the rest are allocated in first-seen order during the pre-walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) struct BlockId(pub(super) usize);

// ── Blocks and terminators ──────────────────────────────────────────────

/// A basic block spans bytecode indices `[start, end_exclusive)`. The final
/// opcode in the range is the block's [`Terminator`]; prior opcodes are the
/// block body.
#[derive(Clone, Debug)]
pub(super) struct Block {
    pub(super) start: Label,
    pub(super) end_exclusive: Label,
    pub(super) terminator: Terminator,
}

/// A Brillig procedure: the region of blocks reachable from a
/// [`Terminator::Call`] target. Either ends in a single `Return` (normal
/// procedure, possibly with `Trap` branches in conditional failure paths),
/// or has no `Return` and all leaves are `Trap` (a diverging helper — only
/// `RevertWithString` matches this shape today).
#[derive(Clone, Debug)]
pub(super) struct Procedure {
    /// Entry block of the procedure (a `Call` target).
    pub(super) entry: BlockId,
    /// Every block reachable from `entry` without crossing nested calls.
    body: BTreeSet<BlockId>,
    /// `Some(b)` for the unique `Return`-terminated block; `None` for
    /// diverging procedures whose only leaves are `Trap`.
    pub(super) return_block: Option<BlockId>,
}

/// A natural loop: a header and the set of blocks reached by walking
/// backwards from the loop's back-edge source until the header is hit.
#[derive(Clone, Debug)]
pub(super) struct NaturalLoop {
    pub(super) header: BlockId,
    pub(super) body: BTreeSet<BlockId>,
}

/// Classification of a block's last opcode. Drives CFG edge construction
/// and structurer dispatch.
#[derive(Clone, Copy, Debug)]
pub(super) enum Terminator {
    /// `Jump L` — unconditional branch.
    Jump(BlockId),
    /// `JumpIf cond, then_block`. `else_block` is the fall-through (the
    /// instruction immediately after the `JumpIf`).
    JumpIf {
        condition: MemoryAddress,
        then_block: BlockId,
        else_block: BlockId,
    },
    /// `Call L`. `target` is the callee's entry; `continuation` is the
    /// block starting at the instruction after the `Call`. Noir's codegen
    /// always emits SP-restore and return-copy opcodes after `Call`, so
    /// `continuation` is always present — bytecode with `Call` as the
    /// final opcode is rejected by [`classify`].
    Call {
        target: BlockId,
        continuation: BlockId,
    },
    /// `Return` — procedure exit. No CFG successors.
    Return,
    /// `Stop` — function exit with return data. No CFG successors.
    Stop,
    /// `Trap` — execution failure. No CFG successors.
    Trap,
    /// Synthesized terminator for the `RevertWithString` shape: a `Trap`
    /// opcode immediately followed by an orphan `Return` opcode.
    TrapReturn,
    /// Synthesized when a block's last opcode is not a flow op and a
    /// jump/call target lands at the next index, splitting an implicit
    /// fall-through edge.
    Fallthrough(BlockId),
    /// Statically-dead block.
    Unreachable,
}

/// Immediate-dominator table. `idom[i]` is the immediate dominator of
/// block `i`, or `None` for the entry and for blocks unreachable from
/// the entry.
#[derive(Debug)]
pub(super) struct DomTree {
    idom: Vec<Option<BlockId>>,
    /// Position of each reachable block in reverse-postorder. Used for the
    /// O(log n) `intersect` step and for fast `dominates` queries.
    /// Unreachable blocks hold `usize::MAX`.
    rpo_index: Vec<usize>,
}
