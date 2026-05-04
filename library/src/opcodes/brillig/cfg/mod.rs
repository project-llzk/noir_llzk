use std::collections::BTreeSet;

use crate::Error;
use acir::FieldElement;
use acir::brillig::Opcode as B;
use block_splitting::{Block, classify, index_ranges, split_blocks};
use divergence::{
    compute_always_divergent, compute_non_returning_calls, rewrite_dead_jumpif_to_procedure_entry,
    rewrite_trap_return_pattern,
};
use dom_tree::{DomTree, check_reducible};
use loops::detect_natural_loops;
use procedures::{Procedure, identify_procedures};
use utils::{caller_successors, compute_successors, invert_edges, unique_call_targets};

pub(crate) use block_splitting::{BlockId, Terminator};
pub(super) use loops::NaturalLoop;

// ── Cfg ─────────────────────────────────────────────────────────────────
mod block_splitting;
mod cfg_display;
mod divergence;
mod dom_tree;
mod loops;
mod procedures;
mod utils;
/// Control-flow graph recovered from Brillig bytecode.
///
/// Blocks are indexed by [`BlockId`]. Block `0` is always the entry.
pub(crate) struct Cfg {
    pub(crate) blocks: Vec<Block>,
    /// `successors[i]` — successor [`BlockId`]s of block `i`.
    pub(crate) successors: Vec<Vec<BlockId>>,
    /// `predecessors[i]` — predecessor [`BlockId`]s of block `i`.
    pub(crate) predecessors: Vec<Vec<BlockId>>,
    /// Caller-view successors: a non-divergent `Call` yields only its
    /// `continuation`; a divergent `Call` yields nothing; everything else
    /// mirrors `successors`. See [`utils::caller_successors`].
    pub(crate) caller_succ: Vec<Vec<BlockId>>,
    /// Caller-view predecessors: inverse of `caller_succ`. Excludes
    /// divergent-`Call` continuations (the bytecode reserves a block
    /// after every `Call` even when the callee never returns; that edge
    /// is never traversed at runtime).
    pub(crate) caller_pred: Vec<Vec<BlockId>>,
    pub(crate) dominators: DomTree,
    /// Post-dominator tree built over the live caller view (edges into
    /// [`Self::divergent_blocks`] are dropped — see trap-peephole join finding).
    pub(crate) post_dominators: DomTree,
    pub(crate) loops: Vec<NaturalLoop>,
    /// One entry per distinct `Call` target.
    pub(crate) procedures: Vec<Procedure>,
    /// Blocks where every forward path ends at a
    /// *divergent* leaf — `Trap`, `TrapReturn`, or `Call` to a divergent
    /// procedure.
    pub(crate) divergent_blocks: BTreeSet<BlockId>,
}

impl Cfg {
    /// Builds the CFG for `bytecode`.
    pub(crate) fn build(bytecode: &[B<FieldElement>]) -> Result<Self, Error> {
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
