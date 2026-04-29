use std::collections::BTreeSet;

use crate::Error;
use acir::FieldElement;
use acir::brillig::Opcode as B;
use block_splitting::{Block, classify, index_ranges, split_blocks};
use divergence::{
    compute_always_divergent, compute_non_returning_calls, rewrite_dangling_constrain_skips,
    rewrite_trap_return_pattern,
};
use dom_tree::{DomTree, check_reducible};
use loops::detect_natural_loops;
use procedures::{Procedure, check_call_graph_acyclic, identify_procedures};
use utils::{compute_successors, invert_edges};

// Re-exports for the sibling `structurer` module. `BlockId` and
// `Terminator` are `pub(crate)` because tests import them directly;
// `NaturalLoop` and `caller_successors` are `pub(super)` (brillig-scope)
// since they're consumed only inside this module tree.
pub(crate) use block_splitting::{BlockId, Terminator};
pub(super) use loops::NaturalLoop;
pub(super) use utils::caller_successors;

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
    pub(crate) dominators: DomTree,
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
        let initial_successors = compute_successors(&blocks);
        let initial_predecessors = invert_edges(&initial_successors);

        rewrite_trap_return_pattern(&mut blocks, &initial_predecessors);

        let divergent_entries = compute_non_returning_calls(&blocks);

        // Recognise the *dangling-constrain-skip* shape that
        // `codegen_if_not(cond, |ctx| call_<divergent>())` emits when the
        // construct is the last in its function. The skip-arm is dead by construction.
        // Replace the `JumpIf` with a `Jump` to the trap-arm.
        rewrite_dangling_constrain_skips(&mut blocks, &divergent_entries);

        let successors = compute_successors(&blocks);
        let predecessors = invert_edges(&successors);

        // Caller-view of the CFG, computed once and shared by post-dominator
        // construction and always-divergent analysis.
        let caller_succ: Vec<Vec<BlockId>> = (0..blocks.len())
            .map(|i| caller_successors(&blocks, &successors, &divergent_entries, BlockId(i)))
            .collect();
        let caller_pred = invert_edges(&caller_succ);

        let dominators = DomTree::build(&successors, &predecessors, BlockId(0));
        let post_dominators = DomTree::build_post(&blocks, &caller_succ, &caller_pred);
        let loops = detect_natural_loops(&predecessors, &dominators, blocks.len());

        let procedures = identify_procedures(&blocks, &successors, &caller_succ)?;
        check_call_graph_acyclic(&blocks, &procedures)?;
        check_reducible(&successors, &dominators)?;

        // Blocks from which every forward path bottoms out at a
        // divergent leaf (`Trap`/`TrapReturn`/`Call`-divergent), with
        // no escape via `Return` or `Stop`.
        let divergent_blocks =
            compute_always_divergent(&blocks, &caller_succ, &caller_pred, &divergent_entries);

        Ok(Cfg {
            blocks,
            successors,
            predecessors,
            dominators,
            post_dominators,
            loops,
            procedures,
            divergent_blocks,
        })
    }
}
