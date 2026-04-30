//! Classification of natural-loop headers and their exit edges.
//!
//! Pure functions over the [`Cfg`]. A successful classification yields a
//! [`LoopShape`] consumed by the walker to build a [`super::RegionNode::Loop`].

use acir::brillig::MemoryAddress;

use super::{CondPolarity, LoopCondition};
use crate::error::Error;
use crate::opcodes::brillig::cfg::{BlockId, Cfg, NaturalLoop, Terminator};

/// Classification of a natural loop's header.
pub(super) struct LoopShape {
    pub(super) body_entry: BlockId,
    pub(super) exit_dest: BlockId,
    /// Trampoline blocks between the header's natural exit arm and
    /// `exit_dest`. Empty for `Jump`-terminated headers and for `JumpIf`
    /// headers exiting directly to a multi-pred block. Emitted as
    /// [`super::RegionNode::Linear`] after the loop.
    pub(super) exit_prefix: Vec<BlockId>,
    pub(super) condition: Option<LoopCondition>,
    /// Every `(src_in_body, dst_outside_body)` edge for the loop, computed
    /// during classification so the walker doesn't recompute them.
    pub(super) exit_edges: Vec<(BlockId, BlockId)>,
}

/// Classifies a natural loop's header. `JumpIf`-terminated → `while` shape
/// with condition; `Jump`-terminated → `loop` shape, requires a single
/// converging in-body exit edge.
pub(super) fn classify_loop_header(cfg: &Cfg, n_loop: &NaturalLoop) -> Result<LoopShape, Error> {
    let header = n_loop.header;
    let exit_edges = collect_exit_edges(cfg, n_loop);
    let shape = match cfg.blocks[header.0].terminator {
        Terminator::JumpIf {
            condition,
            then_block,
            else_block,
        } => {
            let then_in = n_loop.body.contains(&then_block);
            let else_in = n_loop.body.contains(&else_block);
            match (then_in, else_in) {
                (true, false) => jumpif_shape(
                    cfg,
                    condition,
                    then_block,
                    else_block,
                    CondPolarity::ContinueOnTrue,
                    exit_edges,
                ),
                (false, true) => jumpif_shape(
                    cfg,
                    condition,
                    else_block,
                    then_block,
                    CondPolarity::ExitOnTrue,
                    exit_edges,
                ),
                _ => {
                    return Err(Error::UnsupportedBrillig {
                        reason: format!(
                            "Brillig loop header b{}: JumpIf must have exactly one target \
                             inside the loop body",
                            header.0
                        ),
                    });
                }
            }
        }
        Terminator::Jump(target) | Terminator::Fallthrough(target) => {
            if !n_loop.body.contains(&target) {
                return Err(Error::UnsupportedBrillig {
                    reason: format!(
                        "Brillig loop header b{}: Jump target b{} is outside \
                         the loop body — degenerate loop with no body",
                        header.0, target.0
                    ),
                });
            }
            if exit_edges.is_empty() {
                return Err(Error::UnsupportedBrillig {
                    reason: format!(
                        "Brillig loop header b{} (Jump-terminated) has no exit \
                         edges — infinite loop with no break",
                        header.0
                    ),
                });
            }
            // Seed exit_dest from the first edge; the canonical-convergence
            // check below validates that every other edge agrees.
            let exit_dest = walk_to_canonical(cfg, exit_edges[0].1).1;
            LoopShape {
                body_entry: target,
                exit_dest,
                exit_prefix: Vec::new(),
                condition: None,
                exit_edges,
            }
        }
        other => {
            return Err(Error::UnsupportedBrillig {
                reason: format!(
                    "Brillig loop header b{} terminates in {:?}; only JumpIf, \
                     Jump and Fallthrough headers are supported",
                    header.0, other
                ),
            });
        }
    };
    // Invariant: every exit edge canonicalizes to shape.exit_dest.
    for (src, dst) in &shape.exit_edges {
        let canonical = walk_to_canonical(cfg, *dst).1;
        if canonical != shape.exit_dest {
            return Err(Error::UnsupportedBrillig {
                reason: format!(
                    "Brillig loop header b{}: exit edge b{}→b{} converges on \
                     b{} but the loop's canonical exit destination is b{}",
                    header.0, src.0, dst.0, canonical.0, shape.exit_dest.0
                ),
            });
        }
    }
    Ok(shape)
}

/// Builds a `LoopShape` for a `JumpIf`-terminated header. The exit arm is
/// walked to its canonical destination; polarity records the continuation truth value.
fn jumpif_shape(
    cfg: &Cfg,
    condition: MemoryAddress,
    body_entry: BlockId,
    exit_arm: BlockId,
    polarity: CondPolarity,
    exit_edges: Vec<(BlockId, BlockId)>,
) -> LoopShape {
    let (exit_prefix, exit_dest) = walk_to_canonical(cfg, exit_arm);
    LoopShape {
        body_entry,
        exit_dest,
        exit_prefix,
        condition: Some(LoopCondition {
            register: condition,
            polarity,
        }),
        exit_edges,
    }
}

/// Walks forward through "trampoline" blocks (single-pred / single-succ
/// `Jump` or `Fallthrough`). Returns the chain visited and the first
/// non-trampoline block; chain is empty if `start` itself isn't a trampoline.
pub(super) fn walk_to_canonical(cfg: &Cfg, start: BlockId) -> (Vec<BlockId>, BlockId) {
    let mut chain = Vec::new();
    let mut cur = start;
    loop {
        let single_pred = cfg.predecessors[cur.0].len() == 1;
        let single_succ = cfg.successors[cur.0].len() == 1;
        let is_jump = matches!(
            cfg.blocks[cur.0].terminator,
            Terminator::Jump(_) | Terminator::Fallthrough(_)
        );
        if !(single_pred && single_succ && is_jump) {
            return (chain, cur);
        }
        chain.push(cur);
        cur = cfg.successors[cur.0][0];
    }
}

/// Returns every `(src_in_body, dst_outside_body)` edge using the caller's
/// CFG view. Drops `Call→target` edges (procedure entries aren't real exits)
/// and edges into [`Cfg::divergent_blocks`] (always-trapping destinations).
pub(super) fn collect_exit_edges(cfg: &Cfg, n_loop: &NaturalLoop) -> Vec<(BlockId, BlockId)> {
    let mut edges = Vec::new();
    for &block in &n_loop.body {
        for &dst in &cfg.caller_succ[block.0] {
            if !n_loop.body.contains(&dst) && !cfg.divergent_blocks.contains(&dst) {
                edges.push((block, dst));
            }
        }
    }
    edges
}
