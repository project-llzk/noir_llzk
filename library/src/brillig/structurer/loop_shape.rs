//! Classification of natural-loop headers and their exit edges.
//!
//! A successful classification yields a
//! [`LoopShape`] consumed by the walker to build a [`super::RegionNode::Loop`].

use acir::brillig::MemoryAddress;

use super::{CondPolarity, LoopCondition};
use crate::brillig::cfg::{BlockId, Cfg, NaturalLoop, Terminator};
use crate::error::Error;

/// Classification of a natural loop's header.
pub(super) struct LoopShape {
    /// Block whose terminator decides the iteration's exit. Equals the
    /// natural header except when intra-body joining `JumpIf`s precede
    /// the actual exit-deciding block.
    pub(super) effective_header: BlockId,
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
/// converging in-body exit edge. Classification is matched against the
/// *effective* header (see [`find_effective_header`]).
pub(super) fn get_loop_shape(cfg: &Cfg, n_loop: &NaturalLoop) -> Result<LoopShape, Error> {
    let header = n_loop.header;
    let exit_edges = collect_exit_edges(cfg, n_loop);
    let effective_header = find_effective_header(cfg, n_loop)?;
    let shape = match cfg.blocks[effective_header.0].terminator {
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
                    effective_header,
                    condition,
                    then_block,
                    else_block,
                    CondPolarity::ContinueOnTrue,
                    exit_edges,
                ),
                (false, true) => jumpif_shape(
                    cfg,
                    effective_header,
                    condition,
                    else_block,
                    then_block,
                    CondPolarity::ExitOnTrue,
                    exit_edges,
                ),
                _ => {
                    return Err(Error::UnsupportedBrillig {
                        reason: format!(
                            "Brillig loop header b{} (effective b{}): JumpIf must have \
                             exactly one target inside the loop body",
                            header.0, effective_header.0
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
                effective_header,
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
                    "Brillig loop header b{} (effective b{}) terminates in {:?}; only \
                     JumpIf, Jump and Fallthrough headers are supported",
                    header.0, effective_header.0, other
                ),
            });
        }
    };
    // Invariant: every exit edge eventually converges at shape.exit_dest.
    // Use the convergence walker (canonical + post-dominator pass-through)
    // so a break path containing its own joining if/else is recognised.
    let convergence_target = walk_to_convergence(cfg, shape.exit_dest);
    for (src, dst) in &shape.exit_edges {
        let canonical = walk_to_convergence(cfg, *dst);
        if canonical != convergence_target {
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
    effective_header: BlockId,
    condition: MemoryAddress,
    body_entry: BlockId,
    exit_arm: BlockId,
    polarity: CondPolarity,
    exit_edges: Vec<(BlockId, BlockId)>,
) -> LoopShape {
    let (exit_prefix, exit_dest) = walk_to_canonical(cfg, exit_arm);
    LoopShape {
        effective_header,
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

/// Walks from the natural-loop header past `JumpIf`s that aren't real
/// exit-deciders. Two skip shapes are recognised:
/// - **Joining branch**: both arms in body → step to the post-dominator.
/// - **Header-level trap-peephole**: one arm in body, other arm in
///   `divergent_blocks` (an in-loop `assert`) → step to the in-body arm.
fn find_effective_header(cfg: &Cfg, n_loop: &NaturalLoop) -> Result<BlockId, Error> {
    let mut cur = n_loop.header;
    while let Terminator::JumpIf {
        then_block,
        else_block,
        ..
    } = cfg.blocks[cur.0].terminator
    {
        let then_in = n_loop.body.contains(&then_block);
        let else_in = n_loop.body.contains(&else_block);
        let next = match (then_in, else_in) {
            (true, true) => {
                let Some(pd) = cfg.post_dominators.idom(cur) else {
                    return Err(Error::UnsupportedBrillig {
                        reason: format!(
                            "Brillig loop header b{}: has both \
                            arms in the loop that do not join",
                            cur.0
                        ),
                    });
                };
                if !n_loop.body.contains(&pd) {
                    return Err(Error::UnsupportedBrillig {
                        reason: format!(
                            "Brillig loop header b{}: has both \
                            arms in the loop but their join (b{}) is not in loop",
                            cur.0, pd.0
                        ),
                    });
                }
                pd
            }
            (true, false) if cfg.divergent_blocks.contains(&else_block) => then_block,
            (false, true) if cfg.divergent_blocks.contains(&then_block) => else_block,
            _ => break,
        };
        if next == cur {
            break;
        }
        cur = next;
    }
    Ok(cur)
}

/// Lenient canonical walk: [`walk_to_canonical`] plus a post-dominator
/// pass-through for any `JumpIf` we get stuck at.
fn walk_to_convergence(cfg: &Cfg, start: BlockId) -> BlockId {
    let mut cur = walk_to_canonical(cfg, start).1;
    while let Terminator::JumpIf { .. } = cfg.blocks[cur.0].terminator
        && let Some(pd) = cfg.post_dominators.idom(cur)
    {
        cur = walk_to_canonical(cfg, pd).1;
    }
    cur
}

/// Walks forward through "trampoline" blocks (single-pred / single-succ
/// `Jump` or `Fallthrough`). Returns the chain visited and the first
/// non-trampoline block; chain is empty if `start` itself isn't a trampoline.
/// Single-pred uses the caller view, ignoring divergent-`Call` continuation
/// predecessors.
pub(super) fn walk_to_canonical(cfg: &Cfg, start: BlockId) -> (Vec<BlockId>, BlockId) {
    let mut chain = Vec::new();
    let mut cur = start;
    while is_trampoline(cfg, cur) {
        chain.push(cur);
        cur = cfg.successors[cur.0][0];
    }
    (chain, cur)
}

fn is_trampoline(cfg: &Cfg, b: BlockId) -> bool {
    cfg.caller_pred[b.0].len() == 1
        && cfg.successors[b.0].len() == 1
        && matches!(
            cfg.blocks[b.0].terminator,
            Terminator::Jump(_) | Terminator::Fallthrough(_)
        )
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
