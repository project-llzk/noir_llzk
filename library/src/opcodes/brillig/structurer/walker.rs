//! Turns the [`Cfg`] into a tree of [`super::RegionNode`]s; holds the
//! escape-flag counter and threads loop context through recursion.

use std::collections::HashMap;

use acir::brillig::MemoryAddress;

use super::escape_flag::validate_escape_flag_positions;
use super::loop_shape::get_loop_shape;
use super::{EscapeFlagSlot, RegionNode};
use crate::error::Error;
use crate::opcodes::brillig::cfg::{BlockId, Cfg, Terminator};

/// Walker state, reused across main and every procedure body.
/// `escape_flags` is reset per body so slot indices are body-local.
pub(super) struct State<'a> {
    pub(super) cfg: &'a Cfg,
    /// Slots allocated in the body currently being structured; reset
    /// per `structure_one_body` call.
    escape_flags: usize,
    /// `loop_index_by_header[h] = i` iff `cfg.loops[i]` has header `h`.
    loop_index_by_header: HashMap<BlockId, usize>,
    /// `procedure_index_by_entry[e] = i` iff `cfg.procedures[i]` enters at `e`.
    procedure_index_by_entry: HashMap<BlockId, usize>,
}

/// Enclosing loop context, threaded so back-edges and break-edges are
/// recognized.
#[derive(Clone, Copy, Debug)]
pub(super) struct LoopCtx {
    pub(super) header: BlockId,
    /// Loop's exit target. Jumps here from inside the body are
    /// intercepted as breaks when `escape_flag` is set.
    pub(super) exit_dest: BlockId,
    /// Set iff the loop has multi-exit rewrite enabled.
    pub(super) escape_flag: Option<EscapeFlagSlot>,
}

impl<'a> State<'a> {
    pub(super) fn new(cfg: &'a Cfg) -> Self {
        let loop_index_by_header = cfg
            .loops
            .iter()
            .enumerate()
            .map(|(i, l)| (l.header, i))
            .collect();
        let procedure_index_by_entry = cfg
            .procedures
            .iter()
            .enumerate()
            .map(|(i, p)| (p.entry, i))
            .collect();
        State {
            cfg,
            escape_flags: 0,
            loop_index_by_header,
            procedure_index_by_entry,
        }
    }

    /// Structures the body at `entry`; returns its regions and the
    /// count of escape-flag slots used.
    pub(super) fn structure_one_body(
        &mut self,
        entry: BlockId,
    ) -> Result<(Vec<RegionNode>, usize), Error> {
        self.escape_flags = 0;
        let regions = self.structure_region(entry, None, None)?;
        Ok((regions, self.escape_flags))
    }

    /// Walks `[entry, …)`. `end_block = Some(b)` stops at `b` (if-arm
    /// join); `None` walks until a leaf terminator. The back-edge stop
    /// (`current == ctx.header`) is suppressed on the first iteration so
    /// callers can pass `entry == ctx.header` when walking a loop's
    /// header prefix.
    fn structure_region(
        &mut self,
        entry: BlockId,
        end_block: Option<BlockId>,
        loop_ctx: Option<LoopCtx>,
    ) -> Result<Vec<RegionNode>, Error> {
        let mut nodes = Vec::new();
        let mut current = entry;
        let mut first = true;
        loop {
            // Reached the enclosing loop's exit destination — a break.
            // Tag this branch with `SetEscapeFlag`.
            if let Some(ctx) = loop_ctx
                && current == ctx.exit_dest
            {
                let slot = ctx.escape_flag.expect(
                    "reaching the loop's exit_dest implies a body-internal \
                     exit edge, which guarantees an escape flag was allocated",
                );
                nodes.push(RegionNode::SetEscapeFlag { slot });
                return Ok(nodes);
            }
            // Other stopping reasons — the named join block
            // or the enclosing loop's header.
            let header_stop = !first && loop_ctx.is_some_and(|c| c.header == current);
            if matches!(end_block, Some(stop) if stop == current) || header_stop {
                return Ok(nodes);
            }
            first = false;

            // New loop header? Switch to loop structuring.
            if let Some(&loop_idx) = self.loop_index_by_header.get(&current) {
                let already_inside = matches!(loop_ctx, Some(ctx) if ctx.header == current);
                if !already_inside {
                    let (loop_nodes, after) = self.structure_loop(loop_idx)?;
                    nodes.extend(loop_nodes);
                    let Some(next) = after else {
                        return Ok(nodes);
                    };
                    current = next;
                    continue;
                }
            }

            // Trap peephole.
            if let Some(peephole) = self.try_trap_peephole(current) {
                nodes.push(RegionNode::Linear { block: current });
                nodes.push(RegionNode::BoolAssert {
                    cond_block: current,
                    condition: peephole.condition,
                });
                current = peephole.after;
                continue;
            }

            // Generic per-block dispatch.
            nodes.push(RegionNode::Linear { block: current });
            match self.cfg.blocks[current.0].terminator {
                Terminator::Jump(target) | Terminator::Fallthrough(target) => {
                    // Back-edges/exits/headers are intercepted at the
                    // next iteration.
                    current = target;
                }
                Terminator::JumpIf {
                    condition,
                    then_block,
                    else_block,
                } => {
                    let outcome = if let Some(join) = self.cfg.post_dominators.idom(current) {
                        self.structure_joining_cond(
                            current, condition, then_block, else_block, join, loop_ctx, &mut nodes,
                        )?
                    } else {
                        self.structure_diverging_cond(
                            current, condition, then_block, else_block, loop_ctx, &mut nodes,
                        )?
                    };
                    match outcome {
                        Some(next) => current = next,
                        None => return Ok(nodes),
                    }
                }
                Terminator::Call {
                    target,
                    continuation,
                } => {
                    let proc_idx = self.procedure_index_by_entry[&target];
                    let is_diverging = self.cfg.procedures[proc_idx].return_block.is_none();
                    nodes.push(RegionNode::Call { target });
                    if is_diverging {
                        return Ok(nodes);
                    }
                    current = continuation;
                }
                Terminator::Return => {
                    nodes.push(RegionNode::Return { block: current });
                    return Ok(nodes);
                }
                Terminator::Stop => {
                    nodes.push(RegionNode::Stop { block: current });
                    return Ok(nodes);
                }
                Terminator::Trap | Terminator::TrapReturn => {
                    // TrapReturn (RevertWithString) emits like Trap; the
                    // distinction lives at the call site, which skips
                    // the continuation.
                    nodes.push(RegionNode::Trap { block: current });
                    return Ok(nodes);
                }
                Terminator::Unreachable => {
                    unreachable!(
                        "Brillig structurer reached b{} (Unreachable terminator); \
                         dead-byte blocks should not be reachable from any procedure entry",
                        current.0
                    );
                }
            }
        }
    }

    /// `JumpIf` whose arms join at `join`. Pushes `IfThenElse`; returns
    /// `Some(next)` to continue or `None` to stop.
    fn structure_joining_cond(
        &mut self,
        cond_block: BlockId,
        condition: MemoryAddress,
        then_block: BlockId,
        else_block: BlockId,
        join: BlockId,
        loop_ctx: Option<LoopCtx>,
        nodes: &mut Vec<RegionNode>,
    ) -> Result<Option<BlockId>, Error> {
        let then_branch = self.structure_region(then_block, Some(join), loop_ctx)?;
        let else_branch = self.structure_region(else_block, Some(join), loop_ctx)?;
        nodes.push(RegionNode::IfThenElse {
            cond_block,
            condition,
            then_branch,
            else_branch,
        });
        // If join == loop's exit_dest with a flag in use, both arms
        // already emitted SetEscapeFlag — don't double-set.
        if let Some(ctx) = loop_ctx
            && ctx.escape_flag.is_some()
            && join == ctx.exit_dest
        {
            return Ok(None);
        }
        Ok(Some(join))
    }

    /// `JumpIf` with no join. Classifies arms by divergence
    /// (Trap/TrapReturn/Call-divergent vs. Return/Stop) and pushes an
    /// `IfThenElse`; returns `Some(continuing_arm)` for the half-joining
    /// case, `None` otherwise.
    fn structure_diverging_cond(
        &mut self,
        cond_block: BlockId,
        condition: MemoryAddress,
        then_block: BlockId,
        else_block: BlockId,
        loop_ctx: Option<LoopCtx>,
        nodes: &mut Vec<RegionNode>,
    ) -> Result<Option<BlockId>, Error> {
        let then_divergent = self.cfg.divergent_blocks.contains(&then_block);
        let else_divergent = self.cfg.divergent_blocks.contains(&else_block);
        match (then_divergent, else_divergent) {
            (true, false) | (false, true) => {
                // Half-joining: walk only the divergent arm into the
                // IfThenElse, then resume at the continuing arm.
                let (divergent_arm, continuing_arm, divergent_is_then) = if then_divergent {
                    (then_block, else_block, true)
                } else {
                    (else_block, then_block, false)
                };
                let divergent_branch = self.structure_region(divergent_arm, None, loop_ctx)?;
                let (then_branch, else_branch) = if divergent_is_then {
                    (divergent_branch, Vec::new())
                } else {
                    (Vec::new(), divergent_branch)
                };
                nodes.push(RegionNode::IfThenElse {
                    cond_block,
                    condition,
                    then_branch,
                    else_branch,
                });
                Ok(Some(continuing_arm))
            }
            _ => {
                // Both arms terminate (panic or Return/Stop) — no
                // continuation; walk each to its leaf and close the
                // scope.
                let then_branch = self.structure_region(then_block, None, loop_ctx)?;
                let else_branch = self.structure_region(else_block, None, loop_ctx)?;
                nodes.push(RegionNode::IfThenElse {
                    cond_block,
                    condition,
                    then_branch,
                    else_branch,
                });
                Ok(None)
            }
        }
    }

    /// Structures the natural loop at `loop_idx`. Returns the loop node
    /// and the block to continue at after it (`None` if the exit_dest
    /// itself terminates the enclosing region).
    fn structure_loop(
        &mut self,
        loop_idx: usize,
    ) -> Result<(Vec<RegionNode>, Option<BlockId>), Error> {
        let r#loop = self.cfg.loops[loop_idx].clone();
        let header = r#loop.header;

        let shape = get_loop_shape(self.cfg, &r#loop)?;

        // Need a flag iff some exit edge starts at a non-header block.
        // Header-arm exits (from natural or effective header) use the
        // condition directly.
        let body_internal_exits = shape
            .exit_edges
            .iter()
            .filter(|(src, _)| *src != header && *src != shape.effective_header)
            .count();
        let escape_flag = if body_internal_exits > 0 {
            Some(self.alloc_escape_flag())
        } else {
            None
        };

        let body_ctx = LoopCtx {
            header,
            exit_dest: shape.exit_dest,
            escape_flag,
        };

        // Structure the header prefix (intra-body work between natural
        // and effective header) when they differ, then the body proper.
        let mut body = if shape.effective_header != header {
            self.structure_region(header, Some(shape.effective_header), Some(body_ctx))?
        } else {
            Vec::new()
        };
        body.extend(self.structure_region(shape.body_entry, None, Some(body_ctx))?);
        if escape_flag.is_some() {
            validate_escape_flag_positions(&body, header)?;
        }

        let mut nodes = vec![RegionNode::Loop {
            header,
            condition: shape.condition,
            escape_flag,
            body,
        }];
        nodes.extend(
            shape
                .exit_prefix
                .into_iter()
                .map(|block| RegionNode::Linear { block }),
        );
        Ok((nodes, Some(shape.exit_dest)))
    }

    fn alloc_escape_flag(&mut self) -> EscapeFlagSlot {
        let slot = EscapeFlagSlot(self.escape_flags);
        self.escape_flags += 1;
        slot
    }

    /// Recognizes a `JumpIf` whose else arm is dedicated to panicking:
    ///
    /// ```text
    /// block:       JumpIf cond, then=then_block, else=else_block
    /// else_block:  <every path traps: Trap/TrapReturn or divergent Call>
    /// then_block:  …continuation…
    /// ```
    ///
    /// Matches when `else_block`'s sole predecessor is `block`,
    /// `else_block` is in `Cfg::divergent_blocks`, and `then_block` is
    /// not — without that last check we'd lower an unconditional panic
    /// as `BoolAssert(cond)`. The else-arm opcodes are dropped.
    fn try_trap_peephole(&self, block: BlockId) -> Option<TrapPeephole> {
        let Terminator::JumpIf {
            condition,
            then_block,
            else_block,
        } = self.cfg.blocks[block.0].terminator
        else {
            return None;
        };
        let else_arm_always_traps = self.cfg.divergent_blocks.contains(&else_block);
        let then_arm_continues = !self.cfg.divergent_blocks.contains(&then_block);
        let else_arm_is_dedicated = self.cfg.predecessors[else_block.0].as_slice() == [block];
        if else_arm_always_traps && then_arm_continues && else_arm_is_dedicated {
            Some(TrapPeephole {
                condition,
                after: then_block,
            })
        } else {
            None
        }
    }
}

struct TrapPeephole {
    condition: MemoryAddress,
    after: BlockId,
}
