//! Structured-control-flow recovery for Brillig.
//!
//! Consumes the [`Cfg`] from [`super::cfg`] and emits a [`RegionNode`]
//! tree mapping directly to `scf.if`, `scf.while`, `bool.assert`, and
//! `function.return`. The walk is dominator-tree-driven, with terminator
//! kinds driving structural decisions in [`walker`].
//!
//! Multi-exit loops are rewritten to single-exit via a synthetic
//! [`EscapeFlagSlot`]; [`escape_flag`] enforces breaks land at iteration
//! tail. Each procedure body has its own escape-flag slot namespace.

use acir::brillig::MemoryAddress;

use super::cfg::{BlockId, Cfg};
use crate::error::Error;

mod display;
mod escape_flag;
mod loop_shape;
#[cfg(test)]
mod tests;
mod walker;

/// One node of the structured-control-flow tree. Sequence positions in
/// the parent `Vec<RegionNode>` encode fall-through.
#[derive(Clone)]
pub(super) enum StructureNode {
    /// Body opcodes of `block`, excluding its terminator (which has
    /// already driven the surrounding structure).
    Linear {
        block: BlockId,
    },

    /// Two-arm conditional joined at the immediate post-dominator; the
    /// join is whatever follows in the parent sequence.
    IfThenElse {
        cond_block: BlockId,
        condition: MemoryAddress,
        then_branch: Vec<StructureNode>,
        else_branch: Vec<StructureNode>,
    },

    /// Loop targeting `scf.while`. Emission ANDs `!flag` into the
    /// continuation condition when `escape_flag` is set.
    Loop {
        header: BlockId,
        /// Iteration-test region: runs on entry and after every
        /// back-edge, before `condition` is observed.
        test_prefix: Vec<StructureNode>,
        /// `None` for `Jump`-terminated headers (`loop { … }`); `Some`
        /// for `JumpIf`-terminated headers (`while … { … }`).
        condition: Option<LoopCondition>,
        escape_flag: Option<EscapeFlagSlot>,
        /// Body proper. Ends at the back-edge.
        body: Vec<StructureNode>,
    },

    /// Replaces an exit-edge `Jump`; falls through to end-of-iteration
    /// where the next header check observes the flag and exits.
    SetEscapeFlag {
        slot: EscapeFlagSlot,
    },

    /// Procedure call — leaf node. The callee's body lives in
    /// [`StructuredFunction::procedures`]; emission pushes/pops a
    /// [`super::memory::Frame`].
    Call {
        target: BlockId,
    },

    /// Trap-peephole result for `JumpIf cond, end; <trap-arm>; Trap; end:`.
    BoolAssert {
        cond_block: BlockId,
        condition: MemoryAddress,
    },

    Trap {
        block: BlockId,
    },
    Stop {
        block: BlockId,
    },
    /// Procedure exit — emission pops the current frame and emits no IR.
    Return {
        block: BlockId,
    },
}

#[derive(Clone, Copy, Debug)]
pub(super) struct LoopCondition {
    pub(super) register: MemoryAddress,
    pub(super) polarity: CondPolarity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CondPolarity {
    /// `JumpIf(cond, body_entry, exit)` — true continues the loop.
    ContinueOnTrue,
    /// `JumpIf(cond, exit, body_entry)` — true exits the loop.
    ExitOnTrue,
}

/// Synthetic RAM slot used to unify multi-exit loops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct EscapeFlagSlot(pub(super) usize);

/// Result of structuring a single Brillig function. Slot indices are
/// local to each body — slot 0 in `main` is distinct from slot 0 in any
/// procedure.
pub(super) struct StructuredFunction {
    pub(super) main: Vec<StructureNode>,
    pub(super) main_escape_flag_count: usize,
    pub(super) procedures: Vec<StructuredProcedure>,
}

pub(super) struct StructuredProcedure {
    pub(super) entry: BlockId,
    pub(super) body: Vec<StructureNode>,
    pub(super) escape_flag_count: usize,
}

impl StructuredFunction {
    #[cfg(test)]
    fn body_of(&self, target: BlockId) -> Option<&[StructureNode]> {
        self.procedures
            .iter()
            .find(|p| p.entry == target)
            .map(|p| p.body.as_slice())
    }
}

pub(super) fn structure_function(cfg: &Cfg) -> Result<StructuredFunction, Error> {
    let mut state = walker::State::new(cfg);
    let mut procedures = Vec::with_capacity(cfg.procedures.len());
    for proc in &cfg.procedures {
        let (body, escape_flag_count) = state.structure_one_body(proc.entry)?;
        procedures.push(StructuredProcedure {
            entry: proc.entry,
            body,
            escape_flag_count,
        });
    }
    let (main, main_escape_flag_count) = state.structure_one_body(BlockId(0))?;
    Ok(StructuredFunction {
        main,
        main_escape_flag_count,
        procedures,
    })
}
