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
mod walker;

/// One node of the structured-control-flow tree. Sequence positions in
/// the parent `Vec<RegionNode>` encode fall-through.
#[derive(Clone)]
pub(crate) enum RegionNode {
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
        then_branch: Vec<RegionNode>,
        else_branch: Vec<RegionNode>,
    },

    /// Loop targeting `scf.while`. Emission ANDs `!flag` into the
    /// continuation condition when `escape_flag` is set.
    Loop {
        header: BlockId,
        /// Iteration-test region: runs on entry and after every
        /// back-edge, before `condition` is observed.
        test_prefix: Vec<RegionNode>,
        /// `None` for `Jump`-terminated headers (`loop { … }`); `Some`
        /// for `JumpIf`-terminated headers (`while … { … }`).
        condition: Option<LoopCondition>,
        escape_flag: Option<EscapeFlagSlot>,
        /// Body proper. Ends at the back-edge.
        body: Vec<RegionNode>,
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
pub(crate) struct LoopCondition {
    pub(crate) register: MemoryAddress,
    pub(crate) polarity: CondPolarity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CondPolarity {
    /// `JumpIf(cond, body_entry, exit)` — true continues the loop.
    ContinueOnTrue,
    /// `JumpIf(cond, exit, body_entry)` — true exits the loop.
    ExitOnTrue,
}

/// Synthetic RAM slot used to unify multi-exit loops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EscapeFlagSlot(pub(crate) usize);

/// Result of structuring a single Brillig function. Slot indices are
/// local to each body — slot 0 in `main` is distinct from slot 0 in any
/// procedure.
pub(crate) struct StructuredFunction {
    pub(crate) main: Vec<RegionNode>,
    pub(crate) main_escape_flag_count: usize,
    pub(crate) procedures: Vec<StructuredProcedure>,
}

pub(crate) struct StructuredProcedure {
    pub(crate) entry: BlockId,
    pub(crate) body: Vec<RegionNode>,
    pub(crate) escape_flag_count: usize,
}

impl StructuredFunction {
    pub(crate) fn body_of(&self, target: BlockId) -> Option<&[RegionNode]> {
        self.procedures
            .iter()
            .find(|p| p.entry == target)
            .map(|p| p.body.as_slice())
    }
}

pub(crate) fn structure_function(cfg: &Cfg) -> Result<StructuredFunction, Error> {
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
