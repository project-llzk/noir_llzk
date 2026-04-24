//! Per-opcode handlers for Brillig control-flow (terminator) opcodes.
//!
//! Mirrors the [`super::opcodes`] pattern: each control-flow `BrilligOpcode`
//! variant (`Jump`, `JumpIf`, `Call`, `Return`, `Stop`, `Trap`) has its own
//! module holding a handler struct that captures the variant's fields and
//! implements [`FlowHandler`]. The dispatch function [`build_handler`] boxes
//! the right handler for an opcode, returning `None` for non-terminator
//! opcodes so the caller can split body-vs-terminator dispatch.
//!
//! Today these handlers drive Phase 2 CFG recovery (classification only).
//! Phase 3 will extend [`FlowHandler`] with an `execute` method for
//! control-flow emission, keyed off the same per-variant handler types.

use std::collections::HashMap;

use acir::FieldElement;
use acir::brillig::{Label, Opcode as B};

use crate::error::Error;

use super::cfg::{BlockId, Terminator};

mod call;
mod jump;
mod jump_if;
mod return_op;
mod stop;
mod trap;

use self::call::CallHandler;
use self::jump::JumpHandler;
use self::jump_if::JumpIfHandler;
use self::return_op::ReturnHandler;
use self::stop::StopHandler;
use self::trap::TrapHandler;


/// Lookup context for resolving bytecode labels to [`BlockId`]s when
/// materializing a [`Terminator`].
pub(super) struct ClassifyCtx<'a> {
    pub index_to_block: &'a HashMap<Label, BlockId>,
    /// Bytecode index of the terminator opcode being classified.
    pub last_idx: Label,
    pub bytecode_len: usize,
}

/// Trait implemented by each control-flow opcode handler.
pub(super) trait FlowHandler {
    /// Branch target label, if any. `None` for `Return` / `Stop` / `Trap`.
    /// Used by the block splitter to find block-entry points.
    fn target(&self) -> Option<Label>;

    /// Materialize the block's [`Terminator`], resolving labels to
    /// [`BlockId`]s via `ctx`.
    fn to_terminator(&self, ctx: &ClassifyCtx<'_>) -> Result<Terminator, Error>;
}

/// Returns a boxed [`FlowHandler`] if `op` is a terminator opcode, else
/// `None`. Mirrors [`super::opcodes::build_handler`] but with `Option`
/// semantics: `None` signals "not a terminator," not an error.
pub(super) fn build_handler(op: &B<FieldElement>) -> Option<Box<dyn FlowHandler>> {
    match op {
        B::Jump { location } => Some(Box::new(JumpHandler {
            location: *location,
        })),
        B::JumpIf {
            condition,
            location,
        } => Some(Box::new(JumpIfHandler {
            condition: *condition,
            location: *location,
        })),
        B::Call { location } => Some(Box::new(CallHandler {
            location: *location,
        })),
        B::Return => Some(Box::new(ReturnHandler)),
        B::Stop { .. } => Some(Box::new(StopHandler)),
        B::Trap { .. } => Some(Box::new(TrapHandler)),
        _ => None,
    }
}

/// Resolves a bytecode index to its [`BlockId`]. Errors with
/// `UnsupportedBrillig` if the index is not a block entry.
fn lookup(map: &HashMap<Label, BlockId>, index: Label) -> Result<BlockId, Error> {
    map.get(&index)
        .copied()
        .ok_or_else(|| Error::UnsupportedBrillig {
            reason: format!(
                "Brillig branch targets bytecode index {index} which is not a block entry"
            ),
        })
}
