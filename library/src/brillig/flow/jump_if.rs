use acir::brillig::{Label, MemoryAddress};

use crate::error::Error;

use super::super::cfg::Terminator;
use super::{ClassifyCtx, FlowHandler, lookup};

pub(super) struct JumpIfHandler {
    pub condition: MemoryAddress,
    pub location: Label,
}

impl FlowHandler for JumpIfHandler {
    fn target(&self) -> Option<Label> {
        Some(self.location)
    }

    fn to_terminator(&self, ctx: &ClassifyCtx<'_>) -> Result<Terminator, Error> {
        let then_block = lookup(ctx.index_to_block, self.location)?;
        let else_index = ctx.last_idx + 1;
        if else_index >= ctx.bytecode_len {
            return Err(Error::UnsupportedBrillig {
                reason: format!(
                    "`JumpIf` at index {} is the last bytecode opcode; \
                     fall-through target is out of range",
                    ctx.last_idx
                ),
            });
        }
        let else_block = lookup(ctx.index_to_block, else_index)?;
        Ok(Terminator::JumpIf {
            condition: self.condition,
            then_block,
            else_block,
        })
    }
}
