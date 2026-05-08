use acir::brillig::Label;

use crate::error::Error;

use super::super::cfg::Terminator;
use super::{ClassifyCtx, FlowHandler, lookup};

pub(super) struct CallHandler {
    pub location: Label,
}

impl FlowHandler for CallHandler {
    fn target(&self) -> Option<Label> {
        Some(self.location)
    }

    fn to_terminator(&self, ctx: &ClassifyCtx<'_>) -> Result<Terminator, Error> {
        let target = lookup(ctx.index_to_block, self.location)?;
        let continuation_idx = ctx.last_idx + 1;
        if continuation_idx >= ctx.bytecode_len {
            return Err(Error::UnsupportedBrillig {
                reason: format!(
                    "`Call` at index {} is the last bytecode opcode; \
                     continuation is out of range (Noir always emits SP restore \
                     and return-copy opcodes after `Call`)",
                    ctx.last_idx
                ),
            });
        }
        let continuation = lookup(ctx.index_to_block, continuation_idx)?;
        Ok(Terminator::Call {
            target,
            continuation,
        })
    }
}
