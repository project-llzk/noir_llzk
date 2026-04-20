use acir::brillig::MemoryAddress;

use crate::error::Error;

use super::super::translator::{OpcodeAction, TranslationCtx};
use super::BrilligHandler;

pub(super) struct StoreHandler {
    pub destination_pointer: MemoryAddress,
    pub source: MemoryAddress,
}

impl BrilligHandler<'_> for StoreHandler {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let (val, _) = ctx
            .memory
            .read_inferred(ctx.writer, self.source, opcode_index)?;
        ctx.memory.write_dynamic_address(
            ctx.writer,
            self.destination_pointer,
            val,
            opcode_index,
        )?;
        Ok(OpcodeAction::Continue)
    }
}
