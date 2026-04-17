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
        let ptr = ctx
            .memory
            .read_inferred(ctx.writer, self.destination_pointer, opcode_index)?;
        let ptr_idx = ctx.cast_to_index(ptr)?;
        let val = ctx
            .memory
            .read_inferred(ctx.writer, self.source, opcode_index)?;
        ctx.writer.insert_ram_store(ptr_idx, val);
        Ok(OpcodeAction::Continue)
    }
}
