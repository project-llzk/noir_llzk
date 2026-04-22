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
        _opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let val = ctx.memory.read(ctx.writer, self.source)?;
        ctx.memory
            .write_dynamic(ctx.writer, self.destination_pointer, val)?;
        Ok(OpcodeAction::Continue)
    }
}
