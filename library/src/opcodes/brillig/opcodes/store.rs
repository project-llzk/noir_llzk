use acir::brillig::MemoryAddress;

use crate::error::Error;

use super::super::memory::Memory;
use super::super::translator::TranslationCtx;
use super::BrilligHandler;

pub(super) struct StoreHandler {
    pub destination_pointer: MemoryAddress,
    pub source: MemoryAddress,
}

impl<M: Memory> BrilligHandler<'_, M> for StoreHandler {
    fn execute(
        &self,
        ctx: &mut TranslationCtx<'_, '_, '_, M>,
        _opcode_index: usize,
    ) -> Result<(), Error> {
        let val = ctx.memory.read(ctx.writer, self.source)?;
        ctx.memory
            .write_dynamic(ctx.writer, self.destination_pointer, val)?;
        Ok(())
    }
}
