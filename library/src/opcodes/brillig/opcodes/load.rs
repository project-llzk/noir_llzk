use acir::brillig::MemoryAddress;

use crate::error::Error;

use super::super::memory::Memory;
use super::super::translator::TranslationCtx;
use super::BrilligHandler;

pub(super) struct LoadHandler {
    pub destination: MemoryAddress,
    pub source_pointer: MemoryAddress,
}

impl<M: Memory> BrilligHandler<'_, M> for LoadHandler {
    fn execute(
        &self,
        ctx: &mut TranslationCtx<'_, '_, '_, M>,
        _opcode_index: usize,
    ) -> Result<(), Error> {
        let val = ctx.memory.read_dynamic(ctx.writer, self.source_pointer)?;
        ctx.memory.write(ctx.writer, self.destination, val)?;
        Ok(())
    }
}
