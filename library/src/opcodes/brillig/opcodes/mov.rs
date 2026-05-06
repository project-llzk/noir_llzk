use acir::brillig::MemoryAddress;

use crate::error::Error;

use super::super::memory::Memory;
use super::super::translator::TranslationCtx;
use super::BrilligHandler;

pub(super) struct MovHandler {
    pub destination: MemoryAddress,
    pub source: MemoryAddress,
}

impl<M: Memory> BrilligHandler<'_, M> for MovHandler {
    fn execute(
        &self,
        ctx: &mut TranslationCtx<'_, '_, '_, M>,
        _opcode_index: usize,
    ) -> Result<(), Error> {
        let src = ctx.memory.read(ctx.writer, self.source)?;
        ctx.memory.write(ctx.writer, self.destination, src)?;
        Ok(())
    }
}
