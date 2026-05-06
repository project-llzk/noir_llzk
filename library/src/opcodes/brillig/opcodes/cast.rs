use acir::brillig::{BitSize, MemoryAddress};

use crate::error::Error;

use super::super::memory::Memory;
use super::super::translator::TranslationCtx;
use super::BrilligHandler;

pub(super) struct CastHandler<'a> {
    pub destination: MemoryAddress,
    pub source: MemoryAddress,
    pub bit_size: &'a BitSize,
}

impl<'a, M: Memory> BrilligHandler<'a, M> for CastHandler<'a> {
    fn execute(
        &self,
        ctx: &mut TranslationCtx<'_, '_, '_, M>,
        _opcode_index: usize,
    ) -> Result<(), Error> {
        let src = ctx.memory.read(ctx.writer, self.source)?;
        let casted = ctx.emit_cast(src, self.bit_size)?;
        ctx.memory.write(ctx.writer, self.destination, casted)?;
        Ok(())
    }
}
