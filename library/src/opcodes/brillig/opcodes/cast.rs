use acir::brillig::{BitSize, MemoryAddress};

use crate::error::Error;

use super::super::translator::{OpcodeAction, TranslationCtx};
use super::BrilligHandler;

pub(super) struct CastHandler<'a> {
    pub destination: MemoryAddress,
    pub source: MemoryAddress,
    pub bit_size: &'a BitSize,
}

impl<'a> BrilligHandler<'a> for CastHandler<'a> {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let src = ctx
            .memory
            .read_inferred(ctx.writer, self.source, opcode_index)?;
        let casted = ctx.emit_cast(src, self.bit_size)?;
        ctx.memory.write(ctx.writer, self.destination, casted)?;
        Ok(OpcodeAction::Continue)
    }
}
