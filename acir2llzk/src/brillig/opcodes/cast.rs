use acir::brillig::{BitSize, MemoryAddress};

use crate::error::Error;

use super::super::translator::TranslationCtx;
use super::BrilligHandler;

pub(super) struct CastHandler<'a> {
    pub destination: MemoryAddress,
    pub source: MemoryAddress,
    pub bit_size: &'a BitSize,
}

impl<'a> BrilligHandler<'a> for CastHandler<'a> {
    fn execute(
        &self,
        ctx: &mut TranslationCtx<'_, '_, '_>,
        _opcode_index: usize,
    ) -> Result<(), Error> {
        let src = ctx.writer.insert_read(self.source)?;
        let casted = ctx.emit_cast(src, self.bit_size)?;
        ctx.writer.insert_write(self.destination, casted)?;
        Ok(())
    }
}
