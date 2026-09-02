use acir::brillig::MemoryAddress;

use crate::error::Error;

use super::super::translator::TranslationCtx;
use super::BrilligHandler;

pub(super) struct MovHandler {
    pub destination: MemoryAddress,
    pub source: MemoryAddress,
}

impl BrilligHandler<'_> for MovHandler {
    fn execute(
        &self,
        ctx: &mut TranslationCtx<'_, '_, '_>,
        _opcode_index: usize,
    ) -> Result<(), Error> {
        let src = ctx.writer.insert_read(self.source)?;
        ctx.writer.insert_write(self.destination, src)?;
        Ok(())
    }
}
