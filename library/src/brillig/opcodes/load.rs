use acir::brillig::MemoryAddress;

use crate::error::Error;

use super::super::translator::TranslationCtx;
use super::BrilligHandler;

pub(super) struct LoadHandler {
    pub destination: MemoryAddress,
    pub source_pointer: MemoryAddress,
}

impl BrilligHandler<'_> for LoadHandler {
    fn execute(
        &self,
        ctx: &mut TranslationCtx<'_, '_, '_>,
        _opcode_index: usize,
    ) -> Result<(), Error> {
        let val = ctx.writer.insert_dynamic_read(self.source_pointer)?;
        ctx.writer.insert_write(self.destination, val)?;
        Ok(())
    }
}
