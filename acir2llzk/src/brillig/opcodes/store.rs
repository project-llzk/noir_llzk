use acir::brillig::MemoryAddress;

use crate::error::Error;

use super::super::translator::TranslationCtx;
use super::BrilligHandler;

pub(super) struct StoreHandler {
    pub destination_pointer: MemoryAddress,
    pub source: MemoryAddress,
}

impl BrilligHandler<'_> for StoreHandler {
    fn execute(
        &self,
        ctx: &mut TranslationCtx<'_, '_, '_>,
        _opcode_index: usize,
    ) -> Result<(), Error> {
        let val = ctx.writer.insert_read(self.source)?;
        ctx.writer
            .insert_dynamic_write(self.destination_pointer, val)?;
        Ok(())
    }
}
