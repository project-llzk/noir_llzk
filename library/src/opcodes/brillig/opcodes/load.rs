use acir::brillig::MemoryAddress;

use crate::error::Error;

use super::super::translator::{OpcodeAction, TranslationCtx};
use super::BrilligHandler;

pub(crate) struct LoadHandler {
    pub destination: MemoryAddress,
    pub source_pointer: MemoryAddress,
}

impl BrilligHandler<'_> for LoadHandler {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let ptr = ctx.regmap.get(self.source_pointer, opcode_index)?;
        let ptr_idx = ctx.cast_to_index(ptr)?;
        let felt_ty = ctx.writer.felt_type();
        let val = ctx.writer.insert_ram_load(ptr_idx, felt_ty)?;
        ctx.regmap.set(self.destination, val);
        Ok(OpcodeAction::Continue)
    }
}
