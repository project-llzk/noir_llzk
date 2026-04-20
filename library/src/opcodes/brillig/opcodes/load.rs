use acir::brillig::{BitSize, MemoryAddress};

use crate::error::Error;

use super::super::translator::{OpcodeAction, TranslationCtx};
use super::BrilligHandler;

pub(super) struct LoadHandler {
    pub destination: MemoryAddress,
    pub source_pointer: MemoryAddress,
}

impl BrilligHandler<'_> for LoadHandler {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let val = ctx
            .memory
            .read_dynamic_address(ctx.writer, self.source_pointer, opcode_index)?;
        ctx.memory
            .write_constant_address(ctx.writer, self.destination, val, BitSize::Field)?;
        Ok(OpcodeAction::Continue)
    }
}
