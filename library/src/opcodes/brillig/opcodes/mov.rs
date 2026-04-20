use acir::brillig::MemoryAddress;

use crate::error::Error;

use super::super::translator::{OpcodeAction, TranslationCtx};
use super::BrilligHandler;

pub(super) struct MovHandler {
    pub destination: MemoryAddress,
    pub source: MemoryAddress,
}

impl BrilligHandler<'_> for MovHandler {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let (src, bit_size) = ctx
            .memory
            .read_inferred(ctx.writer, self.source, opcode_index)?;
        ctx.memory
            .write_constant_address(ctx.writer, self.destination, src, bit_size)?;
        Ok(OpcodeAction::Continue)
    }
}
