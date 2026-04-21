use acir::brillig::MemoryAddress;

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
        _opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let val = ctx.memory.read_dynamic(ctx.writer, self.source_pointer)?;
        ctx.memory.write(ctx.writer, self.destination, val)?;
        Ok(OpcodeAction::Continue)
    }
}
