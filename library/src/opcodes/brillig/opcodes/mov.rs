use acir::brillig::MemoryAddress;

use crate::error::Error;

use super::super::translator::{OpcodeAction, TranslationCtx};
use super::BrilligHandler;

pub(crate) struct MovHandler {
    pub destination: MemoryAddress,
    pub source: MemoryAddress,
}

impl BrilligHandler<'_> for MovHandler {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let src = ctx.memory.read(self.source, opcode_index)?;
        ctx.memory.write(self.destination, src);
        Ok(OpcodeAction::Continue)
    }
}
