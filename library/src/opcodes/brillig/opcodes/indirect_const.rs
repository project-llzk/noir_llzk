use acir::FieldElement;
use acir::brillig::MemoryAddress;

use crate::error::Error;

use super::super::translator::{OpcodeAction, TranslationCtx};
use super::BrilligHandler;

pub(super) struct IndirectConstHandler<'a> {
    pub destination_pointer: MemoryAddress,
    pub value: &'a FieldElement,
}

impl<'a> BrilligHandler<'a> for IndirectConstHandler<'a> {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        _opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let ssa = ctx.emit_const(self.value)?;
        ctx.memory
            .write_dynamic(ctx.writer, self.destination_pointer, ssa)?;
        Ok(OpcodeAction::Continue)
    }
}
