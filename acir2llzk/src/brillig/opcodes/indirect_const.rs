use acir::FieldElement;
use acir::brillig::MemoryAddress;

use crate::error::Error;

use super::super::translator::TranslationCtx;
use super::BrilligHandler;

pub(super) struct IndirectConstHandler<'a> {
    pub destination_pointer: MemoryAddress,
    pub value: &'a FieldElement,
}

impl<'a> BrilligHandler<'a> for IndirectConstHandler<'a> {
    fn execute(
        &self,
        ctx: &mut TranslationCtx<'_, '_, '_>,
        _opcode_index: usize,
    ) -> Result<(), Error> {
        let ssa = ctx.emit_const(self.value)?;
        ctx.writer
            .insert_dynamic_write(self.destination_pointer, ssa)?;
        Ok(())
    }
}
