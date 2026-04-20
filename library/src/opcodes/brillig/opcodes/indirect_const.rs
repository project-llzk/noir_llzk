use acir::FieldElement;
use acir::brillig::{BitSize, MemoryAddress};

use crate::error::Error;

use super::super::translator::{OpcodeAction, TranslationCtx};
use super::BrilligHandler;

pub(super) struct IndirectConstHandler<'a> {
    pub destination_pointer: MemoryAddress,
    pub bit_size: &'a BitSize,
    pub value: &'a FieldElement,
}

impl<'a> BrilligHandler<'a> for IndirectConstHandler<'a> {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let ssa = ctx.emit_const(self.bit_size, self.value)?;
        ctx.memory.write_dynamic_address(
            ctx.writer,
            self.destination_pointer,
            ssa,
            opcode_index,
        )?;
        Ok(OpcodeAction::Continue)
    }
}
