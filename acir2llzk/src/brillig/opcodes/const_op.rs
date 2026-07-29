use acir::FieldElement;
use acir::brillig::MemoryAddress;

use crate::error::Error;

use super::super::translator::TranslationCtx;
use super::BrilligHandler;

pub(super) struct ConstHandler<'a> {
    pub destination: MemoryAddress,
    pub value: &'a FieldElement,
}

impl<'a> BrilligHandler<'a> for ConstHandler<'a> {
    fn execute(
        &self,
        ctx: &mut TranslationCtx<'_, '_, '_>,
        _opcode_index: usize,
    ) -> Result<(), Error> {
        let ssa = ctx.emit_const(self.value)?;
        ctx.writer.insert_write(self.destination, ssa)?;
        Ok(())
    }
}
