use acir::brillig::{BitSize, MemoryAddress};
use acir::{AcirField, FieldElement};

use crate::error::Error;

use super::super::translator::{OpcodeAction, TranslationCtx};
use super::BrilligHandler;

pub(crate) struct ConstHandler<'a> {
    pub destination: MemoryAddress,
    pub bit_size: &'a BitSize,
    pub value: &'a FieldElement,
}

impl<'a> BrilligHandler<'a> for ConstHandler<'a> {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        _opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        if let BitSize::Integer(_) = self.bit_size
            && let Some(v) = self.value.try_into_u128()
        {
            ctx.memory.record_const(self.destination, v as usize);
        }
        let ssa = ctx.emit_const(self.bit_size, self.value)?;
        ctx.memory.write(self.destination, ssa);
        Ok(OpcodeAction::Continue)
    }
}
