use acir::brillig::{BitSize, IntegerBitSize, MemoryAddress};
use acir::{AcirField, FieldElement};

use crate::error::Error;

use super::super::translator::{OpcodeAction, TranslationCtx};
use super::BrilligHandler;

pub(super) struct ConstHandler<'a> {
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
        let ssa = ctx.emit_const(self.value)?;
        // `write` clears any stale integer-constant tracking for this slot;
        // `record_const` then re-establishes it with the fresh value.
        ctx.memory.write(ctx.writer, self.destination, ssa)?;
        // Noir emits pointers and lengths as U32 (BRILLIG_MEMORY_ADDRESSING_BIT_SIZE),
        // and those are the only values any `get_const` consumer uses.
        if let BitSize::Integer(IntegerBitSize::U32) = self.bit_size
            && let Some(v) = self.value.try_into_u128()
        {
            ctx.memory.record_const(self.destination, v as usize)?;
        }
        Ok(OpcodeAction::Continue)
    }
}
