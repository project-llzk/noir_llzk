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
        // Later shape-sensitive opcodes need these registers statically known.
        if let BitSize::Integer(bs) = self.bit_size
            && matches!(bs, IntegerBitSize::U1 | IntegerBitSize::U32)
            && let Some(v) = self.value.try_to_u32()
        {
            ctx.memory.record_const(self.destination, v as usize)?;
        }
        Ok(OpcodeAction::Continue)
    }
}
