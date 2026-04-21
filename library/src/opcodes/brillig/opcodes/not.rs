use acir::FieldElement;
use acir::brillig::{IntegerBitSize, MemoryAddress};

use crate::error::Error;

use super::super::translator::{OpcodeAction, TranslationCtx};
use super::BrilligHandler;

pub(super) struct NotHandler {
    pub destination: MemoryAddress,
    pub source: MemoryAddress,
    pub bit_size: IntegerBitSize,
}

impl BrilligHandler<'_> for NotHandler {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        _opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        // Brillig `Not` is n-bit complement, not felt-wide complement.
        // `felt.bit_not` would flip all bits of the prime's representation,
        // so we implement it as `src XOR (2^n - 1)` instead.
        let src = ctx.memory.read(ctx.writer, self.source)?;
        let n = u32::from(self.bit_size);
        let mask = if n >= 128 {
            u128::MAX
        } else {
            (1u128 << n) - 1
        };
        let mask_val = ctx.writer.emit_constant(&FieldElement::from(mask))?;
        let result = ctx.writer.insert_felt_bit_xor(src, mask_val)?;
        ctx.memory.write(ctx.writer, self.destination, result)?;
        Ok(OpcodeAction::Continue)
    }
}
