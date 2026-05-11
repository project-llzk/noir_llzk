use acir::brillig::{IntegerBitSize, MemoryAddress};

use crate::error::Error;

use super::super::translator::TranslationCtx;
use super::BrilligHandler;
use crate::writer::Writer;

pub(super) struct NotHandler {
    pub destination: MemoryAddress,
    pub source: MemoryAddress,
    pub bit_size: IntegerBitSize,
}

impl BrilligHandler<'_> for NotHandler {
    fn execute(
        &self,
        ctx: &mut TranslationCtx<'_, '_, '_>,
        _opcode_index: usize,
    ) -> Result<(), Error> {
        // Brillig `Not` is n-bit complement, not felt-wide complement.
        // `felt.bit_not` would flip all bits of the prime's representation,
        // so we implement it as `src XOR (2^n - 1)` instead.
        let src = ctx.memory.read(ctx.writer, self.source)?;
        let mask_val = ctx.emit_mask_constant(self.bit_size)?;
        let result = ctx.writer.insert_felt_bit_xor(src, mask_val)?;
        ctx.memory.write(ctx.writer, self.destination, result)?;
        Ok(())
    }
}
