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
        opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let num_bits = u32::from(self.bit_size);
        let int_ty = ctx.writer.integer_type(num_bits);
        let src = ctx
            .memory
            .read(ctx.writer, self.source, int_ty, opcode_index)?;
        let mask = if num_bits >= 128 {
            u128::MAX
        } else {
            (1u128 << num_bits) - 1
        };
        let all_ones = ctx.writer.insert_arith_int_constant(num_bits, mask)?;
        let result = ctx.writer.insert_arith_xori(src, all_ones)?;
        ctx.memory.write(ctx.writer, self.destination, result)?;
        Ok(OpcodeAction::Continue)
    }
}
