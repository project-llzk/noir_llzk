use acir::brillig::{BitSize, IntegerBitSize, MemoryAddress};

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
        let expected = BitSize::Integer(self.bit_size);
        let num_bits = u32::from(self.bit_size);
        let src = ctx
            .memory
            .read_constant_address(ctx.writer, self.source, expected)?;
        let mask = if num_bits >= 128 {
            u128::MAX
        } else {
            (1u128 << num_bits) - 1
        };
        let all_ones = ctx.writer.insert_arith_int_constant(num_bits, mask)?;
        let result = ctx.writer.insert_arith_xori(src, all_ones)?;
        ctx.memory
            .write_constant_address(ctx.writer, self.destination, result, expected)?;
        Ok(OpcodeAction::Continue)
    }
}
