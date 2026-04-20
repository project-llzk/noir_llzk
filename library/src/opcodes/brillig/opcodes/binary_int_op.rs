use acir::brillig::{BinaryIntOp, BitSize, IntegerBitSize, MemoryAddress};

use crate::error::Error;

use super::super::translator::{OpcodeAction, TranslationCtx};
use super::BrilligHandler;

pub(super) struct BinaryIntOpHandler<'a> {
    pub destination: MemoryAddress,
    pub op: &'a BinaryIntOp,
    pub bit_size: IntegerBitSize,
    pub lhs: MemoryAddress,
    pub rhs: MemoryAddress,
}

impl<'a> BrilligHandler<'a> for BinaryIntOpHandler<'a> {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let expected = BitSize::Integer(self.bit_size);
        let expected_bits = u32::from(self.bit_size);
        let lhs_v = ctx
            .memory
            .read_constant_address(ctx.writer, self.lhs, expected)?;
        let rhs_v = ctx
            .memory
            .read_constant_address(ctx.writer, self.rhs, expected)?;
        ctx.check_int_width(lhs_v, expected_bits, opcode_index)?;
        ctx.check_int_width(rhs_v, expected_bits, opcode_index)?;
        let result = ctx.emit_binary_int_op(self.op, lhs_v, rhs_v)?;
        ctx.memory
            .write_constant_address(ctx.writer, self.destination, result, expected)?;
        Ok(OpcodeAction::Continue)
    }
}
