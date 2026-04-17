use acir::brillig::{BinaryIntOp, IntegerBitSize, MemoryAddress};

use crate::error::Error;

use super::super::translator::{OpcodeAction, TranslationCtx};
use super::BrilligHandler;

pub(crate) struct BinaryIntOpHandler<'a> {
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
        let lhs_v = ctx.regmap.get(self.lhs, opcode_index)?;
        let rhs_v = ctx.regmap.get(self.rhs, opcode_index)?;
        let expected_bits = u32::from(self.bit_size);
        ctx.check_int_width(lhs_v, expected_bits, opcode_index)?;
        ctx.check_int_width(rhs_v, expected_bits, opcode_index)?;
        let result = ctx.emit_binary_int_op(self.op, lhs_v, rhs_v)?;
        ctx.regmap.set(self.destination, result);
        Ok(OpcodeAction::Continue)
    }
}
