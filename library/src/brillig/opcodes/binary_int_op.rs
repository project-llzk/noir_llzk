use acir::brillig::{BinaryIntOp, IntegerBitSize, MemoryAddress};

use crate::error::Error;

use super::super::translator::TranslationCtx;
use super::BrilligHandler;

pub(super) struct BinaryIntOpHandler<'a> {
    pub destination: MemoryAddress,
    pub op: &'a BinaryIntOp,
    pub bit_size: IntegerBitSize,
    pub lhs: MemoryAddress,
    pub rhs: MemoryAddress,
}

impl<'a> BrilligHandler<'a> for BinaryIntOpHandler<'a> {
    fn execute(
        &self,
        ctx: &mut TranslationCtx<'_, '_, '_>,
        _opcode_index: usize,
    ) -> Result<(), Error> {
        let lhs_v = ctx.memory.read(ctx.writer, self.lhs)?;
        let rhs_v = ctx.memory.read(ctx.writer, self.rhs)?;
        let result = ctx.emit_binary_int_op(self.op, self.bit_size, lhs_v, rhs_v)?;
        ctx.memory.write(ctx.writer, self.destination, result)?;
        Ok(())
    }
}
