use acir::brillig::{BinaryFieldOp, MemoryAddress};

use crate::error::Error;

use super::super::memory::Memory;
use super::super::translator::TranslationCtx;
use super::BrilligHandler;

pub(super) struct BinaryFieldOpHandler<'a> {
    pub destination: MemoryAddress,
    pub op: &'a BinaryFieldOp,
    pub lhs: MemoryAddress,
    pub rhs: MemoryAddress,
}

impl<'a, M: Memory> BrilligHandler<'a, M> for BinaryFieldOpHandler<'a> {
    fn execute(
        &self,
        ctx: &mut TranslationCtx<'_, '_, '_, M>,
        _opcode_index: usize,
    ) -> Result<(), Error> {
        let lhs_v = ctx.memory.read(ctx.writer, self.lhs)?;
        let rhs_v = ctx.memory.read(ctx.writer, self.rhs)?;
        let result = ctx.emit_binary_field_op(self.op, lhs_v, rhs_v)?;
        ctx.memory.write(ctx.writer, self.destination, result)?;
        Ok(())
    }
}
