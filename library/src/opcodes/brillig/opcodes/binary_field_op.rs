use acir::brillig::{BinaryFieldOp, MemoryAddress};

use crate::error::Error;

use super::super::translator::{OpcodeAction, TranslationCtx};
use super::BrilligHandler;

pub(super) struct BinaryFieldOpHandler<'a> {
    pub destination: MemoryAddress,
    pub op: &'a BinaryFieldOp,
    pub lhs: MemoryAddress,
    pub rhs: MemoryAddress,
}

impl<'a> BrilligHandler<'a> for BinaryFieldOpHandler<'a> {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let felt_ty = ctx.writer.felt_type();
        let lhs_v = ctx
            .memory
            .read(ctx.writer, self.lhs, felt_ty, opcode_index)?;
        let rhs_v = ctx
            .memory
            .read(ctx.writer, self.rhs, felt_ty, opcode_index)?;
        let result = ctx.emit_binary_field_op(self.op, lhs_v, rhs_v)?;
        ctx.memory.write(ctx.writer, self.destination, result)?;
        Ok(OpcodeAction::Continue)
    }
}
