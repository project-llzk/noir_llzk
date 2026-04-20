use acir::brillig::{BinaryFieldOp, BitSize, MemoryAddress};

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
        _opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let lhs_v = ctx
            .memory
            .read_constant_address(ctx.writer, self.lhs, BitSize::Field)?;
        let rhs_v = ctx
            .memory
            .read_constant_address(ctx.writer, self.rhs, BitSize::Field)?;
        let result = ctx.emit_binary_field_op(self.op, lhs_v, rhs_v)?;
        ctx.memory
            .write_constant_address(ctx.writer, self.destination, result, BitSize::Field)?;
        Ok(OpcodeAction::Continue)
    }
}
