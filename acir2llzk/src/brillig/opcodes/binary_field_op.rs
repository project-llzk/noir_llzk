use acir::brillig::{BinaryFieldOp, MemoryAddress};

use crate::error::Error;

use super::super::translator::TranslationCtx;
use super::BrilligHandler;

pub(super) struct BinaryFieldOpHandler<'a> {
    pub destination: MemoryAddress,
    pub op: &'a BinaryFieldOp,
    pub lhs: MemoryAddress,
    pub rhs: MemoryAddress,
}

impl<'a> BrilligHandler<'a> for BinaryFieldOpHandler<'a> {
    fn execute(
        &self,
        ctx: &mut TranslationCtx<'_, '_, '_>,
        _opcode_index: usize,
    ) -> Result<(), Error> {
        let lhs_v = ctx.writer.insert_read(self.lhs)?;
        let rhs_v = ctx.writer.insert_read(self.rhs)?;
        let result = ctx.emit_binary_field_op(self.op, lhs_v, rhs_v)?;
        ctx.writer.insert_write(self.destination, result)?;
        Ok(())
    }
}
