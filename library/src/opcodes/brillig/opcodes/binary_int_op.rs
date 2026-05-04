use acir::brillig::{BinaryIntOp, IntegerBitSize, MemoryAddress};
use brillig_vm::STACK_POINTER_ADDRESS;

use crate::error::Error;

use super::super::memory::Memory;
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

        // Compute any SP fold before `write` invalidates the current SP.
        let new_sp = self.try_fold_sp_prologue(&ctx.memory)?;
        ctx.memory.write(ctx.writer, self.destination, result)?;
        if let Some(sp) = new_sp {
            ctx.memory.set_sp(sp);
        }

        Ok(())
    }
}

impl<'a> BinaryIntOpHandler<'a> {
    /// Detects the Brillig prologue pattern `Add(slot0, slot0, <const>)` and
    /// returns the folded stack pointer. Noir's call-frame codegen updates SP
    /// via this exact shape rather than a `Const` write; without folding it,
    /// callee `Relative(_)` accesses would resolve against the caller's SP.
    fn try_fold_sp_prologue(&self, memory: &Memory) -> Result<Option<usize>, Error> {
        if !matches!(self.op, BinaryIntOp::Add)
            || self.destination != STACK_POINTER_ADDRESS
            || self.lhs != STACK_POINTER_ADDRESS
        {
            return Ok(None);
        }
        let Some(old_sp) = memory.get_const(STACK_POINTER_ADDRESS)? else {
            return Ok(None);
        };
        let Some(rhs_const) = memory.get_const(self.rhs)? else {
            return Ok(None);
        };
        Ok(Some(old_sp + rhs_const))
    }
}
