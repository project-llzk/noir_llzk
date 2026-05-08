use acir::FieldElement;
use acir::brillig::MemoryAddress;
use llzk::prelude::ValueLike;

use crate::error::Error;

use super::super::memory::Memory;
use super::super::translator::TranslationCtx;
use super::BrilligHandler;

/// `dst = cond > 0 ? source_a : source_b`, lowered as `scf.if` with
/// single-value yield regions. The Brillig VM requires `cond` to be a u1,
/// but we express the truthy check as `cond > 0` (via `bool.cmp gt`) so
/// that any nonzero felt selects `source_a`.
pub(super) struct ConditionalMovHandler {
    pub destination: MemoryAddress,
    pub source_a: MemoryAddress,
    pub source_b: MemoryAddress,
    pub condition: MemoryAddress,
}

impl<M: Memory> BrilligHandler<'_, M> for ConditionalMovHandler {
    fn execute(
        &self,
        ctx: &mut TranslationCtx<'_, '_, '_, M>,
        _opcode_index: usize,
    ) -> Result<(), Error> {
        let a = ctx.memory.read(ctx.writer, self.source_a)?;
        let b = ctx.memory.read(ctx.writer, self.source_b)?;
        let cond = ctx.memory.read(ctx.writer, self.condition)?;

        let zero = ctx.writer.emit_constant(&FieldElement::from(0u128))?;
        let cond_i1 = ctx.writer.insert_bool_gt(cond, zero)?;

        let result = ctx.writer.insert_scf_if_select(cond_i1, a, b, a.r#type())?;

        ctx.memory.write(ctx.writer, self.destination, result)?;
        Ok(())
    }
}
