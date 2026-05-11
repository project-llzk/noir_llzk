use acir::FieldElement;
use acir::brillig::MemoryAddress;
use llzk::prelude::ValueLike;

use crate::error::Error;

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

impl BrilligHandler<'_> for ConditionalMovHandler {
    fn execute(
        &self,
        ctx: &mut TranslationCtx<'_, '_, '_>,
        _opcode_index: usize,
    ) -> Result<(), Error> {
        let a = ctx.writer.insert_read(self.source_a)?;
        let b = ctx.writer.insert_read(self.source_b)?;
        let cond = ctx.writer.insert_read(self.condition)?;

        let zero = ctx.writer.emit_constant(&FieldElement::from(0u128))?;
        let cond_i1 = ctx.writer.insert_bool_gt(cond, zero)?;

        let result = ctx.writer.insert_scf_if_select(cond_i1, a, b, a.r#type())?;

        ctx.writer.insert_write(self.destination, result)?;
        Ok(())
    }
}
