use std::collections::BTreeSet;

use acir::{FieldElement, native_types::Expression};
use llzk::prelude::Value;

use crate::{
    block_writer::BlockWriter,
    common::{collect_witnesses, emit_expression},
    error::Error,
    opcodes::{OpcodeEmitter, memory_ops::selectors::EmitSelectors},
    writer::Writer as _,
};

use super::selectors::{emit_selectors_compute, emit_selectors_constrain};
use super::uninit_error;

/// Translates an ACIR `MemoryOp` with `operation=1` (write).
///
/// In both `@compute` and `@constrain`: evaluates the index and value, then
/// applies the selector-mux write gadget.
pub(crate) struct MemoryWrite<'p> {
    pub(super) block_id: u32,
    pub(super) index: &'p Expression<FieldElement>,
    pub(super) value: &'p Expression<FieldElement>,
}

impl<'p> OpcodeEmitter for MemoryWrite<'p> {
    fn get_witnesses(&self) -> BTreeSet<u32> {
        let mut witnesses = collect_witnesses(self.index);
        witnesses.extend(collect_witnesses(self.value));
        witnesses
    }

    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        emit_array_write(
            writer,
            emit_selectors_compute,
            self.block_id,
            self.index,
            self.value,
        )
    }

    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        emit_array_write(
            writer,
            emit_selectors_constrain,
            self.block_id,
            self.index,
            self.value,
        )
    }
}

/// Evaluates index and value, then dispatches to the selector-mux write gadget.
fn emit_array_write<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    emit_selectors: EmitSelectors<'c, 'b>,
    block_id: u32,
    index: &Expression<FieldElement>,
    value: &Expression<FieldElement>,
) -> Result<(), Error> {
    let idx_felt = emit_expression(writer, index)?;
    let val = emit_expression(writer, value)?;
    let arr = writer
        .get_memory(block_id)
        .ok_or_else(|| uninit_error(block_id))?;
    let len = writer.array_len(arr)?;
    emit_select_write(writer, emit_selectors, arr, idx_felt, val, len)
}

/// Emits a sound dynamic-index write: for each slot j, replaces `arr[j]` with
/// `arr[j] + s_j * (val - arr[j])` (i.e. `val` when `s_j = 1`, unchanged when 0).
pub(super) fn emit_select_write<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    emit_selectors: EmitSelectors<'c, 'b>,
    arr: Value<'c, 'b>,
    idx_felt: Value<'c, 'b>,
    val: Value<'c, 'b>,
    len: usize,
) -> Result<(), Error> {
    let selectors = emit_selectors(writer, idx_felt, len)?;
    for (j, &s_j) in selectors.iter().enumerate() {
        let j_idx = writer.insert_integer(j)?;
        // This array read is safe, because we call with constant
        let old = writer.insert_array_read(arr, j_idx)?;
        let neg_old = writer.insert_neg(old)?;
        let diff = writer.insert_add(val, neg_old)?;
        let scaled = writer.insert_mul(s_j, diff)?;
        let new = writer.insert_add(old, scaled)?;
        writer.insert_array_write(arr, &[j_idx], new);
    }
    Ok(())
}
