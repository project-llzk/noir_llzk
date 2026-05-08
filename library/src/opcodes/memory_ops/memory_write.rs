use std::collections::BTreeSet;

use acir::{FieldElement, native_types::Expression};

use crate::{
    block_writer::BlockWriter,
    common::{collect_witnesses, emit_expression},
    error::Error,
    opcodes::OpcodeEmitter,
};

use super::uninit_error;
use crate::writer::Writer;

/// Translates an ACIR `MemoryOp` with `operation=1` (write).
///
/// In both `@compute` and `@constrain`: evaluates the index and value, then
/// applies `array.write arr[index] = value` in-place to the live array so
/// that subsequent reads see the updated state.
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
        emit_array_write(writer, self.block_id, self.index, self.value)
    }

    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        emit_array_write(writer, self.block_id, self.index, self.value)
    }
}

/// Evaluates index and value, then applies `array.write arr[index] = value` in-place.
fn emit_array_write<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    block_id: u32,
    index: &Expression<FieldElement>,
    value: &Expression<FieldElement>,
) -> Result<(), Error> {
    let idx_felt = emit_expression(writer, index)?;
    let idx = writer.insert_cast_to_index(idx_felt)?;
    let val = emit_expression(writer, value)?;
    let arr = writer
        .get_memory(block_id)
        .ok_or_else(|| uninit_error(block_id))?;
    writer.insert_array_write(arr, &[idx], val);
    Ok(())
}
