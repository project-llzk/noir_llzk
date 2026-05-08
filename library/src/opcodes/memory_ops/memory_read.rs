use std::collections::BTreeSet;

use acir::{FieldElement, native_types::Expression};

use llzk::prelude::Value;

use crate::{
    block_writer::BlockWriter,
    common::{collect_witnesses, emit_expression},
    error::Error,
    opcodes::OpcodeEmitter,
};

use super::uninit_error;
use crate::writer::Writer;
/// Translates an ACIR `MemoryOp` with `operation=0` (read).
///
/// In `@compute`: evaluates the index, reads `arr[index]` from the live array,
/// stores the result to `@w{value_witness}`, and marks the witness as known.
///
/// In `@constrain`: re-evaluates the index, reads `arr[index]` from the
/// rebuilt array, and emits `constrain.eq stored_value, read_result`.
pub(crate) struct MemoryRead<'p> {
    pub(super) block_id: u32,
    pub(super) index: &'p Expression<FieldElement>,
    pub(super) value_witness: u32,
}

impl<'p> OpcodeEmitter for MemoryRead<'p> {
    fn get_witnesses(&self) -> BTreeSet<u32> {
        let mut witnesses = collect_witnesses(self.index);
        witnesses.insert(self.value_witness);
        witnesses
    }

    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let result = self.emit_array_read(writer)?;
        writer.write_member(&format!("w{}", self.value_witness), result)?;
        writer.mark_known(self.value_witness, result);
        Ok(())
    }

    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let expected = self.emit_array_read(writer)?;
        let stored = writer.read_witness(self.value_witness)?;
        writer.insert_constrain_eq(stored, expected);
        Ok(())
    }
}

impl<'p> MemoryRead<'p> {
    /// Evaluates the index expression, looks up the memory array, and reads the element.
    fn emit_array_read<'c, 'b>(
        &self,
        writer: &mut BlockWriter<'c, 'b>,
    ) -> Result<Value<'c, 'b>, Error> {
        let idx_felt = emit_expression(writer, self.index)?;
        let idx = writer.insert_cast_to_index(idx_felt)?;
        let arr = writer
            .get_memory(self.block_id)
            .ok_or_else(|| uninit_error(self.block_id))?;
        writer.insert_array_read(arr, idx)
    }
}
