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
/// Translates an ACIR `MemoryOp` with `operation=0` (read).
///
/// In `@compute`: evaluates the index, materialises `arr[index]` via the
/// linear-scan mux gadget, stores the result to `@w{value_witness}`, and
/// marks the witness as known.
///
/// In `@constrain`: re-evaluates the index, materialises `arr[index]` via
/// the same gadget (with nondet selectors pinned by field-native soundness
/// constraints), and emits `constrain.eq stored_value, read_result`.
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
        let result = self.emit_array_read(writer, emit_selectors_compute)?;
        writer.write_member(&format!("w{}", self.value_witness), result)?;
        writer.mark_known(self.value_witness, result);
        Ok(())
    }

    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let expected = self.emit_array_read(writer, emit_selectors_constrain)?;
        let stored = writer.read_witness(self.value_witness)?;
        writer.insert_constrain_eq(stored, expected);
        Ok(())
    }
}

impl<'p> MemoryRead<'p> {
    /// Evaluates the index expression and dispatches to the selector-mux
    /// read gadget so the emitted `array.read` ops all carry constant indices.
    fn emit_array_read<'c, 'b>(
        &self,
        writer: &mut BlockWriter<'c, 'b>,
        emit_selectors: EmitSelectors<'c, 'b>,
    ) -> Result<Value<'c, 'b>, Error> {
        let idx_felt = emit_expression(writer, self.index)?;
        let arr = writer
            .get_memory(self.block_id)
            .ok_or_else(|| uninit_error(self.block_id))?;
        let len = writer.array_len(arr)?;
        emit_select_read(writer, emit_selectors, arr, idx_felt, len)
    }
}

/// Emits a sound dynamic-index read: returns `Σ s_i * arr[i]` over constant-
/// indexed reads.
fn emit_select_read<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    emit_selectors: EmitSelectors<'c, 'b>,
    arr: Value<'c, 'b>,
    idx_felt: Value<'c, 'b>,
    len: usize,
) -> Result<Value<'c, 'b>, Error> {
    let selectors = emit_selectors(writer, idx_felt, len)?;
    let mut acc: Option<Value<'c, 'b>> = None;
    for (i, &s_i) in selectors.iter().enumerate() {
        let i_idx = writer.insert_integer(i)?;
        let elem = writer.insert_array_read(arr, i_idx)?;
        let term = writer.insert_mul(s_i, elem)?;
        acc = Some(match acc {
            None => term,
            Some(prev) => writer.insert_add(prev, term)?,
        });
    }
    // `len == 0` cannot occur — MemoryInit always supplies at least one element.
    acc.ok_or_else(|| Error::UnsupportedOpcode("MemoryRead on zero-length block".into()))
}
