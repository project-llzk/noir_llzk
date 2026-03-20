use acir::{
    FieldElement,
    circuit::{Circuit, Opcode},
    native_types::{Expression, Witness},
};
use llzk::prelude::{
    BlockLike, LlzkContext, Location, StructDefOp, StructDefOpLike, StructType, Value, dialect,
};

use crate::{
    block_writer::BlockWriter,
    common::{collect_witnesses, emit_expression, emit_gated_eq, is_trivial_predicate},
    error::Error,
    opcodes::{BuildContext, OpcodeEmitter},
};

pub(crate) struct Call<'p> {
    /// Position of this opcode in the caller's opcode list — used as the subcircuit suffix.
    index: usize,
    /// Callee circuit index in the program (from `AcirFunctionId.0`).
    callee_id: u32,
    /// Caller witness indices passed positionally as callee input parameters.
    inputs: &'p [Witness],
    /// Caller witness indices that receive callee return values (positionally aligned to
    /// `callee.return_values` in sorted order).
    outputs: &'p [Witness],
    /// The callee circuit, needed to determine return-value witness indices.
    callee: &'p Circuit<FieldElement>,

    predicate: &'p Expression<FieldElement>,
}

impl<'p> Call<'p> {
    pub(crate) fn from_opcode(
        opcode: &'p Opcode<FieldElement>,
        index: usize,
        ctx: &BuildContext<'p>,
    ) -> Result<Self, Error> {
        let Opcode::Call {
            id,
            inputs,
            outputs,
            predicate,
        } = opcode
        else {
            unreachable!("Call::from_opcode called with non-Call opcode");
        };

        let callee =
            ctx.program
                .functions
                .get(id.as_usize())
                .ok_or(Error::OutOfRangeCallTarget {
                    id: id.0,
                    num_circuits: ctx.program.functions.len(),
                })?;

        Ok(Self {
            index,
            callee_id: id.0,
            inputs,
            outputs,
            callee,
            predicate,
        })
    }
}

impl<'p> OpcodeEmitter for Call<'p> {
    fn get_witnesses(&self) -> std::collections::BTreeSet<u32> {
        let mut witnesses: std::collections::BTreeSet<u32> = self
            .inputs
            .iter()
            .chain(self.outputs.iter())
            .map(|w| w.0)
            .collect();
        witnesses.extend(collect_witnesses(self.predicate));
        witnesses
    }

    /// Emits `struct.member @subcircuit_{index} : !struct.type<@Circuit{callee_id}>`.
    fn emit_member<'c>(
        &self,
        context: &'c LlzkContext,
        struct_def: &StructDefOp<'c>,
    ) -> Result<(), Error> {
        let member = dialect::r#struct::member(
            Location::unknown(context),
            &format!("subcircuit_{}", self.index),
            StructType::from_str(context, &format!("Circuit{}", self.callee_id)),
            false,
            false,
        )?;
        struct_def.body().append_operation(member.into());
        Ok(())
    }

    /// In `@compute`:
    /// 1. Gathers caller input witnesses for the callee.
    /// 2. Invokes `@Circuit{callee_id}::@compute` to produce the callee struct.
    /// 3. Stores the callee struct as `@subcircuit_{index}`.
    /// 4. Reads callee return values and writes them to caller output witnesses, marking each known.
    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let callee_name = format!("Circuit{}", self.callee_id);

        // Gather callee input values from the caller's witness cache.
        let arg_vals = self
            .inputs
            .iter()
            .map(|w| writer.read_witness(w.0))
            .collect::<Result<Vec<_>, _>>()?;

        // Call @Circuit{callee_id}::@compute(%arg0, ...) → callee struct
        let callee_struct_type = writer.struct_type(&callee_name);
        let callee_val: Value<'c, 'b> = writer
            .call_function(&callee_name, "compute", &arg_vals, &[callee_struct_type])?
            .result(0)?
            .into();

        // Store callee struct as subcircuit member.
        writer.write_member(&format!("subcircuit_{}", self.index), callee_val)?;

        // Extract callee return values (BTreeSet — ascending index order) and write them to
        // the caller's output witnesses, making each known for subsequent opcodes.
        for (callee_ret_idx, caller_out_witness) in self
            .callee
            .return_values
            .0
            .iter()
            .map(|w| w.0)
            .zip(self.outputs)
        {
            let ret_val: Value<'c, 'b> =
                writer.read_field_member(callee_val, &format!("w{callee_ret_idx}"))?;

            writer.write_member(&format!("w{}", caller_out_witness.0), ret_val)?;

            // Mark the output witness as known so subsequent opcodes can use it.
            writer.mark_known(caller_out_witness.0, ret_val);
        }

        Ok(())
    }

    /// In `@constrain`:
    /// 1. Reads `@subcircuit_{index}` from `%self`.
    /// 2. Gathers caller input witnesses for the callee.
    /// 3. Invokes `@Circuit{callee_id}::@constrain(%callee, %arg0, ...)`.
    /// 4. Constrains output witnesses against callee return values, gated by the predicate.
    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let trivial = is_trivial_predicate(self.predicate);
        let callee_name = format!("Circuit{}", self.callee_id);
        let callee_struct_type = writer.struct_type(&callee_name);

        // Evaluate the predicate once (only when non-trivial).
        let pred_val = if trivial {
            None
        } else {
            Some(emit_expression(writer, self.predicate)?)
        };

        // Read the stored subcomponent from %self.
        let callee_val: Value<'c, 'b> =
            writer.read_self_member(callee_struct_type, &format!("subcircuit_{}", self.index))?;

        // Build args: callee struct first, then caller input witnesses.
        let mut arg_vals = vec![callee_val];
        for w in self.inputs {
            arg_vals.push(writer.read_witness(w.0)?);
        }

        // Call @Circuit{callee_id}::@constrain(%callee, %arg0, ...) — returns ()
        writer.call_function(&callee_name, "constrain", &arg_vals, &[])?;

        // Constrain that each output witness stored by @compute matches the
        // corresponding return value from the callee struct.
        for (callee_ret_witness, caller_out_witness) in
            self.callee.return_values.0.iter().zip(self.outputs)
        {
            let stored_val = writer.read_witness(caller_out_witness.0)?;
            let callee_ret_val: Value<'c, 'b> =
                writer.read_field_member(callee_val, &format!("w{}", callee_ret_witness.0))?;

            match pred_val {
                None => {
                    // Trivial predicate: unconditional equality.
                    writer.insert_constrain_eq(stored_val, callee_ret_val);
                }
                Some(p) => {
                    emit_gated_eq(writer, p, stored_val, callee_ret_val)?;
                }
            }
        }

        Ok(())
    }
}
