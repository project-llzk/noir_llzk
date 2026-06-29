use acir::{
    AcirField as _, FieldElement,
    circuit::Circuit,
    native_types::{Expression, Witness},
};
use llzk::builder::OpBuilder;
use llzk::prelude::{
    Block, BlockLike, LlzkContext, Location, Operation, Region, RegionLike as _, StructDefOp,
    StructDefOpLike, StructType, SymbolRefAttribute, Type, Value, dialect, melior_dialects::scf,
};

use crate::{
    block_writer::BlockWriter,
    common::{
        collect_witnesses, constrain_bool, emit_expression, emit_gated_eq, is_trivial_predicate,
    },
    error::Error,
    opcodes::OpcodeEmitter,
    writer::Writer,
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
    pub(crate) fn new(
        index: usize,
        callee_id: u32,
        inputs: &'p [Witness],
        outputs: &'p [Witness],
        callee: &'p Circuit<FieldElement>,
        predicate: &'p Expression<FieldElement>,
    ) -> Self {
        Self {
            index,
            callee_id,
            inputs,
            outputs,
            callee,
            predicate,
        }
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
    /// 4. Writes each caller output witness with `predicate * callee_ret`,
    ///    so a false predicate zeroes the output.
    ///    Trivially true predicates skip the multiplication.
    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let callee_name = format!("Circuit{}", self.callee_id);

        // Gather callee input values from the caller's witness cache.
        let arg_vals = self
            .inputs
            .iter()
            .map(|w| writer.read_witness(w.0))
            .collect::<Result<Vec<_>, _>>()?;

        // Call @Circuit{callee_id}::@compute(%arg0, ...) → callee struct.
        let callee_struct_type = writer.struct_type(&callee_name);
        let callee_val: Value<'c, 'b> = writer
            .call_function(&callee_name, "compute", &arg_vals, &[callee_struct_type])?
            .result(0)?
            .into();

        // Store callee struct as subcircuit member.
        writer.write_member(&format!("subcircuit_{}", self.index), callee_val)?;

        let pred_val = if is_trivial_predicate(self.predicate) {
            None
        } else {
            Some(emit_expression(writer, self.predicate)?)
        };

        for (callee_ret_witness, caller_out_witness) in
            self.callee.return_values.0.iter().zip(self.outputs)
        {
            let ret_val =
                writer.read_field_member(callee_val, &format!("w{}", callee_ret_witness.0))?;
            let val = match pred_val {
                None => ret_val,
                Some(p) => writer.insert_mul(p, ret_val)?,
            };
            writer.write_member(&format!("w{}", caller_out_witness.0), val)?;
            writer.mark_known(caller_out_witness.0, val);
        }

        Ok(())
    }

    /// In `@constrain`:
    /// 1. Reads `@subcircuit_{index}` from `%self`.
    /// 2. Gathers caller input witnesses for the callee.
    /// 3. Invokes `@Circuit{callee_id}::@constrain(%callee, %arg0, ...)`,
    ///    gated by the predicate when non-trivial.
    /// 4. Constrains output witnesses against callee return values, gated by the predicate.
    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let trivial = is_trivial_predicate(self.predicate);
        let callee_name = format!("Circuit{}", self.callee_id);
        let callee_struct_type = writer.struct_type(&callee_name);
        let context = writer.context();
        let location = writer.location();

        // Evaluate the predicate once (only when non-trivial).
        let pred_val = if trivial {
            None
        } else {
            let p = emit_expression(writer, self.predicate)?;
            constrain_bool(writer, p)?;
            Some(p)
        };

        // Read the stored subcomponent from %self.
        let callee_val: Value<'c, 'b> =
            writer.read_self_member(callee_struct_type, &format!("subcircuit_{}", self.index))?;

        // Build args: callee struct first, then caller input witnesses.
        let mut arg_vals = vec![callee_val];
        for w in self.inputs {
            arg_vals.push(writer.read_witness(w.0)?);
        }

        // Define constrain function for inner circuit.
        // Call it conditionally based on predicate value.
        let call_op: Operation<'c> = dialect::function::call(
            &OpBuilder::new(context),
            location,
            SymbolRefAttribute::new_from_str(context, &callee_name, &["constrain"]),
            &arg_vals,
            &[] as &[Type<'c>],
        )?
        .into();

        match pred_val {
            None => {
                writer.insert_op(call_op);
            }
            Some(p) => {
                let one = writer.emit_constant(&FieldElement::one())?;
                let pred_is_one =
                    writer.insert_op_with_result(dialect::bool::eq(location, p, one)?)?;

                let then_region = Region::new();
                let then_block = Block::new(&[]);
                then_block.append_operation(call_op);
                then_block.append_operation(scf::r#yield(&[], location));
                then_region.append_block(then_block);

                let else_region = Region::new();
                let else_block = Block::new(&[]);
                else_block.append_operation(scf::r#yield(&[], location));
                else_region.append_block(else_block);

                writer.insert_op(scf::r#if(
                    pred_is_one,
                    &[],
                    then_region,
                    else_region,
                    location,
                ));
            }
        }

        // Constrain that each output witness stored by @compute matches the
        // corresponding return value from the callee struct.
        for (callee_ret_witness, caller_out_witness) in
            self.callee.return_values.0.iter().zip(self.outputs)
        {
            let stored_val = writer.read_witness(caller_out_witness.0)?;
            let callee_ret_val: Value<'c, 'b> =
                writer.read_field_member(callee_val, &format!("w{}", callee_ret_witness.0))?;

            match pred_val {
                None => writer.insert_constrain_eq(stored_val, callee_ret_val),
                Some(p) => emit_gated_eq(writer, p, stored_val, callee_ret_val)?,
            }
        }

        Ok(())
    }
}
