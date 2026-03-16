use acir::{FieldElement, circuit::Circuit, native_types::Witness};
use llzk::builder::OpBuilder;
use llzk::prelude::{
    BlockLike, FeltType, LlzkContext, Location, StructDefOp, StructDefOpLike,
    StructType, SymbolRefAttribute, Type, Value, dialect,
};

use crate::{
    FIELD_NAME, compute::ComputeWriter, constrain::ConstraintWriter, error::Error,
    opcodes::OpcodeEmitter,
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
}

impl<'p> Call<'p> {
    pub(crate) fn new(
        index: usize,
        callee_id: u32,
        inputs: &'p [Witness],
        outputs: &'p [Witness],
        callee: &'p Circuit<FieldElement>,
    ) -> Self {
        Self { index, callee_id, inputs, outputs, callee }
    }
}

impl<'p> OpcodeEmitter for Call<'p> {
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
    fn emit_compute<'c, 'b>(&self, writer: &mut ComputeWriter<'c, 'b>) -> Result<(), Error> {
        let callee_name = format!("Circuit{}", self.callee_id);
        let callee_struct_type: Type<'c> =
            StructType::from_str(writer.inner.context, &callee_name).into();

        // Gather callee input values from the caller's witness cache.
        let arg_vals = self.inputs.iter()
            .map(|w| writer.inner.read_witness(w.0))
            .collect::<Result<Vec<_>, _>>()?;

        // Call @Circuit{callee_id}::@compute(%arg0, ...) → callee struct
        let call_op = dialect::function::call(
            &OpBuilder::new(writer.inner.context),
            writer.inner.location,
            SymbolRefAttribute::new(writer.inner.context, &callee_name, &["compute"]),
            &arg_vals,
            &[callee_struct_type],
        )?;
        let callee_val: Value<'c, 'b> = writer.inner.block
            .insert_operation_before(writer.inner.ret_op, call_op.into())
            .result(0)?.into();

        // Store callee struct as subcircuit member.
        writer.inner.block.insert_operation_before(
            writer.inner.ret_op,
            dialect::r#struct::writem(
                writer.inner.location,
                writer.inner.self_value,
                &format!("subcircuit_{}", self.index),
                callee_val,
            )?,
        );

        // Extract callee return values (BTreeSet — ascending index order) and write them to
        // the caller's output witnesses, making each known for subsequent opcodes.
        let felt_type: Type<'c> = FeltType::with_field(writer.inner.context, FIELD_NAME).into();
        for (callee_ret_idx, caller_out_witness) in
            self.callee.return_values.0.iter().map(|w| w.0).zip(self.outputs)
        {
            let ret_val: Value<'c, 'b> = writer.inner.block
                .insert_operation_before(
                    writer.inner.ret_op,
                    dialect::r#struct::readm(
                        &OpBuilder::new(writer.inner.context),
                        writer.inner.location,
                        felt_type,
                        callee_val,
                        &format!("w{callee_ret_idx}"),
                    )?,
                )
                .result(0)?.into();

            writer.inner.block.insert_operation_before(
                writer.inner.ret_op,
                dialect::r#struct::writem(
                    writer.inner.location,
                    writer.inner.self_value,
                    &format!("w{}", caller_out_witness.0),
                    ret_val,
                )?,
            );

            // Mark the output witness as known so subsequent opcodes can use it.
            writer.known.insert(caller_out_witness.0);
            writer.inner.witness_cache.insert(caller_out_witness.0, ret_val);
        }

        Ok(())
    }

    /// In `@constrain`:
    /// 1. Reads `@subcircuit_{index}` from `%self`.
    /// 2. Gathers caller input witnesses for the callee.
    /// 3. Invokes `@Circuit{callee_id}::@constrain(%callee, %arg0, ...)`.
    fn emit_constrain<'c, 'b>(&self, writer: &mut ConstraintWriter<'c, 'b>) -> Result<(), Error> {
        let callee_name = format!("Circuit{}", self.callee_id);
        let callee_struct_type: Type<'c> =
            StructType::from_str(writer.inner.context, &callee_name).into();

        // Read the stored subcomponent from %self.
        let callee_val: Value<'c, 'b> = writer.inner.block
            .insert_operation_before(
                writer.inner.ret_op,
                dialect::r#struct::readm(
                    &OpBuilder::new(writer.inner.context),
                    writer.inner.location,
                    callee_struct_type,
                    writer.inner.self_value,
                    &format!("subcircuit_{}", self.index),
                )?,
            )
            .result(0)?.into();

        // Build args: callee struct first, then caller input witnesses.
        let mut arg_vals = vec![callee_val];
        for w in self.inputs {
            arg_vals.push(writer.inner.read_witness(w.0)?);
        }

        // Call @Circuit{callee_id}::@constrain(%callee, %arg0, ...) — returns ()
        let call_op = dialect::function::call(
            &OpBuilder::new(writer.inner.context),
            writer.inner.location,
            SymbolRefAttribute::new(writer.inner.context, &callee_name, &["constrain"]),
            &arg_vals,
            &[] as &[StructType<'c>],
        )?;
        writer.inner.block.insert_operation_before(writer.inner.ret_op, call_op.into());

        Ok(())
    }
}
