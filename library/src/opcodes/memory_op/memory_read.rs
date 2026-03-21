use std::collections::BTreeSet;

use acir::native_types::Expression;
use acir::{AcirField, FieldElement};
use llzk::builder::OpBuilder;
use llzk::dialect::array::ArrayType;
use llzk::prelude::{
    BlockLike, FeltType, LlzkContext, Location, OperationLike, RegionLike, StructDefOp,
    StructDefOpLike, StructType, Type, Value, dialect,
};

use crate::FIELD_NAME;
use crate::block_writer::BlockWriter;
use crate::common::{array_member, collect_witnesses, emit_expression, empty_struct, field_member};
use crate::error::Error;
use crate::opcodes::OpcodeEmitter;

// ── Opcode handler ─────────────────────────────────────────────────────

/// Translates an ACIR `MemoryOp` with `operation=0` (read).
///
/// Emits a `MemRead_{N}` subcomponent member on the circuit struct.  In
/// `@compute`, calls `MemRead_{N}::@compute` with the current array version
/// and the index, then extracts the value to solve the output witness.
/// In `@constrain`, reads the subcomponent and invokes its `@constrain`.
pub(crate) struct MemoryRead<'p> {
    /// Unique index among all reads in this circuit (for naming `read_{i}`).
    pub(crate) member_index: usize,
    /// Which memory block this read accesses.
    pub(crate) block_id: u32,
    /// Array length of the target block (from the corresponding `MemoryInit`).
    pub(crate) array_len: usize,
    /// Expression that evaluates to the array index (typically a single witness).
    pub(crate) index_expr: &'p Expression<FieldElement>,
    /// Expression that identifies the output witness for the read value.
    /// In practice, this is a single witness `1 * w_k + 0`.
    pub(crate) value_expr: &'p Expression<FieldElement>,
}

impl<'p> OpcodeEmitter for MemoryRead<'p> {
    fn get_witnesses(&self) -> BTreeSet<u32> {
        let mut witnesses = collect_witnesses(self.index_expr);
        witnesses.extend(collect_witnesses(self.value_expr));
        witnesses
    }

    fn emit_member<'c>(
        &self,
        context: &'c LlzkContext,
        struct_def: &StructDefOp<'c>,
    ) -> Result<(), Error> {
        let member = dialect::r#struct::member(
            Location::unknown(context),
            &format!("read_{}", self.member_index),
            StructType::from_str(context, &format!("MemRead_{}", self.array_len)),
            false,
            false,
        )?;
        struct_def.body().append_operation(member.into());
        Ok(())
    }

    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let struct_name = format!("MemRead_{}", self.array_len);

        // Get current array version for this block.
        let (data, _len) = writer.memory_versions.get(self.block_id).expect(
            "MemoryRead: block not initialized (MemoryInit should have been processed first)",
        );

        // Evaluate the index expression to a felt value.
        let idx = emit_expression(writer, self.index_expr)?;

        // Call MemRead_N::@compute(%data, %idx) → MemRead struct
        let read_struct_type = writer.struct_type(&struct_name);
        let read_struct: Value<'c, 'b> = writer
            .call_function(&struct_name, "compute", &[data, idx], &[read_struct_type])?
            .result(0)?
            .into();

        // Store the subcomponent.
        writer.write_member(&format!("read_{}", self.member_index), read_struct)?;

        // Extract the read value and solve the output witness.
        let read_val = writer.read_field_member(read_struct, "value")?;
        self.solve_value_witness(writer, read_val)?;

        Ok(())
    }

    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let struct_name = format!("MemRead_{}", self.array_len);
        let read_struct_type = writer.struct_type(&struct_name);

        // Get current array version and evaluate index (same args as compute).
        let (data, _len) = writer
            .memory_versions
            .get(self.block_id)
            .expect("MemoryRead constrain: block not initialized");
        let idx = emit_expression(writer, self.index_expr)?;

        let read_struct =
            writer.read_self_member(read_struct_type, &format!("read_{}", self.member_index))?;
        writer.call_function(&struct_name, "constrain", &[read_struct, data, idx], &[])?;
        Ok(())
    }
}

impl<'p> MemoryRead<'p> {
    /// Extracts the output witness from `value_expr` and stores the read value.
    ///
    /// Handles the common case where `value_expr` is a single witness
    /// (`coeff * w_k + constant`), solving `w_k = (read_val - constant) / coeff`.
    fn solve_value_witness<'c, 'b>(
        &self,
        writer: &mut BlockWriter<'c, 'b>,
        read_val: Value<'c, 'b>,
    ) -> Result<(), Error> {
        let expr = self.value_expr;

        // The value expression must be a single linear witness (no mul terms).
        assert!(
            expr.mul_terms.is_empty(),
            "MemoryRead value expression with mul terms is not supported"
        );
        assert!(
            expr.linear_combinations.len() == 1,
            "MemoryRead value expression must reference exactly one witness"
        );

        let (coeff, witness) = &expr.linear_combinations[0];
        let w_idx = witness.0;

        // Solve: coeff * w_k + q_c = read_val  →  w_k = (read_val - q_c) / coeff
        let mut val = read_val;
        if !expr.q_c.is_zero() {
            let constant = writer.emit_constant(&expr.q_c)?;
            val = writer.insert_sub(val, constant)?;
        }
        if !coeff.is_one() {
            let coeff_val = writer.emit_constant(coeff)?;
            val = writer.insert_div(val, coeff_val)?;
        }

        writer.write_member(&format!("w{w_idx}"), val)?;
        writer.mark_known(w_idx, val);
        Ok(())
    }
}

// ── Struct def emission ────────────────────────────────────────────────

/// Emits the `MemRead_{n}` struct def at the module level.
///
/// The struct stores `data`, `index`, and `value`.  Compute reads
/// `value = data[index]`.  Constrain asserts `value == data[index]`.
pub(crate) fn emit_struct_def<'c>(
    context: &'c LlzkContext,
    n: usize,
) -> Result<StructDefOp<'c>, Error> {
    let location = Location::unknown(context);
    let struct_name = format!("MemRead_{n}");
    let felt_type: Type<'c> = FeltType::with_field(context, FIELD_NAME).into();
    let array_type: Type<'c> = ArrayType::new_with_dims(felt_type, &[n as i64]).into();
    let struct_type = StructType::from_str(context, &struct_name);

    let struct_def = empty_struct(location, &struct_name)?;

    // Members: @data, @index, @value
    struct_def
        .body()
        .append_operation(array_member(location, context, "data", n, false)?);
    struct_def
        .body()
        .append_operation(field_member(location, context, "index", false)?);
    struct_def
        .body()
        .append_operation(field_member(location, context, "value", true)?); // public

    // ── @compute(%block_data: array<felt, N>, %idx: felt) -> MemRead_N ──
    let compute = dialect::r#struct::helpers::compute_fn(
        location,
        struct_type,
        &[(array_type, location), (felt_type, location)],
        None,
    )?;
    {
        let block = compute.region(0)?.first_block().unwrap();
        let self_val: Value = block.first_operation().unwrap().result(0)?.into();
        let block_data: Value = block.argument(0)?.into();
        let idx: Value = block.argument(1)?.into();
        let ret_op = block.terminator().unwrap();

        block.insert_operation_before(
            ret_op,
            dialect::r#struct::writem(location, self_val, "data", block_data)?,
        );
        block.insert_operation_before(
            ret_op,
            dialect::r#struct::writem(location, self_val, "index", idx)?,
        );
        // Cast felt index → index type for array.read
        let idx_as_index: Value = block
            .insert_operation_before(ret_op, dialect::cast::toindex(location, idx))
            .result(0)?
            .into();
        let read_op = block.insert_operation_before(
            ret_op,
            dialect::array::read(location, felt_type, block_data, &[idx_as_index]),
        );
        let val: Value = read_op.result(0)?.into();
        block.insert_operation_before(
            ret_op,
            dialect::r#struct::writem(location, self_val, "value", val)?,
        );
    }
    struct_def.body().append_operation(compute.into());

    // ── @constrain(%self: MemRead_N, %block_data: array, %idx: felt) ──
    // Extra params must match @compute's signature for LLZK validation.
    let constrain = dialect::r#struct::helpers::constrain_fn(
        location,
        struct_type,
        &[(array_type, location), (felt_type, location)],
        None,
    )?;
    {
        let block = constrain.region(0)?.first_block().unwrap();
        let self_val: Value = block.argument(0)?.into();
        let ret_op = block.terminator().unwrap();
        let builder = OpBuilder::new(context);

        let data: Value = block
            .insert_operation_before(
                ret_op,
                dialect::r#struct::readm(&builder, location, array_type, self_val, "data")?,
            )
            .result(0)?
            .into();
        let idx: Value = block
            .insert_operation_before(
                ret_op,
                dialect::r#struct::readm(&builder, location, felt_type, self_val, "index")?,
            )
            .result(0)?
            .into();
        let val: Value = block
            .insert_operation_before(
                ret_op,
                dialect::r#struct::readm(&builder, location, felt_type, self_val, "value")?,
            )
            .result(0)?
            .into();
        // Cast felt index → index type for array.read
        let idx_as_index: Value = block
            .insert_operation_before(ret_op, dialect::cast::toindex(location, idx))
            .result(0)?
            .into();
        let expected: Value = block
            .insert_operation_before(
                ret_op,
                dialect::array::read(location, felt_type, data, &[idx_as_index]),
            )
            .result(0)?
            .into();
        block.insert_operation_before(ret_op, dialect::constrain::eq(location, val, expected));
    }
    struct_def.body().append_operation(constrain.into());

    Ok(struct_def)
}
