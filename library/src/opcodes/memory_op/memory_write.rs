use std::collections::BTreeSet;

use acir::native_types::Expression;
use acir::{AcirField, FieldElement};
use llzk::builder::OpBuilder;
use llzk::dialect::array::{ArrayCtor, ArrayType};
use llzk::prelude::melior_dialects::arith;
use llzk::prelude::{
    BlockLike, FeltType, IntegerAttribute, LlzkContext, Location, OperationLike, RegionLike,
    StructDefOp, StructDefOpLike, StructType, Type, Value, dialect,
};

use crate::FIELD_NAME;
use crate::block_writer::BlockWriter;
use crate::common::{array_member, collect_witnesses, emit_expression, empty_struct, field_member};
use crate::error::Error;
use crate::opcodes::OpcodeEmitter;

// ── Opcode handler ─────────────────────────────────────────────────────

/// Translates an ACIR `MemoryOp` with `operation=1` (write).
///
/// Emits a `MemWrite_{N}` subcomponent member on the circuit struct.  In
/// `@compute`, calls `MemWrite_{N}::@compute` with the current array version,
/// index, and write value, then updates the memory version to `new_data`.
/// In `@constrain`, reads the subcomponent and invokes its `@constrain`.
pub(crate) struct MemoryWrite<'p> {
    /// Unique index among all writes in this circuit (for naming `write_{i}`).
    pub(crate) member_index: usize,
    /// Which memory block this write modifies.
    pub(crate) block_id: u32,
    /// Array length of the target block (from the corresponding `MemoryInit`).
    pub(crate) array_len: usize,
    /// Expression that evaluates to the array index.
    pub(crate) index_expr: &'p Expression<FieldElement>,
    /// Expression that evaluates to the value to write.
    pub(crate) value_expr: &'p Expression<FieldElement>,
}

impl<'p> OpcodeEmitter for MemoryWrite<'p> {
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
            &format!("write_{}", self.member_index),
            StructType::from_str(context, &format!("MemWrite_{}", self.array_len)),
            false,
            false,
        )?;
        struct_def.body().append_operation(member.into());
        Ok(())
    }

    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let struct_name = format!("MemWrite_{}", self.array_len);

        // Get current array version for this block.
        let (data, len) = writer.memory_versions.get(self.block_id).expect(
            "MemoryWrite: block not initialized (MemoryInit should have been processed first)",
        );

        // Evaluate index and value expressions.
        let idx = emit_expression(writer, self.index_expr)?;
        let val = emit_expression(writer, self.value_expr)?;

        // Call MemWrite_N::@compute(%data, %idx, %val) → MemWrite struct
        let write_struct_type = writer.struct_type(&struct_name);
        let write_struct: Value<'c, 'b> = writer
            .call_function(
                &struct_name,
                "compute",
                &[data, idx, val],
                &[write_struct_type],
            )?
            .result(0)?
            .into();

        // Store the subcomponent.
        writer.write_member(&format!("write_{}", self.member_index), write_struct)?;

        // Read new_data and update the memory version.
        let new_data_type = writer.array_type(len);
        let new_data = writer.read_member(new_data_type, write_struct, "new_data")?;
        writer.memory_versions.set(self.block_id, new_data, len);

        Ok(())
    }

    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let struct_name = format!("MemWrite_{}", self.array_len);
        let write_struct_type = writer.struct_type(&struct_name);

        // Get current array version and evaluate index/value (same args as compute).
        let (data, _len) = writer
            .memory_versions
            .get(self.block_id)
            .expect("MemoryWrite constrain: block not initialized");
        let idx = emit_expression(writer, self.index_expr)?;
        let val = emit_expression(writer, self.value_expr)?;

        let write_struct =
            writer.read_self_member(write_struct_type, &format!("write_{}", self.member_index))?;
        writer.call_function(
            &struct_name,
            "constrain",
            &[write_struct, data, idx, val],
            &[],
        )?;

        // Update the memory version in constrain so that subsequent operations
        // in the constrain phase reference the correct version.
        let new_data_type = writer.array_type(self.array_len);
        let new_data = writer.read_member(new_data_type, write_struct, "new_data")?;
        writer
            .memory_versions
            .set(self.block_id, new_data, self.array_len);

        Ok(())
    }
}

// ── Struct def emission ────────────────────────────────────────────────

/// Emits the `MemWrite_{n}` struct def at the module level.
///
/// The struct stores `old_data`, `new_data`, `index`, and `write_value`.
/// Compute creates `new_data` by copying `old_data` and overwriting at `index`.
/// Constrain checks that the written slot matches and all other slots are unchanged.
pub(crate) fn emit_struct_def<'c>(
    context: &'c LlzkContext,
    n: usize,
) -> Result<StructDefOp<'c>, Error> {
    let location = Location::unknown(context);
    let struct_name = format!("MemWrite_{n}");
    let felt_type: Type<'c> = FeltType::with_field(context, FIELD_NAME).into();
    let array_type: Type<'c> = ArrayType::new_with_dims(felt_type, &[n as i64]).into();
    let struct_type = StructType::from_str(context, &struct_name);

    let struct_def = empty_struct(location, &struct_name)?;

    // Members: @old_data, @new_data (public), @index, @write_value
    struct_def
        .body()
        .append_operation(array_member(location, context, "old_data", n, false)?);
    struct_def
        .body()
        .append_operation(array_member(location, context, "new_data", n, true)?); // public
    for name in ["index", "write_value"] {
        struct_def
            .body()
            .append_operation(field_member(location, context, name, false)?);
    }

    // ── @compute(%old: array<felt, N>, %idx: felt, %val: felt) -> MemWrite_N ──
    let compute = dialect::r#struct::helpers::compute_fn(
        location,
        struct_type,
        &[
            (array_type, location),
            (felt_type, location),
            (felt_type, location),
        ],
        None,
    )?;
    {
        let block = compute.region(0)?.first_block().unwrap();
        let self_val: Value = block.first_operation().unwrap().result(0)?.into();
        let old: Value = block.argument(0)?.into();
        let idx: Value = block.argument(1)?.into();
        let val: Value = block.argument(2)?.into();
        let ret_op = block.terminator().unwrap();

        // Store old_data, index, write_value
        block.insert_operation_before(
            ret_op,
            dialect::r#struct::writem(location, self_val, "old_data", old)?,
        );
        block.insert_operation_before(
            ret_op,
            dialect::r#struct::writem(location, self_val, "index", idx)?,
        );
        block.insert_operation_before(
            ret_op,
            dialect::r#struct::writem(location, self_val, "write_value", val)?,
        );

        // Build new_data: create a new array, copy all elements from old, then overwrite at idx
        let builder = OpBuilder::new(context);
        let new_arr: Value = block
            .insert_operation_before(
                ret_op,
                dialect::array::new(
                    &builder,
                    location,
                    ArrayType::new_with_dims(felt_type, &[n as i64]),
                    ArrayCtor::Empty,
                ),
            )
            .result(0)?
            .into();

        let index_type = Type::index(context);
        for i in 0..n {
            let ci: Value = block
                .insert_operation_before(
                    ret_op,
                    arith::constant(
                        context,
                        IntegerAttribute::new(index_type, i as i64).into(),
                        location,
                    ),
                )
                .result(0)?
                .into();
            let elem: Value = block
                .insert_operation_before(
                    ret_op,
                    dialect::array::read(location, felt_type, old, &[ci]),
                )
                .result(0)?
                .into();
            block.insert_operation_before(
                ret_op,
                dialect::array::write(location, new_arr, &[ci], elem),
            );
        }
        // Cast felt index → index type, then overwrite at the write index
        let idx_as_index: Value = block
            .insert_operation_before(ret_op, dialect::cast::toindex(location, idx))
            .result(0)?
            .into();
        block.insert_operation_before(
            ret_op,
            dialect::array::write(location, new_arr, &[idx_as_index], val),
        );

        block.insert_operation_before(
            ret_op,
            dialect::r#struct::writem(location, self_val, "new_data", new_arr)?,
        );
    }
    struct_def.body().append_operation(compute.into());

    // ── @constrain(%self: MemWrite_N, %old: array, %idx: felt, %val: felt) ──
    // Extra params must match @compute's signature for LLZK validation.
    let constrain = dialect::r#struct::helpers::constrain_fn(
        location,
        struct_type,
        &[
            (array_type, location),
            (felt_type, location),
            (felt_type, location),
        ],
        None,
    )?;
    {
        let block = constrain.region(0)?.first_block().unwrap();
        let self_val: Value = block.argument(0)?.into();
        let ret_op = block.terminator().unwrap();
        let builder = OpBuilder::new(context);

        let old: Value = block
            .insert_operation_before(
                ret_op,
                dialect::r#struct::readm(&builder, location, array_type, self_val, "old_data")?,
            )
            .result(0)?
            .into();
        let new: Value = block
            .insert_operation_before(
                ret_op,
                dialect::r#struct::readm(&builder, location, array_type, self_val, "new_data")?,
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
        let wval: Value = block
            .insert_operation_before(
                ret_op,
                dialect::r#struct::readm(&builder, location, felt_type, self_val, "write_value")?,
            )
            .result(0)?
            .into();

        // Cast felt index → index type for array access
        let idx_as_index: Value = block
            .insert_operation_before(ret_op, dialect::cast::toindex(location, idx))
            .result(0)?
            .into();

        // Constraint 1: new[idx] == write_value
        let new_at_idx: Value = block
            .insert_operation_before(
                ret_op,
                dialect::array::read(location, felt_type, new, &[idx_as_index]),
            )
            .result(0)?
            .into();
        block.insert_operation_before(ret_op, dialect::constrain::eq(location, new_at_idx, wval));

        // Constraint 2: for i in 0..N: (new[i] - old[i]) * (i - index) == 0
        let index_type = Type::index(context);
        let zero_felt = {
            let attr = crate::common::field_to_felt_const(context, &FieldElement::zero());
            let op =
                block.insert_operation_before(ret_op, dialect::felt::constant(location, attr)?);
            let v: Value = op.result(0)?.into();
            v
        };

        for i in 0..n {
            let ci: Value = block
                .insert_operation_before(
                    ret_op,
                    arith::constant(
                        context,
                        IntegerAttribute::new(index_type, i as i64).into(),
                        location,
                    ),
                )
                .result(0)?
                .into();
            let old_i: Value = block
                .insert_operation_before(
                    ret_op,
                    dialect::array::read(location, felt_type, old, &[ci]),
                )
                .result(0)?
                .into();
            let new_i: Value = block
                .insert_operation_before(
                    ret_op,
                    dialect::array::read(location, felt_type, new, &[ci]),
                )
                .result(0)?
                .into();
            let diff: Value = block
                .insert_operation_before(ret_op, dialect::felt::sub(location, new_i, old_i)?)
                .result(0)?
                .into();

            // i as a felt constant
            let i_felt = {
                let attr =
                    crate::common::field_to_felt_const(context, &FieldElement::from(i as u128));
                let op =
                    block.insert_operation_before(ret_op, dialect::felt::constant(location, attr)?);
                let v: Value = op.result(0)?.into();
                v
            };
            let idx_diff: Value = block
                .insert_operation_before(ret_op, dialect::felt::sub(location, i_felt, idx)?)
                .result(0)?
                .into();
            let prod: Value = block
                .insert_operation_before(ret_op, dialect::felt::mul(location, diff, idx_diff)?)
                .result(0)?
                .into();
            block
                .insert_operation_before(ret_op, dialect::constrain::eq(location, prod, zero_felt));
        }
    }
    struct_def.body().append_operation(constrain.into());

    Ok(struct_def)
}
