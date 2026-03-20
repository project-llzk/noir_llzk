use std::collections::BTreeSet;

use acir::circuit::Opcode;
use acir::native_types::Expression;
use acir::{AcirField, FieldElement};
use llzk::builder::OpBuilder;
use llzk::dialect::array::{ArrayCtor, ArrayType};
use llzk::prelude::melior_dialects::arith;
use llzk::prelude::{
    BlockLike, FeltType, IntegerAttribute, LlzkContext, LlzkError, Location, Operation,
    OperationLike, RegionLike, StructDefOp, StructDefOpLike, StructType, Type, Value, dialect,
};

use crate::FIELD_NAME;
use crate::block_writer::BlockWriter;
use crate::common::{collect_witnesses, emit_expression};
use crate::error::Error;
use crate::opcodes::{BuildContext, OpcodeEmitter, TranslatedOpcode};

// ── Struct def emission ────────────────────────────────────────────────

/// Emits the `MemRead_{n}` struct def at the module level.
///
/// The struct stores `data`, `index`, and `value`.  Compute reads
/// `value = data[index]`.  Constrain asserts `value == data[index]`.
pub(crate) fn emit_mem_read_struct_def<'c>(
    context: &'c LlzkContext,
    n: usize,
) -> Result<StructDefOp<'c>, Error> {
    let location = Location::unknown(context);
    let struct_name = format!("MemRead_{n}");
    let felt_type: Type<'c> = FeltType::with_field(context, FIELD_NAME).into();
    let array_type: Type<'c> = ArrayType::new_with_dims(felt_type, &[n as i64]).into();
    let struct_type = StructType::from_str(context, &struct_name);

    let struct_def = dialect::r#struct::def(
        location,
        &struct_name,
        &[],
        [] as [Result<Operation, LlzkError>; 0],
    )?;

    // Members: @data, @index, @value
    struct_def.body().append_operation(
        dialect::r#struct::member(
            location,
            "data",
            ArrayType::new_with_dims(felt_type, &[n as i64]),
            false,
            false,
        )?
        .into(),
    );
    struct_def.body().append_operation(
        dialect::r#struct::member(
            location,
            "index",
            FeltType::with_field(context, FIELD_NAME),
            false,
            false,
        )?
        .into(),
    );
    struct_def.body().append_operation(
        dialect::r#struct::member(
            location,
            "value",
            FeltType::with_field(context, FIELD_NAME),
            false,
            true, // public — read by the parent circuit to extract the solved witness
        )?
        .into(),
    );

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

/// Emits the `MemWrite_{n}` struct def at the module level.
///
/// The struct stores `old_data`, `new_data`, `index`, and `write_value`.
/// Compute creates `new_data` by copying `old_data` and overwriting at `index`.
/// Constrain checks that the written slot matches and all other slots are unchanged.
pub(crate) fn emit_mem_write_struct_def<'c>(
    context: &'c LlzkContext,
    n: usize,
) -> Result<StructDefOp<'c>, Error> {
    let location = Location::unknown(context);
    let struct_name = format!("MemWrite_{n}");
    let felt_type: Type<'c> = FeltType::with_field(context, FIELD_NAME).into();
    let array_type: Type<'c> = ArrayType::new_with_dims(felt_type, &[n as i64]).into();
    let struct_type = StructType::from_str(context, &struct_name);

    let struct_def = dialect::r#struct::def(
        location,
        &struct_name,
        &[],
        [] as [Result<Operation, LlzkError>; 0],
    )?;

    // Members: @old_data, @new_data (public), @index, @write_value
    struct_def.body().append_operation(
        dialect::r#struct::member(
            location,
            "old_data",
            ArrayType::new_with_dims(felt_type, &[n as i64]),
            false,
            false,
        )?
        .into(),
    );
    struct_def.body().append_operation(
        dialect::r#struct::member(
            location,
            "new_data",
            ArrayType::new_with_dims(felt_type, &[n as i64]),
            false,
            true, // public — read by the parent circuit for version chaining
        )?
        .into(),
    );
    for name in ["index", "write_value"] {
        struct_def.body().append_operation(
            dialect::r#struct::member(
                location,
                name,
                FeltType::with_field(context, FIELD_NAME),
                false,
                false,
            )?
            .into(),
        );
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

// ── Opcode handlers ────────────────────────────────────────────────────

/// Dispatches an ACIR `MemoryOp` opcode to either [`MemoryRead`] or
/// [`MemoryWrite`] based on the `operation` expression, updating counters and
/// size sets in `ctx`.
pub(crate) fn from_opcode<'p>(
    opcode: &'p Opcode<FieldElement>,
    index: usize,
    ctx: &mut BuildContext<'p>,
) -> Result<TranslatedOpcode<'p>, Error> {
    let Opcode::MemoryOp {
        block_id,
        op: mem_op,
        ..
    } = opcode
    else {
        unreachable!("memory_op::from_opcode called with non-MemoryOp opcode");
    };

    let array_len = *ctx
        .block_sizes
        .get(&block_id.0)
        .ok_or(Error::UninitializedMemoryBlock {
            block_id: block_id.0,
            opcode_index: index,
        })?;

    // Determine read vs write from the operation expression.
    let op_expr = &mem_op.operation;
    let is_write = if op_expr.is_const() {
        if op_expr.q_c.is_zero() {
            false // read
        } else if op_expr.q_c.is_one() {
            true // write
        } else {
            return Err(Error::NonConstantMemoryOperation {
                opcode_index: index,
            });
        }
    } else {
        return Err(Error::NonConstantMemoryOperation {
            opcode_index: index,
        });
    };

    if is_write {
        let mi = ctx.write_count;
        ctx.write_count += 1;
        ctx.write_sizes.insert(array_len);
        Ok(Box::new(MemoryWrite {
            member_index: mi,
            block_id: block_id.0,
            array_len,
            index_expr: &mem_op.index,
            value_expr: &mem_op.value,
        }))
    } else {
        let mi = ctx.read_count;
        ctx.read_count += 1;
        ctx.read_sizes.insert(array_len);
        Ok(Box::new(MemoryRead {
            member_index: mi,
            block_id: block_id.0,
            array_len,
            index_expr: &mem_op.index,
            value_expr: &mem_op.value,
        }))
    }
}

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
