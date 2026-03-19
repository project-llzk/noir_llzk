use std::collections::{BTreeSet, HashMap, HashSet};

use acir::{
    AcirField, FieldElement,
    circuit::{Circuit, Opcode, Program, opcodes::BlockType},
};
use llzk::{
    attributes::NamedAttribute,
    prelude::{
        BlockLike, FeltType, LlzkContext, LlzkError, Location, Operation, PublicAttribute,
        StructDefOp, StructDefOpLike, StructType, Type, dialect,
    },
};

use crate::{
    Error, FIELD_NAME,
    block_writer::BlockWriter,
    opcodes::{
        TranslatedOpcode, assert_zero::AssertZero, bitwise, call::Call, memory_init::MemoryInit,
        memory_op::{self, MemoryRead, MemoryWrite},
    },
};

/// Translates a single ACIR [`Circuit`] into LLZK [`StructDefOp`]s.
///
/// Returns a vec whose first element is the circuit struct, followed by any
/// auxiliary struct defs (`MemRead_{N}`, `MemWrite_{N}`) needed by memory
/// operations.  All returned struct defs should be added to the module.
pub(crate) struct CircuitTranslator<'c, 'p> {
    context: &'c LlzkContext,
    circuit: &'p Circuit<FieldElement>,
    /// Full program, needed to resolve called circuits by index for `Call`.
    program: &'p Program<FieldElement>,
}

impl<'c, 'p> CircuitTranslator<'c, 'p> {
    pub(crate) fn new(
        context: &'c LlzkContext,
        circuit: &'p Circuit<FieldElement>,
        program: &'p Program<FieldElement>,
    ) -> Self {
        Self {
            context,
            circuit,
            program,
        }
    }

    /// Runs the full translation pipeline and returns the circuit struct def
    /// followed by any auxiliary struct defs.
    ///
    /// 1. `build_handlers` — converts ACIR opcodes to [`TranslatedOpcode`]s,
    ///    pre-computing all metadata (member names, circuit names for `Call`,
    ///    block sizes and member indices for `MemoryOp`).
    /// 2. `emit_witness_members` — adds `struct.member @w{i} : !felt.type` for
    ///    each internal witness.
    /// 3. Iterate opcodes → `emit_member` (subcomponent members).
    /// 4. Build and populate the `@compute` function.
    /// 5. Build and populate the `@constrain` function.
    /// 6. Emit auxiliary `MemRead_{N}` / `MemWrite_{N}` struct defs.
    pub(crate) fn translate(
        self,
        circuit_index: usize,
    ) -> Result<Vec<StructDefOp<'c>>, Error> {
        let location = Location::unknown(self.context);
        let struct_name = format!("Circuit{circuit_index}");

        let struct_def = dialect::r#struct::def(
            location,
            &struct_name,
            &[],
            [] as [Result<Operation, LlzkError>; 0],
        )?;

        let (ops, read_sizes, write_sizes) = self.build_handlers()?;
        let input_witnesses = self.sorted_input_witnesses();

        // Collect the set of witnesses actually referenced by opcodes.
        let opcode_witnesses: BTreeSet<u32> =
            ops.iter().flat_map(|op| op.get_witnesses()).collect();

        // Phase 1: struct members
        self.emit_witness_members(&struct_def, &input_witnesses, &opcode_witnesses)?;
        for op in &ops {
            op.emit_member(self.context, &struct_def)?;
        }

        let inputs = self.build_input_list(&input_witnesses);
        let arg_attrs = self.build_input_attrs(&input_witnesses);
        let struct_type = StructType::from_str(self.context, &struct_name);

        // Phase 2: @compute
        let compute = dialect::r#struct::helpers::compute_fn(
            location,
            struct_type,
            &inputs,
            Some(&arg_attrs),
        )?;
        struct_def.body().append_operation(compute.into());
        let mut compute_writer =
            BlockWriter::for_compute(self.context, &struct_def, &input_witnesses)?;
        for op in &ops {
            op.emit_compute(&mut compute_writer)?;
        }

        // Phase 3: @constrain
        let constrain = dialect::r#struct::helpers::constrain_fn(
            location,
            struct_type,
            &inputs,
            Some(&arg_attrs),
        )?;
        struct_def.body().append_operation(constrain.into());
        let mut constrain_writer =
            BlockWriter::for_constrain(self.context, &struct_def, &input_witnesses)?;
        for op in &ops {
            op.emit_constrain(&mut constrain_writer)?;
        }

        // Collect results: auxiliary MemRead/MemWrite struct defs first (they must
        // be defined before the circuit struct that references them), then the
        // circuit struct itself.
        let mut result = Vec::new();
        for n in &read_sizes {
            result.push(memory_op::emit_mem_read_struct_def(self.context, *n)?);
        }
        for n in &write_sizes {
            result.push(memory_op::emit_mem_write_struct_def(self.context, *n)?);
        }
        result.push(struct_def);

        Ok(result)
    }

    /// Converts each ACIR opcode into a [`TranslatedOpcode`], pre-computing
    /// all metadata needed by the emission phases.
    ///
    /// Also returns the set of distinct array sizes that need `MemRead_{N}`
    /// and `MemWrite_{N}` struct defs.
    fn build_handlers(
        &self,
    ) -> Result<(Vec<TranslatedOpcode<'p>>, BTreeSet<usize>, BTreeSet<usize>), Error> {
        let mut block_sizes: HashMap<u32, usize> = HashMap::new();
        let mut read_count: usize = 0;
        let mut write_count: usize = 0;
        let mut read_sizes: BTreeSet<usize> = BTreeSet::new();
        let mut write_sizes: BTreeSet<usize> = BTreeSet::new();

        let mut handlers: Vec<TranslatedOpcode<'p>> = Vec::new();

        for (index, opcode) in self.circuit.opcodes.iter().enumerate() {
            let handler =
                self.build_handler(
                    index,
                    opcode,
                    &mut block_sizes,
                    &mut read_count,
                    &mut write_count,
                    &mut read_sizes,
                    &mut write_sizes,
                )?;
            handlers.push(handler);
        }

        Ok((handlers, read_sizes, write_sizes))
    }

    /// Dispatches a single opcode to its handler.
    #[allow(clippy::too_many_arguments)]
    fn build_handler(
        &self,
        index: usize,
        opcode: &'p Opcode<FieldElement>,
        block_sizes: &mut HashMap<u32, usize>,
        read_count: &mut usize,
        write_count: &mut usize,
        read_sizes: &mut BTreeSet<usize>,
        write_sizes: &mut BTreeSet<usize>,
    ) -> Result<TranslatedOpcode<'p>, Error> {
        if let Some(range_op) = bitwise::rangecheck::from_opcode(opcode) {
            return Ok(Box::new(range_op));
        }

        if let Some(xor_op) = bitwise::xor::from_opcode(opcode) {
            return Ok(Box::new(xor_op));
        }

        if let Some(and_op) = bitwise::and::from_opcode(opcode) {
            return Ok(Box::new(and_op));
        }

        match opcode {
            Opcode::AssertZero(expr) => Ok(Box::new(AssertZero { expr, index })),
            Opcode::Call {
                id,
                inputs,
                outputs,
                predicate,
            } => {
                let callee = self.program.functions.get(id.as_usize()).ok_or(
                    Error::OutOfRangeCallTarget {
                        id: id.0,
                        num_circuits: self.program.functions.len(),
                    },
                )?;
                Ok(Box::new(Call::new(
                    index, id.0, inputs, outputs, callee, predicate,
                )))
            }
            Opcode::MemoryInit {
                block_id,
                init,
                block_type,
            } => match block_type {
                BlockType::Memory => {
                    block_sizes.insert(block_id.0, init.len());
                    Ok(Box::new(MemoryInit {
                        block_id: block_id.0,
                        init,
                    }))
                }
                _ => Err(Error::UnsupportedOpcode(format!(
                    "MemoryInit with block_type {block_type:?}"
                ))),
            },
            Opcode::MemoryOp {
                block_id,
                op: mem_op,
                ..
            } => {
                let array_len = *block_sizes.get(&block_id.0).ok_or(
                    Error::UninitializedMemoryBlock {
                        block_id: block_id.0,
                        opcode_index: index,
                    },
                )?;

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
                    let mi = *write_count;
                    *write_count += 1;
                    write_sizes.insert(array_len);
                    Ok(Box::new(MemoryWrite {
                        member_index: mi,
                        block_id: block_id.0,
                        array_len,
                        index_expr: &mem_op.index,
                        value_expr: &mem_op.value,
                    }))
                } else {
                    let mi = *read_count;
                    *read_count += 1;
                    read_sizes.insert(array_len);
                    Ok(Box::new(MemoryRead {
                        member_index: mi,
                        block_id: block_id.0,
                        array_len,
                        index_expr: &mem_op.index,
                        value_expr: &mem_op.value,
                    }))
                }
            }
            other => Err(Error::UnsupportedOpcode(other.to_string())),
        }
    }

    /// Returns input witness indices sorted by witness index.
    fn sorted_input_witnesses(&self) -> Vec<u32> {
        let mut witnesses: Vec<u32> = self
            .circuit
            .private_parameters
            .iter()
            .map(|w| w.0)
            .chain(self.circuit.public_parameters.0.iter().map(|w| w.0))
            .collect();
        witnesses.sort();
        witnesses
    }

    /// Emits `struct.member @w{i} : !felt.type` for every internal witness
    /// actually referenced by opcodes (excluding inputs, which live as function
    /// parameters).
    ///
    /// Public return witnesses are marked `{llzk.pub}`.
    fn emit_witness_members(
        &self,
        struct_def: &StructDefOp<'c>,
        input_witnesses: &[u32],
        opcode_witnesses: &BTreeSet<u32>,
    ) -> Result<(), Error> {
        let location = Location::unknown(self.context);
        let felt_type = FeltType::with_field(self.context, FIELD_NAME);

        let input_set: HashSet<u32> = input_witnesses.iter().copied().collect();
        let public_witnesses: HashSet<u32> =
            self.circuit.return_values.0.iter().map(|w| w.0).collect();

        // Only emit members for witnesses that opcodes actually reference.
        // Skip inputs — they are available as function parameters.
        for &i in opcode_witnesses {
            if input_set.contains(&i) {
                continue;
            }
            let member_name = format!("w{i}");
            let is_public = public_witnesses.contains(&i);
            let member =
                dialect::r#struct::member(location, &member_name, felt_type, false, is_public)?;
            struct_def.body().append_operation(member.into());
        }

        Ok(())
    }

    /// Builds the function parameter list: one `!felt.type` per input witness.
    fn build_input_list(&self, input_witnesses: &[u32]) -> Vec<(Type<'c>, Location<'c>)> {
        let location = Location::unknown(self.context);
        let felt_type = FeltType::with_field(self.context, FIELD_NAME);
        input_witnesses
            .iter()
            .map(|_| (felt_type.into(), location))
            .collect()
    }

    /// Builds argument attributes: `{llzk.pub}` for public inputs, empty for private.
    fn build_input_attrs(&self, input_witnesses: &[u32]) -> Vec<Vec<NamedAttribute<'c>>> {
        let pub_attr = vec![PublicAttribute::new_named_attr(self.context)];
        let no_attr: Vec<NamedAttribute> = vec![];

        let public_set: HashSet<u32> = self
            .circuit
            .public_parameters
            .0
            .iter()
            .map(|w| w.0)
            .collect();

        input_witnesses
            .iter()
            .map(|w| {
                if public_set.contains(w) {
                    pub_attr.clone()
                } else {
                    no_attr.clone()
                }
            })
            .collect()
    }
}
