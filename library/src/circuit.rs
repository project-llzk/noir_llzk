use std::collections::{BTreeSet, HashSet};

use acir::{
    FieldElement,
    circuit::{Circuit, Opcode, Program},
};
use llzk::{
    attributes::NamedAttribute,
    prelude::{
        BlockLike, FeltType, LlzkContext, Location, PublicAttribute, StructDefOp, StructDefOpLike,
        StructType, Type, dialect,
    },
};

use crate::{
    Error, FIELD_NAME,
    block_writer::BlockWriter,
    common::{empty_struct, field_member},
    opcodes::{
        BuildContext, TranslatedOpcode, assert_zero::AssertZero, bitwise, call::Call,
        memory_init::MemoryInit, memory_op,
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
    pub(crate) fn translate(self, circuit_index: usize) -> Result<Vec<StructDefOp<'c>>, Error> {
        let location = Location::unknown(self.context);
        let struct_name = format!("Circuit{circuit_index}");

        let struct_def = empty_struct(location, &struct_name)?;

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
        let mut ctx = BuildContext::new(self.program);
        let mut handlers: Vec<TranslatedOpcode<'p>> = Vec::new();

        for (index, opcode) in self.circuit.opcodes.iter().enumerate() {
            handlers.push(Self::build_handler(index, opcode, &mut ctx)?);
        }

        Ok((handlers, ctx.read_sizes, ctx.write_sizes))
    }

    /// Dispatches a single opcode to its handler.
    fn build_handler(
        index: usize,
        opcode: &'p Opcode<FieldElement>,
        ctx: &mut BuildContext<'p>,
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
            Opcode::Call { .. } => Ok(Box::new(Call::from_opcode(opcode, index, ctx)?)),
            Opcode::MemoryInit { .. } => Ok(Box::new(MemoryInit::from_opcode(opcode, ctx)?)),
            Opcode::MemoryOp { .. } => memory_op::from_opcode(opcode, index, ctx),
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
            struct_def.body().append_operation(field_member(
                location,
                self.context,
                &member_name,
                is_public,
            )?);
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
