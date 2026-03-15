use std::collections::HashSet;

use acir::{
    FieldElement,
    circuit::{Circuit, Program},
};
use llzk::{
    attributes::NamedAttribute,
    prelude::{
        BlockLike, FeltType, LlzkContext, LlzkError, Location, Operation, PublicAttribute,
        StructDefOp, StructDefOpLike, StructType, Type, dialect,
    },
};

use crate::{
    Error, FIELD_NAME, compute::ComputeWriter, constrain::ConstraintWriter,
    opcode::TranslatedOpcode,
};

/// Translates a single ACIR [`Circuit`] into an LLZK [`StructDefOp`].
///
/// Holds all circuit-level context (program reference for `Call` resolution,
/// sub-component counter for naming) and runs the three emission phases in
/// order: struct members → `@compute` body → `@constrain` body.
pub(crate) struct CircuitTranslator<'c, 'p> {
    context: &'c LlzkContext,
    circuit: &'p Circuit<FieldElement>,
    /// Full program, needed to resolve called circuits by index for `Call`.
    #[allow(dead_code)]
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

    /// Runs the full translation pipeline and returns the completed struct.
    ///
    /// 1. `build_handlers` — converts ACIR opcodes to [`TranslatedOpcode`]s,
    ///    pre-computing all metadata (member names, circuit names for `Call`).
    /// 2. `emit_witness_members` — adds `struct.member @w{i} : !felt.type` for
    ///    each internal witness.
    /// 3. Iterate opcodes → `emit_member` (subcomponent members for `Call`).
    /// 4. Build and populate the `@compute` function.
    /// 5. Build and populate the `@constrain` function.
    pub(crate) fn translate(self, circuit_index: usize) -> Result<StructDefOp<'c>, Error> {
        let location = Location::unknown(self.context);
        let struct_name = format!("Circuit{circuit_index}");

        let struct_def = dialect::r#struct::def(
            location,
            &struct_name,
            &[],
            [] as [Result<Operation, LlzkError>; 0],
        )?;

        let ops = self.build_handlers()?;
        let input_witnesses = self.sorted_input_witnesses();

        // Phase 1: struct members
        self.emit_witness_members(&struct_def, &input_witnesses)?;
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
        let mut compute_writer = ComputeWriter::new(self.context, &struct_def, &input_witnesses)?;
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
            ConstraintWriter::new(self.context, &struct_def, &input_witnesses)?;
        for op in &ops {
            op.emit_constrain(&mut constrain_writer)?;
        }

        Ok(struct_def)
    }

    /// Converts each ACIR opcode into a [`TranslatedOpcode`], pre-computing
    /// all metadata needed by the emission phases.
    fn build_handlers(&self) -> Result<Vec<TranslatedOpcode<'p>>, Error> {
        self.circuit
            .opcodes
            .iter()
            .enumerate()
            .map(|(index, opcode)| TranslatedOpcode::from_acir(opcode, index))
            .collect()
    }

    /// Returns input witness indices: private parameters first, then public,
    /// each group sorted by index.
    fn sorted_input_witnesses(&self) -> Vec<u32> {
        let mut private: Vec<u32> = self
            .circuit
            .private_parameters
            .iter()
            .map(|w| w.0)
            .collect();
        private.sort();
        let mut public: Vec<u32> = self
            .circuit
            .public_parameters
            .0
            .iter()
            .map(|w| w.0)
            .collect();
        public.sort();
        private.into_iter().chain(public).collect()
    }

    /// Emits `struct.member @w{i} : !felt.type` for every internal witness
    /// (i.e., all witnesses except inputs, which live as function parameters).
    ///
    /// Public return witnesses are marked `{llzk.pub}`.
    fn emit_witness_members(
        &self,
        struct_def: &StructDefOp<'c>,
        input_witnesses: &[u32],
    ) -> Result<(), Error> {
        let location = Location::unknown(self.context);
        let felt_type = FeltType::with_field(self.context, FIELD_NAME);

        let input_set: HashSet<u32> = input_witnesses.iter().copied().collect();
        let public_witnesses: HashSet<u32> =
            self.circuit.return_values.0.iter().map(|w| w.0).collect();

        // `current_witness_index` is the highest index (inclusive range).
        // Skip inputs — they are available as function parameters.
        for i in 0..=self.circuit.current_witness_index {
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
