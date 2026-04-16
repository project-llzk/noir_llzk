//! Brillig (`BrilligCall`) opcode translation.
//!
//! Each `Opcode::BrilligCall` in the caller's ACIR lowers to a
//! `function.call @brillig_{id}` inside the caller's `@compute`. The sibling
//! function body itself lives at module scope and is emitted once per
//! `BrilligFunctionId` after all circuits have been translated — see
//! [`registry::emit_brillig_functions`].
//!
//! Call-site validation (predicate trivial, marshalling shapes supported)
//! happens at handler construction in [`crate::circuit::CircuitTranslator`]
//! so that the registry only ever sees well-formed entries.

pub(crate) mod registry;
pub(crate) mod regmap;
pub(crate) mod translator;

use std::collections::BTreeSet;

use acir::{
    FieldElement,
    circuit::brillig::{BrilligFunctionId, BrilligInputs, BrilligOutputs},
    native_types::Expression,
};
use llzk::prelude::{Type, Value};

use crate::{
    block_writer::BlockWriter,
    common::{collect_witnesses, emit_expression},
    error::Error,
    opcodes::OpcodeEmitter,
};

use self::registry::BrilligRegistry;

/// Translator for a single `Opcode::BrilligCall`.
///
/// Shape validation (predicate, input/output marshalling) is performed at
/// construction time by [`crate::circuit::CircuitTranslator::build_handler`],
/// so `emit_compute` can emit without re-checking.
pub(crate) struct BrilligCall<'p> {
    id: BrilligFunctionId,
    inputs: &'p [BrilligInputs<FieldElement>],
    outputs: &'p [BrilligOutputs],
    predicate: &'p Expression<FieldElement>,
}

impl<'p> BrilligCall<'p> {
    pub(crate) fn new(
        id: BrilligFunctionId,
        inputs: &'p [BrilligInputs<FieldElement>],
        outputs: &'p [BrilligOutputs],
        predicate: &'p Expression<FieldElement>,
    ) -> Self {
        Self {
            id,
            inputs,
            outputs,
            predicate,
        }
    }
}

impl<'p> OpcodeEmitter for BrilligCall<'p> {
    fn get_witnesses(&self) -> BTreeSet<u32> {
        let mut witnesses = BTreeSet::new();
        for input in self.inputs {
            match input {
                BrilligInputs::Single(expr) => {
                    witnesses.extend(collect_witnesses(expr));
                }
                BrilligInputs::Array(exprs) => {
                    for expr in exprs {
                        witnesses.extend(collect_witnesses(expr));
                    }
                }
                BrilligInputs::MemoryArray(_) => {}
            }
        }
        for output in self.outputs {
            match output {
                BrilligOutputs::Simple(w) => {
                    witnesses.insert(w.0);
                }
                BrilligOutputs::Array(ws) => {
                    for w in ws {
                        witnesses.insert(w.0);
                    }
                }
            }
        }
        witnesses.extend(collect_witnesses(self.predicate));
        witnesses
    }

    /// In `@compute`, emits:
    /// 1. Each `Single` input expression evaluated to an SSA value.
    /// 2. `function.call @brillig_{id}(args)` — the callee body is built
    ///    later by [`registry::emit_brillig_functions`].
    /// 3. For each `Simple` output, writes the returned value into `%self`
    ///    and marks the witness known.
    ///
    /// Inputs/outputs must be `Single`/`Simple`; the predicate must be
    /// trivial. Those are enforced at handler construction.
    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let felt_ty = writer.felt_type();

        let mut input_args: Vec<Value<'c, 'b>> = Vec::with_capacity(self.inputs.len());
        for input in self.inputs {
            match input {
                BrilligInputs::Single(expr) => {
                    input_args.push(emit_expression(writer, expr)?);
                }
                BrilligInputs::Array(_) | BrilligInputs::MemoryArray(_) => {
                    // Validated out at handler construction.
                    unreachable!("non-Single brillig input survived validation");
                }
            }
        }

        let mut output_types: Vec<Type<'c>> = Vec::with_capacity(self.outputs.len());
        let mut output_witnesses: Vec<u32> = Vec::with_capacity(self.outputs.len());
        for output in self.outputs {
            match output {
                BrilligOutputs::Simple(w) => {
                    output_types.push(felt_ty);
                    output_witnesses.push(w.0);
                }
                BrilligOutputs::Array(_) => {
                    unreachable!("non-Simple brillig output survived validation");
                }
            }
        }

        let name = BrilligRegistry::function_name(self.id);
        let call = writer.call_top_level_function(&name, &input_args, &output_types)?;

        for (i, w_idx) in output_witnesses.iter().enumerate() {
            let ret: Value<'c, 'b> = call.result(i)?.into();
            writer.write_member(&format!("w{w_idx}"), ret)?;
            writer.mark_known(*w_idx, ret);
        }

        Ok(())
    }
}
