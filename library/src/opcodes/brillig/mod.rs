//! Brillig (`BrilligCall`) opcode translation.
//!
//! Each `Opcode::BrilligCall` in the caller's ACIR lowers to a
//! `function.call @brillig_{id}` inside the caller's `@compute`. The sibling
//! function body itself lives at module scope and is emitted once per
//! `BrilligFunctionId` after all circuits have been translated — see
//! [`registry::emit_brillig_functions`].
//!
//! Call-site validation (marshalling shapes supported) happens at handler
//! construction in [`crate::circuit::CircuitTranslator`] so that the
//! registry only ever sees well-formed entries.

pub(crate) mod cfg;
mod flow;
mod memory;
mod opcodes;
pub(crate) mod registry;
mod structured_translator;
pub(crate) mod structurer;
mod translator;

use std::collections::BTreeSet;

use acir::{
    FieldElement,
    circuit::brillig::{BrilligFunctionId, BrilligInputs, BrilligOutputs},
    native_types::Expression,
};
use llzk::prelude::{ArrayType, IntegerAttribute, Type, Value, ValueLike};

use crate::{
    block_writer::BlockWriter,
    common::{collect_witnesses, emit_expression, is_trivial_predicate},
    error::Error,
    opcodes::OpcodeEmitter,
};

use self::registry::BrilligRegistry;

/// Translator for a single `Opcode::BrilligCall`.
///
/// Shape validation (input/output marshalling) is performed at construction
/// time by [`crate::circuit::CircuitTranslator::build_handler`], so
/// `emit_compute` can emit without re-checking.
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
    /// 3. For each `Simple` output, gates the returned value by the
    ///    predicate (`predicate * result`) when the predicate is
    ///    non-trivial, then writes the (possibly gated) value into `%self`
    ///    and marks the witness known.
    ///
    /// When the predicate is trivially `1`, outputs are written directly
    /// (no multiplication overhead). When the predicate evaluates to `0`,
    /// all outputs become zero — matching the ACVM's skip-and-zero
    /// semantics for predicate-gated Brillig calls.
    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let felt_ty = writer.felt_type();

        // Evaluate the predicate once (only when non-trivial).
        let pred_val = if is_trivial_predicate(self.predicate) {
            None
        } else {
            Some(emit_expression(writer, self.predicate)?)
        };

        let mut input_args: Vec<Value<'c, 'b>> = Vec::new();
        for input in self.inputs {
            match input {
                BrilligInputs::Single(expr) => {
                    input_args.push(emit_expression(writer, expr)?);
                }
                BrilligInputs::Array(exprs) => {
                    for expr in exprs {
                        input_args.push(emit_expression(writer, expr)?);
                    }
                }
                BrilligInputs::MemoryArray(block_id) => {
                    let arr =
                        writer
                            .get_memory(block_id.0)
                            .ok_or_else(|| Error::UnsupportedBrillig {
                                reason: format!(
                                    "MemoryArray input references block {} which has \
                                 not been initialised by a prior MemoryInit",
                                    block_id.0
                                ),
                            })?;
                    let arr_ty = ArrayType::try_from(arr.r#type()).map_err(|_| {
                        Error::UnsupportedBrillig {
                            reason: format!("MemoryArray block {} has non-array type", block_id.0),
                        }
                    })?;
                    let len = IntegerAttribute::try_from(arr_ty.dim(0))
                        .map_err(|_| Error::UnsupportedBrillig {
                            reason: format!(
                                "MemoryArray block {} has non-integer dimension",
                                block_id.0
                            ),
                        })?
                        .value() as usize;
                    for i in 0..len {
                        let idx = writer.insert_integer(i)?;
                        let elem = writer.insert_array_read(arr, idx)?;
                        input_args.push(elem);
                    }
                }
            }
        }

        let mut output_types: Vec<Type<'c>> = Vec::new();
        let mut output_witnesses: Vec<u32> = Vec::new();
        for output in self.outputs {
            match output {
                BrilligOutputs::Simple(w) => {
                    output_types.push(felt_ty);
                    output_witnesses.push(w.0);
                }
                BrilligOutputs::Array(ws) => {
                    for w in ws {
                        output_types.push(felt_ty);
                        output_witnesses.push(w.0);
                    }
                }
            }
        }

        let name = BrilligRegistry::function_name(self.id);
        let call = writer.call_top_level_function(&name, &input_args, &output_types)?;

        for (i, w_idx) in output_witnesses.iter().enumerate() {
            let ret: Value<'c, 'b> = call.result(i)?.into();
            let gated = match pred_val {
                None => ret,
                Some(p) => writer.insert_mul(p, ret)?,
            };
            writer.write_member(&format!("w{w_idx}"), gated)?;
            writer.mark_known(*w_idx, gated);
        }

        Ok(())
    }
}
