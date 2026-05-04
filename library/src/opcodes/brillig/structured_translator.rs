//! Structured translator: walks a [`StructuredFunction`] tree and emits
//! LLZK IR via the existing per-opcode handlers from [`super::translator`].
//!
//! Replaces the flat per-bytecode-index walk in [`super::translator::translate_bytecode`]
//! for bodies that the structurer succeeds on. Each region node emits the
//! corresponding scf-shaped IR; per-opcode emission inside a `Linear` block
//! is delegated to [`translate_block_body`].
//!
//! Phase B: leaf-ish nodes only (`Linear`, `Stop`, `Return`, `Trap`,
//! `BoolAssert`). `IfThenElse`, `Loop`, `Call`, and `SetEscapeFlag` return
//! [`Error::UnsupportedBrillig`] until later phases wire them up.

use acir::FieldElement;
use acir::brillig::Opcode as BrilligOpcode;
use acir::circuit::brillig::BrilligBytecode;
use llzk::prelude::{Block, Value};

use crate::brillig_writer::BrilligWriter;
use crate::error::Error;

use super::cfg::Cfg;
use super::memory::Memory;
use super::structurer::{RegionNode, StructuredFunction};
use super::translator::{OpcodeAction, TranslationCtx, translate_block_body};

/// Outcome of emitting one node or a sibling sequence.
enum EmitOutcome<'c, 'b> {
    /// Continue with the next sibling.
    Continue,
    /// `Stop` was hit; carry its return values to the function-level caller.
    Returned(Vec<Value<'c, 'b>>),
}

/// Defensive check: the structured emitter relies on the structurer
/// invariant that `Stop` / `Return` only appear at body top level
/// (asserted by `noir_examples_terminator_placement_audit`). If a
/// `Returned` outcome ever bubbles up from inside an `IfThenElse` arm
/// or `Loop` body we'd need a return-flag side channel through scf
/// regions, so surface it as `UnsupportedBrillig` rather than emit
/// silently broken IR.
fn forbid_nested_return<'c, 'b>(arm: &str, outcome: EmitOutcome<'c, 'b>) -> Result<(), Error> {
    match outcome {
        EmitOutcome::Continue => Ok(()),
        EmitOutcome::Returned(_) => Err(Error::UnsupportedBrillig {
            reason: format!(
                "structurer invariant violated: Stop/Return found inside \
                 {arm} of a nested region. The structured emitter assumes \
                 Noir's codegen sinks all returns to top-level (verified by \
                 `noir_examples_terminator_placement_audit`); handling this \
                 shape would require a return-flag side channel through scf"
            ),
        }),
    }
}

/// Emits the [`StructuredFunction::main`] body for a Brillig sibling
/// function. Procedures are not yet handled (Phase E); a tree containing
/// `Call` / `Return` will hit [`Error::UnsupportedBrillig`].
pub(crate) fn translate_structured<'c, 'b>(
    writer: &mut BrilligWriter<'c, 'b>,
    bytecode: &BrilligBytecode<FieldElement>,
    cfg: &Cfg,
    structured: &StructuredFunction,
    calldata: &[Value<'c, 'b>],
    expected_output_count: usize,
) -> Result<Vec<Value<'c, 'b>>, Error> {
    let mut ctx = TranslationCtx {
        writer,
        memory: Memory::new(),
        calldata,
        expected_output_count,
    };

    match emit_body(&mut ctx, &bytecode.bytecode, cfg, &structured.main)? {
        EmitOutcome::Returned(vals) => Ok(vals),
        EmitOutcome::Continue => {
            if ctx.expected_output_count != 0 {
                return Err(Error::UnsupportedBrillig {
                    reason: format!(
                        "brillig function declares {} output(s) but the structured \
                         body ended without a Stop",
                        ctx.expected_output_count
                    ),
                });
            }
            Ok(Vec::new())
        }
    }
}

fn emit_body<'c, 'b>(
    ctx: &mut TranslationCtx<'c, 'b, '_>,
    bytecode: &[BrilligOpcode<FieldElement>],
    cfg: &Cfg,
    nodes: &[RegionNode],
) -> Result<EmitOutcome<'c, 'b>, Error> {
    for node in nodes {
        if let outcome @ EmitOutcome::Returned(_) = emit_node(ctx, bytecode, cfg, node)? {
            return Ok(outcome);
        }
    }
    Ok(EmitOutcome::Continue)
}

fn emit_node<'c, 'b>(
    ctx: &mut TranslationCtx<'c, 'b, '_>,
    bytecode: &[BrilligOpcode<FieldElement>],
    cfg: &Cfg,
    node: &RegionNode,
) -> Result<EmitOutcome<'c, 'b>, Error> {
    match node {
        RegionNode::Linear { block } => {
            let bd = &cfg.blocks[block.0];
            // `Linear` covers the block body — every opcode except the
            // terminator (which is structurally represented by a sibling
            // node such as `Stop`, `Trap`, or the `IfThenElse`/`Loop`
            // surrounding this Linear).
            let range = bd.start..(bd.end_exclusive - 1);
            match translate_block_body(ctx, bytecode, range)? {
                OpcodeAction::Continue => Ok(EmitOutcome::Continue),
                OpcodeAction::Return(_) => Err(Error::UnsupportedBrillig {
                    reason: format!(
                        "Linear(b{}) emitted an unexpected Return: a Stop opcode \
                         must be exposed as a Stop region node by the structurer",
                        block.0
                    ),
                }),
            }
        }

        RegionNode::Stop { block } => {
            // Drive the existing StopHandler against the single Stop opcode
            // at the end of the block; it reads the return_data HeapVector
            // and returns the slot values.
            let bd = &cfg.blocks[block.0];
            let stop_idx = bd.end_exclusive - 1;
            match translate_block_body(ctx, bytecode, stop_idx..bd.end_exclusive)? {
                OpcodeAction::Return(vals) => Ok(EmitOutcome::Returned(vals)),
                OpcodeAction::Continue => Err(Error::UnsupportedBrillig {
                    reason: format!(
                        "Stop region node at b{} did not produce return data — \
                         the terminator opcode at index {stop_idx} is not a Stop",
                        block.0
                    ),
                }),
            }
        }

        RegionNode::Trap { .. } => {
            // Unconditional failure: assert(0 == 1).
            let zero = ctx.writer.emit_constant(&FieldElement::from(0u128))?;
            let one = ctx.writer.emit_constant(&FieldElement::from(1u128))?;
            let always_false = ctx.writer.insert_bool_eq(zero, one)?;
            ctx.writer.insert_bool_assert(always_false)?;
            Ok(EmitOutcome::Continue)
        }

        RegionNode::BoolAssert { condition, .. } => {
            let cond_felt = ctx.memory.read(ctx.writer, *condition)?;
            let cond_bool = ctx.writer.insert_felt_to_bool(cond_felt)?;
            ctx.writer.insert_bool_assert(cond_bool)?;
            Ok(EmitOutcome::Continue)
        }

        RegionNode::Return { .. } => Err(Error::UnsupportedBrillig {
            reason: "Return region node not yet supported by structured emitter \
                     (Phase E: procedure emission)"
                .into(),
        }),

        RegionNode::Call { target } => Err(Error::UnsupportedBrillig {
            reason: format!(
                "Call(target=b{}) not yet supported by structured emitter \
                 (Phase E: procedure emission)",
                target.0
            ),
        }),

        RegionNode::IfThenElse {
            condition,
            then_branch,
            else_branch,
            ..
        } => {
            // Materialise the i1 condition in `current_block` so both
            // arms can see it.
            let cond_felt = ctx.memory.read(ctx.writer, *condition)?;
            let cond_bool = ctx.writer.insert_felt_to_bool(cond_felt)?;

            let then_block = Block::new(&[]);
            let saved = ctx.writer.enter_block(&then_block);
            let then_outcome = emit_body(ctx, bytecode, cfg, then_branch);
            ctx.writer.leave_block(saved);
            forbid_nested_return("then", then_outcome?)?;

            let else_block = Block::new(&[]);
            let saved = ctx.writer.enter_block(&else_block);
            let else_outcome = emit_body(ctx, bytecode, cfg, else_branch);
            ctx.writer.leave_block(saved);
            forbid_nested_return("else", else_outcome?)?;

            ctx.writer
                .insert_scf_if(cond_bool, then_block, else_block)?;
            Ok(EmitOutcome::Continue)
        }

        RegionNode::Loop { header, .. } => Err(Error::UnsupportedBrillig {
            reason: format!(
                "Loop(header=b{}) not yet supported by structured emitter (Phase D)",
                header.0
            ),
        }),

        RegionNode::SetEscapeFlag { .. } => Err(Error::UnsupportedBrillig {
            reason: "SetEscapeFlag region node not yet supported by structured emitter \
                     (Phase D)"
                .into(),
        }),
    }
}
