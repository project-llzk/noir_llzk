//! Structured translator: walks a [`StructuredFunction`] tree and emits
//! LLZK IR via the existing per-opcode handlers from [`super::translator`].
//!
//! Replaces the flat per-bytecode-index walk in [`super::translator::translate_bytecode`]
//! for bodies that the structurer succeeds on. Each region node emits the
//! corresponding scf-shaped IR; per-opcode emission inside a `Linear` block
//! is delegated to [`translate_block_body`].
//!

use acir::FieldElement;
use acir::brillig::{MemoryAddress, Opcode as BrilligOpcode};
use acir::circuit::brillig::BrilligBytecode;
use brillig_vm::FREE_MEMORY_POINTER_ADDRESS;
use llzk::prelude::{Block, Value};

use crate::brillig_writer::BrilligWriter;
use crate::error::Error;

use super::cfg::Cfg;
use super::memory::Memory;
use super::structurer::{
    CondPolarity, EscapeFlagSlot, LoopCondition, RegionNode, StructuredFunction,
};
use super::translator::{TranslationCtx, translate_block_body};

/// Emits the [`StructuredFunction::main`] body for a Brillig sibling
/// function.
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
        escape_flag_addrs: Vec::new(),
    };

    init_escape_flags(&mut ctx, structured.main_escape_flag_count)?;

    let (tail, head) = structured
        .main
        .split_last()
        .ok_or_else(|| Error::UnsupportedBrillig {
            reason: "structured main body is empty (must end with Stop)".into(),
        })?;

    emit_body(&mut ctx, &bytecode.bytecode, cfg, head)?;

    let RegionNode::Stop { block: stop_block } = tail else {
        return Err(Error::UnsupportedBrillig {
            reason: format!("structured main body must end with Stop, found {tail:?}"),
        });
    };
    let bd = &cfg.blocks[stop_block.0];
    let stop_idx = bd.end_exclusive - 1;
    match &bytecode.bytecode[stop_idx] {
        BrilligOpcode::Stop { return_data } => ctx.emit_return_data(return_data, stop_idx),
        other => Err(Error::UnsupportedBrillig {
            reason: format!(
                "Stop region node at b{} expects a Stop opcode at index \
                 {stop_idx}, found {other:?}",
                stop_block.0
            ),
        }),
    }
}

fn emit_body<'c, 'b>(
    ctx: &mut TranslationCtx<'c, 'b, '_>,
    bytecode: &[BrilligOpcode<FieldElement>],
    cfg: &Cfg,
    nodes: &[RegionNode],
) -> Result<(), Error> {
    for node in nodes {
        emit_node(ctx, bytecode, cfg, node)?;
    }
    Ok(())
}

fn emit_node<'c, 'b>(
    ctx: &mut TranslationCtx<'c, 'b, '_>,
    bytecode: &[BrilligOpcode<FieldElement>],
    cfg: &Cfg,
    node: &RegionNode,
) -> Result<(), Error> {
    match node {
        RegionNode::Linear { block } => {
            let bd = &cfg.blocks[block.0];
            translate_block_body(ctx, bytecode, bd.start..bd.end_exclusive)
        }

        RegionNode::Stop { .. } => unreachable!(
            "RegionNode::Stop is peeled off in translate_structured before \
             emit_body runs; the structurer guarantees Stop appears only as \
             the tail of main"
        ),

        RegionNode::Trap { .. } => {
            // Unconditional failure: assert(0 == 1).
            let zero = ctx.writer.emit_constant(&FieldElement::from(0u128))?;
            let one = ctx.writer.emit_constant(&FieldElement::from(1u128))?;
            let always_false = ctx.writer.insert_bool_eq(zero, one)?;
            ctx.writer.insert_bool_assert(always_false)?;
            Ok(())
        }

        RegionNode::BoolAssert { condition, .. } => {
            let cond_felt = ctx.memory.read(ctx.writer, *condition)?;
            let cond_bool = ctx.writer.insert_felt_to_bool(cond_felt)?;
            ctx.writer.insert_bool_assert(cond_bool)?;
            Ok(())
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
            then_outcome?;

            let else_block = Block::new(&[]);
            let saved = ctx.writer.enter_block(&else_block);
            let else_outcome = emit_body(ctx, bytecode, cfg, else_branch);
            ctx.writer.leave_block(saved);
            else_outcome?;

            ctx.writer
                .insert_scf_if(cond_bool, then_block, else_block)?;
            Ok(())
        }

        RegionNode::Loop {
            test_prefix,
            condition,
            escape_flag,
            body,
            header,
        } => {
            // before-region: emit `test_prefix`, compute the i1
            // continuation condition (`loop_cond AND !escape_flag` with
            // either side optional), terminate with `scf.condition`.
            let before_block = Block::new(&[]);
            let saved = ctx.writer.enter_block(&before_block);
            let before_outcome = (|| -> Result<(), Error> {
                emit_body(ctx, bytecode, cfg, test_prefix)?;
                let continue_cond =
                    compute_loop_continue_cond(ctx, condition, *escape_flag, *header)?;
                ctx.writer.insert_scf_condition(continue_cond);
                Ok(())
            })();
            ctx.writer.leave_block(saved);
            before_outcome?;

            // after-region: emit body, terminate with `scf.yield`.
            let after_block = Block::new(&[]);
            let saved = ctx.writer.enter_block(&after_block);
            let body_outcome = emit_body(ctx, bytecode, cfg, body);
            ctx.writer.insert_scf_yield();
            ctx.writer.leave_block(saved);
            body_outcome?;

            ctx.writer.insert_scf_while(before_block, after_block)?;
            Ok(())
        }

        RegionNode::SetEscapeFlag { slot } => {
            let one = ctx.writer.emit_constant(&FieldElement::from(1u128))?;
            let addr = ctx.escape_flag_addrs[slot.0];
            ctx.writer.insert_ram_store(addr, one);
            Ok(())
        }
    }
}

/// Allocates `count` escape-flag cells from the Brillig heap by bumping
/// `FREE_MEMORY_POINTER_ADDRESS` (`@1`), captures their index-typed
/// addresses on the context, and zero-initialises them so loop test-prefix
/// reads observe `flag = 0` on the first iteration.
///
/// Cooperates with the Brillig program's own allocator: the bump tells
/// any subsequent FMP-routed allocation to skip our slots.
fn init_escape_flags<'c, 'b>(
    ctx: &mut TranslationCtx<'c, 'b, '_>,
    count: usize,
) -> Result<(), Error> {
    if count == 0 {
        return Ok(());
    }

    let fmp_addr = ctx.writer.insert_integer(fmp_slot())?;
    let fmp_felt = ctx.writer.insert_ram_load(fmp_addr)?;
    let fmp_idx = ctx.writer.cast_to_index(fmp_felt)?;

    ctx.escape_flag_addrs = Vec::with_capacity(count);
    for i in 0..count {
        let slot_addr = if i == 0 {
            fmp_idx
        } else {
            let offset = ctx.writer.insert_integer(i)?;
            ctx.writer.insert_index_add(fmp_idx, offset)?
        };
        ctx.escape_flag_addrs.push(slot_addr);
    }

    let count_idx = ctx.writer.insert_integer(count)?;
    let bumped_idx = ctx.writer.insert_index_add(fmp_idx, count_idx)?;
    let bumped_felt = ctx.writer.insert_cast_to_felt(bumped_idx)?;
    ctx.writer.insert_ram_store(fmp_addr, bumped_felt);

    let zero = ctx.writer.emit_constant(&FieldElement::from(0u128))?;
    for &slot_addr in &ctx.escape_flag_addrs {
        ctx.writer.insert_ram_store(slot_addr, zero);
    }
    Ok(())
}

/// Builds the `i1` continuation condition for an `scf.while`:
///   - `Some(loop_cond)`: load the register, convert felt → i1; invert
///     when polarity is `ExitOnTrue` so "true means continue".
///   - `Some(slot)`: load the escape flag, convert to i1, invert (we
///     want "true means *not* set, i.e. continue").
///   - When both are present, AND them.
fn compute_loop_continue_cond<'c, 'b>(
    ctx: &mut TranslationCtx<'c, 'b, '_>,
    condition: &Option<LoopCondition>,
    escape_flag: Option<EscapeFlagSlot>,
    header: super::cfg::BlockId,
) -> Result<Value<'c, 'b>, Error> {
    let from_cond = match condition {
        Some(loop_cond) => {
            let cond_felt = ctx.memory.read(ctx.writer, loop_cond.register)?;
            let cond_bool = ctx.writer.insert_felt_to_bool(cond_felt)?;
            Some(match loop_cond.polarity {
                CondPolarity::ContinueOnTrue => cond_bool,
                CondPolarity::ExitOnTrue => ctx.writer.insert_bool_not(cond_bool)?,
            })
        }
        None => None,
    };
    let from_flag = match escape_flag {
        Some(slot) => {
            let addr = ctx.escape_flag_addrs[slot.0];
            let flag_felt = ctx.writer.insert_ram_load(addr)?;
            let flag_bool = ctx.writer.insert_felt_to_bool(flag_felt)?;
            Some(ctx.writer.insert_bool_not(flag_bool)?)
        }
        None => None,
    };
    match (from_cond, from_flag) {
        (Some(c), Some(f)) => ctx.writer.insert_bool_and(c, f),
        (Some(c), None) => Ok(c),
        (None, Some(f)) => Ok(f),
        (None, None) => Err(Error::UnsupportedBrillig {
            reason: format!(
                "Loop(header=b{}): no condition and no escape flag — \
                 infinite loop with no exit",
                header.0
            ),
        }),
    }
}

fn fmp_slot() -> usize {
    match FREE_MEMORY_POINTER_ADDRESS {
        MemoryAddress::Direct(s) => s as usize,
        MemoryAddress::Relative(_) => {
            unreachable!("FREE_MEMORY_POINTER_ADDRESS is defined as Direct in brillig_vm")
        }
    }
}
