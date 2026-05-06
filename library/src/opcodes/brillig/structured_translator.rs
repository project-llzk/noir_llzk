//! Structured translator: walks a [`StructuredFunction`] tree and emits
//! LLZK IR via the existing per-opcode handlers from [`super::translator`].
//!
//! Replaces the flat per-bytecode-index walk in [`super::translator::translate_bytecode`]
//! for bodies that the structurer succeeds on. Each region node emits the
//! corresponding scf-shaped IR; per-opcode emission inside a `Linear` block
//! is delegated to [`translate_block_body`].

use std::collections::HashSet;

use acir::FieldElement;
use acir::brillig::{MemoryAddress, Opcode as BrilligOpcode};
use acir::circuit::brillig::BrilligBytecode;
use brillig_vm::FREE_MEMORY_POINTER_ADDRESS;
use llzk::dialect::function::def;
use llzk::prelude::{
    Block, BlockLike, FuncDefOpLike, FunctionType, LlzkContext, Location, Module, OperationLike,
    RegionLike, Value, dialect,
};

use crate::brillig_writer::BrilligWriter;
use crate::error::Error;

use super::cfg::{BlockId, Cfg};
use super::memory::Memory;
use super::registry::{BrilligRegistry, BrilligVariantKey};
use super::structurer::{
    CondPolarity, EscapeFlagSlot, LoopCondition, RegionNode, StructuredFunction,
    StructuredProcedure,
};
use super::translator::{TranslationCtx, translate_block_body};

/// Per-Brillig-function emission state.
pub(crate) struct ProcedureEmitter<'c, 'p> {
    pub(crate) context: &'c LlzkContext,
    pub(crate) module: &'p Module<'c>,
    pub(crate) location: Location<'c>,
    pub(crate) bytecode: &'p BrilligBytecode<FieldElement>,
    pub(crate) cfg: &'p Cfg,
    pub(crate) procedures: &'p [StructuredProcedure],
    pub(crate) variant: BrilligVariantKey,
    emitted: HashSet<BlockId>,
}

impl<'c, 'p> ProcedureEmitter<'c, 'p> {
    pub(crate) fn new(
        context: &'c LlzkContext,
        module: &'p Module<'c>,
        location: Location<'c>,
        bytecode: &'p BrilligBytecode<FieldElement>,
        cfg: &'p Cfg,
        procedures: &'p [StructuredProcedure],
        variant: BrilligVariantKey,
    ) -> Self {
        Self {
            context,
            module,
            location,
            bytecode,
            cfg,
            procedures,
            variant,
            emitted: HashSet::new(),
        }
    }

    /// Emits the procedure whose entry is `target` if it hasn't been
    /// emitted yet.
    fn ensure_emitted<M: Memory>(
        &mut self,
        target: BlockId,
        memory: &mut M,
    ) -> Result<(), Error> {
        if !self.emitted.insert(target) {
            return Ok(());
        }

        // Copy the procedures slice out so the lookup borrows from `'p`,
        // not from `&mut self`. This lets us hand `&mut self` back to
        // the recursive procedure walker while `proc` is still live.
        let procedures: &'p [StructuredProcedure] = self.procedures;
        let proc = procedures
            .iter()
            .find(|p| p.entry == target)
            .ok_or_else(|| Error::UnsupportedBrillig {
                reason: format!(
                    "structured procedure for entry b{} not found in brillig function {}",
                    target.0, self.variant.id.0
                ),
            })?;

        let proc_func_type = FunctionType::new(self.context, &[], &[]);
        let proc_name = BrilligRegistry::procedure_function_name(self.variant, target);
        let proc_func = def(self.location, &proc_name, proc_func_type, &[], None)?;
        proc_func.set_allow_witness_attr(true);
        proc_func.set_allow_non_native_field_ops_attr(true);

        let proc_body = Block::new(&[]);
        let mut proc_writer = BrilligWriter::new(self.context, &proc_body);
        translate_structured_procedure(&mut proc_writer, memory, self, proc)?;
        proc_body.append_operation(dialect::function::r#return(self.location, &[]));
        proc_func.region(0)?.append_block(proc_body);
        self.module.body().append_operation(proc_func.into());
        Ok(())
    }
}

/// Emits the [`StructuredFunction::main`] body for a Brillig sibling
/// function. Procedures referenced from the walk are emitted lazily via
/// `emitter`.
pub(crate) fn translate_structured<'c, 'b, M: Memory>(
    writer: &mut BrilligWriter<'c, 'b>,
    memory: &mut M,
    emitter: &mut ProcedureEmitter<'c, '_>,
    structured: &StructuredFunction,
    calldata: &[Value<'c, 'b>],
    expected_output_count: usize,
) -> Result<Vec<Value<'c, 'b>>, Error> {
    let mut ctx = TranslationCtx {
        writer,
        memory,
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

    emit_body(&mut ctx, emitter, head)?;

    let RegionNode::Stop { block: stop_block } = tail else {
        return Err(Error::UnsupportedBrillig {
            reason: format!("structured main body must end with Stop, found {tail:?}"),
        });
    };
    let bd = &emitter.cfg.blocks[stop_block.0];
    let stop_idx = bd.end_exclusive - 1;
    match &emitter.bytecode.bytecode[stop_idx] {
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

/// Emits one [`StructuredProcedure`]'s body. The procedure's
/// `function.return` terminator is appended by [`ProcedureEmitter::ensure_emitted`],
/// not here — this only walks the body's region nodes against the shared
/// `Memory`.
fn translate_structured_procedure<'c, 'b, M: Memory>(
    writer: &mut BrilligWriter<'c, 'b>,
    memory: &mut M,
    emitter: &mut ProcedureEmitter<'c, '_>,
    procedure: &StructuredProcedure,
) -> Result<(), Error> {
    let mut ctx = TranslationCtx {
        writer,
        memory,
        calldata: &[],
        expected_output_count: 0,
        escape_flag_addrs: Vec::new(),
    };
    init_escape_flags(&mut ctx, procedure.escape_flag_count)?;
    emit_body(&mut ctx, emitter, &procedure.body)
}

fn emit_body<'c, 'b, M: Memory>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
    emitter: &mut ProcedureEmitter<'c, '_>,
    nodes: &[RegionNode],
) -> Result<(), Error> {
    for node in nodes {
        emit_node(ctx, emitter, node)?;
    }
    Ok(())
}

fn emit_node<'c, 'b, M: Memory>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
    emitter: &mut ProcedureEmitter<'c, '_>,
    node: &RegionNode,
) -> Result<(), Error> {
    match node {
        RegionNode::Linear { block } => {
            let range = {
                let bd = &emitter.cfg.blocks[block.0];
                bd.start..bd.end_exclusive
            };
            translate_block_body(ctx, &emitter.bytecode.bytecode, range)
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

        RegionNode::Return { .. } => {
            // The procedure-body emitter (`ProcedureEmitter::ensure_emitted`)
            // appends `function.return` once the walk finishes, so this
            // region node has no per-site IR.
            Ok(())
        }

        RegionNode::Call { target } => {
            emitter.ensure_emitted(*target, ctx.memory)?;
            let name = BrilligRegistry::procedure_function_name(emitter.variant, *target);
            ctx.writer.insert_function_call(&name)
        }

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

            // Snapshot pre-branch cache so the else-arm walk doesn't
            // see entries the then-arm wrote, and so we can `meet` end-
            // of-then with end-of-else at the join.
            let pre_branch = ctx.memory.clone();
            let then_block = build_block_with(ctx, |ctx| emit_body(ctx, emitter, then_branch))?;
            let after_then = ctx.memory.clone();
            *ctx.memory = pre_branch;
            let else_block = build_block_with(ctx, |ctx| emit_body(ctx, emitter, else_branch))?;
            // Post-arms cache is the intersection: only entries that
            // hold on both paths survive the join.
            ctx.memory.meet(&after_then);

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
            let before_block = build_block_with(ctx, |ctx| {
                emit_body(ctx, emitter, test_prefix)?;
                let continue_cond =
                    compute_loop_continue_cond(ctx, condition, *escape_flag, *header)?;
                ctx.writer.insert_scf_condition(continue_cond);
                Ok(())
            })?;
            // after-region: emit body, terminate with `scf.yield`.
            let after_block = build_block_with(ctx, |ctx| {
                emit_body(ctx, emitter, body)?;
                ctx.writer.insert_scf_yield();
                Ok(())
            })?;

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

/// Creates a fresh [`Block`], runs `f` with the writer redirected to it,
/// then restores the previous insertion target. Returns the populated
/// block (or propagates the closure's error).
fn build_block_with<'c, 'b, M: Memory, F>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
    f: F,
) -> Result<Block<'c>, Error>
where
    F: FnOnce(&mut TranslationCtx<'c, 'b, '_, M>) -> Result<(), Error>,
{
    let block = Block::new(&[]);
    let saved = ctx.writer.enter_block(&block);
    let outcome = f(ctx);
    ctx.writer.leave_block(saved);
    outcome?;
    Ok(block)
}

/// Allocates `count` escape-flag cells from the Brillig heap by bumping
/// `FREE_MEMORY_POINTER_ADDRESS` (`@1`), captures their index-typed
/// addresses on the context, and zero-initialises them so loop test-prefix
/// reads observe `flag = 0` on the first iteration.
///
/// Cooperates with the Brillig program's own allocator: the bump tells
/// any subsequent FMP-routed allocation to skip our slots.
fn init_escape_flags<'c, 'b, M: Memory>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
    count: usize,
) -> Result<(), Error> {
    if count == 0 {
        return Ok(());
    }

    let fmp_slot = match FREE_MEMORY_POINTER_ADDRESS {
        MemoryAddress::Direct(s) => s as usize,
        MemoryAddress::Relative(_) => {
            unreachable!("FREE_MEMORY_POINTER_ADDRESS is defined as Direct in brillig_vm")
        }
    };
    let fmp_addr = ctx.writer.insert_integer(fmp_slot)?;
    let fmp_felt = ctx.writer.insert_ram_load(fmp_addr)?;
    let fmp_idx = ctx.writer.cast_to_index(fmp_felt)?;

    let zero = ctx.writer.emit_constant(&FieldElement::from(0u128))?;
    ctx.escape_flag_addrs = Vec::with_capacity(count);
    for i in 0..count {
        let slot_addr = if i == 0 {
            fmp_idx
        } else {
            let offset = ctx.writer.insert_integer(i)?;
            ctx.writer.insert_index_add(fmp_idx, offset)?
        };
        ctx.writer.insert_ram_store(slot_addr, zero);
        ctx.escape_flag_addrs.push(slot_addr);
    }

    let count_idx = ctx.writer.insert_integer(count)?;
    let bumped_idx = ctx.writer.insert_index_add(fmp_idx, count_idx)?;
    let bumped_felt = ctx.writer.insert_cast_to_felt(bumped_idx)?;
    ctx.writer.insert_ram_store(fmp_addr, bumped_felt);
    Ok(())
}

/// Builds the `i1` continuation condition for an `scf.while`:
///   - `Some(loop_cond)`: load the register, convert felt → i1; invert
///     when polarity is `ExitOnTrue` so "true means continue".
///   - `Some(slot)`: load the escape flag, convert to i1, invert (we
///     want "true means *not* set, i.e. continue").
///   - When both are present, AND them.
fn compute_loop_continue_cond<'c, 'b, M: Memory>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
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
