//! Structured translator: walks a [`StructuredFunction`] tree and emits
//! LLZK IR via the existing per-opcode handlers from [`super::translator`].

use std::collections::HashSet;

use acir::FieldElement;
use acir::brillig::Opcode as BrilligOpcode;
use acir::circuit::brillig::BrilligBytecode;
use llzk::dialect::function::def;
use llzk::prelude::{
    Block, BlockLike, FuncDefOpLike, FunctionType, LlzkContext, Location, Module, OperationLike,
    RegionLike, Value, dialect,
};

use crate::brillig::translator::{
    build_block_with, compute_loop_continue_cond, emit_bool_assert, emit_return_data, emit_trap,
    init_escape_flags,
};
use crate::brillig_writer::BrilligWriter;
use crate::error::Error;

use super::cfg::{BlockId, Cfg};
use super::memory::Memory;
use super::registry::{BrilligRegistry, BrilligRegistryKey};
use super::structurer::{StructureNode, StructuredFunction, StructuredProcedure};
use super::translator::{TranslationCtx, translate_block_body};
use crate::writer::Writer;

/// Per-Brillig-function emission state.
pub(super) struct BrilligFunctionEmitter<'c, 'p> {
    pub(super) context: &'c LlzkContext,
    pub(super) module: &'p Module<'c>,
    pub(super) location: Location<'c>,
    pub(super) bytecode: &'p BrilligBytecode<FieldElement>,
    pub(super) cfg: &'p Cfg,
    pub(super) procedures: &'p [StructuredProcedure],
    pub(super) variant: BrilligRegistryKey,
    emitted: HashSet<BlockId>,
}

impl<'c, 'p> BrilligFunctionEmitter<'c, 'p> {
    pub(super) fn new(
        context: &'c LlzkContext,
        module: &'p Module<'c>,
        location: Location<'c>,
        bytecode: &'p BrilligBytecode<FieldElement>,
        cfg: &'p Cfg,
        procedures: &'p [StructuredProcedure],
        variant: BrilligRegistryKey,
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
    fn ensure_emitted<M: Memory>(&mut self, target: BlockId, memory: &mut M) -> Result<(), Error> {
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
        self.translate_procedure(&mut proc_writer, memory, proc)?;
        proc_body.append_operation(dialect::function::r#return(self.location, &[]));
        proc_func.region(0)?.append_block(proc_body);
        self.module.body().append_operation(proc_func.into());
        Ok(())
    }

    /// Emits the [`StructuredFunction::main`] body for a Brillig sibling
    /// function. Procedures referenced from the walk are emitted lazily via
    /// `emitter`.
    pub(super) fn translate_main<'b, 'r, M: Memory>(
        &mut self,
        structured: &StructuredFunction,
        mut ctx: TranslationCtx<'c, 'b, 'r, M>,
        expected_output_count: usize,
    ) -> Result<Vec<Value<'c, 'b>>, Error> {
        let escape_flag_addrs = init_escape_flags(&mut ctx, structured.main_escape_flag_count)?;

        let (tail, head) =
            structured
                .main
                .split_last()
                .ok_or_else(|| Error::UnsupportedBrillig {
                    reason: "structured main body is empty (must end with Stop)".into(),
                })?;

        self.emit_body(&mut ctx, &escape_flag_addrs, head)?;

        let StructureNode::Stop { block: stop_block } = tail else {
            return Err(Error::UnsupportedBrillig {
                reason: format!("structured main body must end with Stop, found {tail:?}"),
            });
        };
        let bd = &self.cfg.blocks[stop_block.0];
        let stop_idx = bd.end_exclusive - 1;
        let return_data = match &self.bytecode.bytecode[stop_idx] {
            BrilligOpcode::Stop { return_data } => *return_data,
            other => {
                return Err(Error::UnsupportedBrillig {
                    reason: format!(
                        "Stop region node at b{} expects a Stop opcode at index \
                     {stop_idx}, found {other:?}",
                        stop_block.0
                    ),
                });
            }
        };
        emit_return_data(&mut ctx, expected_output_count, &return_data)
    }

    /// Emits one [`StructuredProcedure`]'s body. The procedure's
    /// `function.return` terminator is appended by [`ProcedureEmitter::ensure_emitted`],
    /// not here — this only walks the body's region nodes against the shared
    /// `Memory`.
    fn translate_procedure<'b, M: Memory>(
        &mut self,
        writer: &mut BrilligWriter<'c, 'b>,
        memory: &mut M,

        procedure: &StructuredProcedure,
    ) -> Result<(), Error> {
        let mut ctx = TranslationCtx::new(writer, memory, &[]);
        let escape_flag_addrs = init_escape_flags(&mut ctx, procedure.escape_flag_count)?;
        self.emit_body(&mut ctx, &escape_flag_addrs, &procedure.body)
    }

    fn emit_body<'b, M: Memory>(
        &mut self,
        ctx: &mut TranslationCtx<'c, 'b, '_, M>,
        escape_flag_addrs: &[Value<'c, 'b>],
        nodes: &[StructureNode],
    ) -> Result<(), Error> {
        for node in nodes {
            self.emit_node(ctx, escape_flag_addrs, node)?;
        }
        Ok(())
    }

    fn emit_node<'b, M: Memory>(
        &mut self,
        ctx: &mut TranslationCtx<'c, 'b, '_, M>,
        escape_flag_addrs: &[Value<'c, 'b>],
        node: &StructureNode,
    ) -> Result<(), Error> {
        match node {
            StructureNode::Linear { block } => {
                let range = {
                    let bd = &self.cfg.blocks[block.0];
                    bd.start..bd.end_exclusive
                };
                translate_block_body(ctx, &self.bytecode.bytecode, range)
            }

            StructureNode::Stop { .. } => unreachable!(
                "StructureNode::Stop is peeled off in translate_structured before \
             emit_body runs; the structurer guarantees Stop appears only as \
             the tail of main"
            ),

            StructureNode::Trap { .. } => emit_trap(ctx),

            StructureNode::BoolAssert { condition, .. } => emit_bool_assert(ctx, condition),

            StructureNode::Return { .. } => {
                // The procedure-body emitter (`ProcedureEmitter::ensure_emitted`)
                // appends `function.return` once the walk finishes, so this
                // region node has no per-site IR.
                Ok(())
            }

            StructureNode::Call { target } => {
                self.ensure_emitted(*target, ctx.memory)?;
                let name = BrilligRegistry::procedure_function_name(self.variant, *target);
                ctx.writer.insert_function_call(&name)
            }

            StructureNode::IfThenElse {
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
                let then_block = build_block_with(ctx, |ctx| {
                    self.emit_body(ctx, escape_flag_addrs, then_branch)
                })?;
                let after_then = ctx.memory.clone();
                *ctx.memory = pre_branch;
                let else_block = build_block_with(ctx, |ctx| {
                    self.emit_body(ctx, escape_flag_addrs, else_branch)
                })?;
                // Post-arms cache is the intersection: only entries that
                // hold on both paths survive the join.
                ctx.memory.meet(&after_then);

                ctx.writer
                    .insert_scf_if(cond_bool, then_block, else_block)?;
                Ok(())
            }

            StructureNode::Loop {
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
                    self.emit_body(ctx, escape_flag_addrs, test_prefix)?;
                    let continue_cond = compute_loop_continue_cond(
                        ctx,
                        escape_flag_addrs,
                        condition,
                        *escape_flag,
                        *header,
                    )?;
                    ctx.writer.insert_scf_condition(continue_cond, &[]);
                    Ok(())
                })?;
                // after-region: emit body, terminate with `scf.yield`.
                let after_block = build_block_with(ctx, |ctx| {
                    self.emit_body(ctx, escape_flag_addrs, body)?;
                    ctx.writer.insert_scf_yield(&[]);
                    Ok(())
                })?;

                ctx.writer
                    .insert_scf_while(&[], &[], before_block, after_block)?;
                Ok(())
            }

            StructureNode::SetEscapeFlag { slot } => {
                let one = ctx.writer.emit_constant(&FieldElement::from(1u128))?;
                let addr = escape_flag_addrs[slot.0];
                ctx.writer.insert_ram_store(addr, one);
                Ok(())
            }
        }
    }
}
