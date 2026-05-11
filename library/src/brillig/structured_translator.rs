//! Structured translator: walks a [`StructuredFunction`] tree and emits
//! LLZK IR via the existing per-opcode handlers from [`super::translator`].

use acir::FieldElement;
use acir::brillig::Opcode as BrilligOpcode;
use acir::circuit::brillig::BrilligBytecode;
use llzk::dialect::function::{FuncDefOpLike, def};
use llzk::prelude::{
    Block, BlockLike, FunctionType, LlzkContext, Location, Module, OperationLike, RegionLike,
    Value, dialect,
};

use crate::brillig::translator::{
    emit_bool_assert, emit_if_with, emit_return_data, emit_set_flag, emit_trap, emit_while_with,
    init_escape_flags,
};
use crate::brillig_writer::BrilligWriter;
use crate::error::Error;

use super::cfg::Block as CFGBlock;
use super::memory::Memory;
use super::registry::{BrilligRegistry, BrilligRegistryKey};
use super::structurer::{StructureNode, StructuredFunction, StructuredProcedure};
use super::translator::{TranslationCtx, translate_block_body};

/// Per-Brillig-function emission state.
pub(super) struct BrilligFunctionEmitter<'c, 'p> {
    pub(super) context: &'c LlzkContext,
    pub(super) module: &'p Module<'c>,
    pub(super) location: Location<'c>,
    pub(super) bytecode: &'p BrilligBytecode<FieldElement>,
    pub(super) blocks: &'p [CFGBlock],
    pub(super) procedures: &'p [StructuredProcedure],
    pub(super) variant: BrilligRegistryKey,
}

impl<'c, 'p> BrilligFunctionEmitter<'c, 'p> {
    pub(super) fn new(
        context: &'c LlzkContext,
        module: &'p Module<'c>,
        location: Location<'c>,
        bytecode: &'p BrilligBytecode<FieldElement>,
        blocks: &'p [CFGBlock],
        procedures: &'p [StructuredProcedure],
        variant: BrilligRegistryKey,
    ) -> Self {
        Self {
            context,
            module,
            location,
            bytecode,
            blocks,
            procedures,
            variant,
        }
    }

    /// Entry point for structured brillig function translation.
    ///
    /// Emits the all procedures iteratively followed by the main function.
    pub(super) fn translate<'b, 'r>(
        &mut self,
        structured: &StructuredFunction,
        ctx: TranslationCtx<'c, 'b, 'r>,
        expected_output_count: usize,
    ) -> Result<Vec<Value<'c, 'b>>, Error> {
        self.translate_procedures(ctx.memory)?;
        self.translate_main(structured, ctx, expected_output_count)
    }

    /// Emits the [`StructuredFunction::main`] body for a Brillig sibling
    /// function.
    pub fn translate_main<'b, 'r>(
        &mut self,
        structured: &StructuredFunction,
        mut ctx: TranslationCtx<'c, 'b, 'r>,
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
        let bd = &self.blocks[stop_block.0];
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

    fn emit_body<'b>(
        &mut self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        escape_flag_addrs: &[Value<'c, 'b>],
        nodes: &[StructureNode],
    ) -> Result<(), Error> {
        for node in nodes {
            self.emit_node(ctx, escape_flag_addrs, node)?;
        }
        Ok(())
    }

    fn emit_node<'b>(
        &mut self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        escape_flag_addrs: &[Value<'c, 'b>],
        node: &StructureNode,
    ) -> Result<(), Error> {
        match node {
            StructureNode::Linear { block } => {
                let range = {
                    let bd = &self.blocks[block.0];
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
                let name = BrilligRegistry::procedure_function_name(self.variant, *target);
                ctx.writer.insert_function_call(&name)
            }

            StructureNode::IfThenElse {
                condition,
                then_branch,
                else_branch,
                ..
            } => emit_if_with(
                ctx,
                *condition,
                then_branch.as_slice(),
                else_branch.as_slice(),
                |ctx, nodes| self.emit_body(ctx, escape_flag_addrs, nodes),
            ),

            StructureNode::Loop {
                test_prefix,
                condition,
                escape_flag,
                body,
                header,
            } => emit_while_with(
                ctx,
                test_prefix.as_slice(),
                body.as_slice(),
                escape_flag_addrs,
                condition,
                *escape_flag,
                *header,
                |ctx, nodes| self.emit_body(ctx, escape_flag_addrs, nodes),
            ),

            StructureNode::SetEscapeFlag { slot } => emit_set_flag(ctx, slot, escape_flag_addrs),
        }
    }

    /// Emits all brillig function procedure bodies.
    fn translate_procedures(&mut self, memory: &mut Memory) -> Result<(), Error> {
        for procedure in self.procedures {
            self.translate_procedure(memory, procedure)?;
        }
        Ok(())
    }

    /// Emits one [`StructuredProcedure`]'s body.
    fn translate_procedure(
        &mut self,
        memory: &mut Memory,
        procedure: &StructuredProcedure,
    ) -> Result<(), Error> {
        let proc_func_type = FunctionType::new(self.context, &[], &[]);
        let proc_name = BrilligRegistry::procedure_function_name(self.variant, procedure.entry);
        let proc_func = def(self.location, &proc_name, proc_func_type, &[], None)?;
        proc_func.set_allow_witness_attr(true);
        proc_func.set_allow_non_native_field_ops_attr(true);

        let proc_body = Block::new(&[]);
        let mut proc_writer = BrilligWriter::new(self.context, &proc_body);
        let mut ctx = TranslationCtx::new(&mut proc_writer, memory, &[], None);
        let escape_flag_addrs = init_escape_flags(&mut ctx, procedure.escape_flag_count)?;
        self.emit_body(&mut ctx, &escape_flag_addrs, &procedure.body)?;
        proc_body.append_operation(dialect::function::r#return(self.location, &[]));
        proc_func.region(0)?.append_block(proc_body);
        self.module.body().append_operation(proc_func.into());
        Ok(())
    }
}
