//! Program-level collector for `BrilligCall` sites.
//!
//! 1. While translating circuits, each `BrilligCall::emit_compute` emits a
//!    call site against `@brillig_{id}_{in}x{out}` and registers the shape
//!    + bytecode here.
//! 2. After every circuit has been translated, [`emit_brillig_functions`]
//!    walks the registry and appends one `@brillig_{id}_{in}x{out}` function
//!    per entry to the module body.
//!

use std::collections::HashMap;

use acir::{
    FieldElement,
    circuit::brillig::{BrilligBytecode, BrilligFunctionId},
};
use llzk::prelude::{
    Block, BlockLike, FeltType, FuncDefOpLike, FunctionType, LlzkContext, Location, Module,
    OperationLike, RegionLike, Type, Value, dialect,
};

use crate::brillig_writer::BrilligWriter;
use crate::error::Error;
use crate::{FIELD_NAME, brillig::translator::TranslationCtx};

use super::cfg::Cfg;
use super::memory::precompute_calldata_copy_params;
use super::structured_translator::BrilligFunctionEmitter;
use super::structurer::structure_function;

/// Identifies a single shape variant of a Brillig function.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct BrilligRegistryKey {
    pub(super) id: BrilligFunctionId,
    pub(super) input_count: usize,
    pub(super) output_count: usize,
}

impl BrilligRegistryKey {
    pub(crate) fn new(id: BrilligFunctionId, input_count: usize, output_count: usize) -> Self {
        Self {
            id,
            input_count,
            output_count,
        }
    }
}

/// Collector of unique Brillig call sites across a program.
pub(crate) struct BrilligRegistry<'p> {
    entries: HashMap<BrilligRegistryKey, BrilligEntry<'p>>,
}

/// A single Brillig function scheduled for module-level emission.
struct BrilligEntry<'p> {
    bytecode: &'p BrilligBytecode<FieldElement>,
}

impl<'p> BrilligRegistry<'p> {
    pub(crate) fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Returns the LLZK symbol name for a Brillig function variant.
    pub(crate) fn function_name(key: BrilligRegistryKey) -> String {
        format!(
            "brillig_{}_{}x{}",
            key.id.0, key.input_count, key.output_count
        )
    }

    /// Returns the LLZK symbol name for a procedure inside a
    /// Brillig function variant.
    pub(super) fn procedure_function_name(
        key: BrilligRegistryKey,
        entry: super::cfg::BlockId,
    ) -> String {
        format!(
            "brillig_{}_{}x{}_proc_b{}",
            key.id.0, key.input_count, key.output_count, entry.0
        )
    }

    /// Records a call site for `key`.
    pub(crate) fn register(
        &mut self,
        key: BrilligRegistryKey,
        bytecode: &'p BrilligBytecode<FieldElement>,
    ) -> Result<(), Error> {
        self.entries.entry(key).or_insert(BrilligEntry { bytecode });
        Ok(())
    }
}

/// Emits one module-level `@brillig_{id}_{in}x{out}` function for every
/// registered variant. Must be called after every circuit has been
/// translated — before this runs, call sites reference symbols that do not
/// yet exist.
pub(crate) fn emit_brillig_functions<'c>(
    context: &'c LlzkContext,
    module: &Module<'c>,
    registry: &BrilligRegistry<'_>,
) -> Result<(), Error> {
    let location = Location::unknown(context);
    let felt_ty: Type<'c> = FeltType::with_field(context, FIELD_NAME).into();
    // Order so emitted IR is deterministic across runs.
    let mut entries: Vec<(&BrilligRegistryKey, &BrilligEntry<'_>)> =
        registry.entries.iter().collect();
    entries.sort_by_key(|(k, _)| (k.id.0, k.input_count, k.output_count));

    for (key, entry) in entries {
        let name = BrilligRegistry::function_name(*key);
        let input_types = vec![felt_ty; key.input_count];
        let output_types = vec![felt_ty; key.output_count];
        let func_type = FunctionType::new(context, &input_types, &output_types);
        let func = dialect::function::def(location, &name, func_type, &[], None)?;
        func.set_allow_witness_attr(true);
        func.set_allow_non_native_field_ops_attr(true);

        let arg_sig: Vec<(Type<'c>, Location<'c>)> =
            (0..key.input_count).map(|_| (felt_ty, location)).collect();
        let body_block = Block::new(&arg_sig);
        let calldata: Vec<Value<'c, '_>> = (0..key.input_count)
            .map(|i| body_block.argument(i).unwrap().into())
            .collect();
        let mut writer = BrilligWriter::new(context, &body_block);
        let cfg = Cfg::build(&entry.bytecode.bytecode)?;
        let structured = structure_function(&cfg)?;

        let mut emitter = BrilligFunctionEmitter::new(
            context,
            module,
            location,
            entry.bytecode,
            &cfg.blocks,
            &structured.procedures,
            *key,
        );

        let calldata_copy_params = precompute_calldata_copy_params(&entry.bytecode.bytecode)?;
        let ctx = TranslationCtx::new(&mut writer, &calldata, Some(calldata_copy_params));
        let returns = emitter.translate(&structured, ctx, key.output_count)?;

        body_block.append_operation(dialect::function::r#return(location, &returns));
        func.region(0)?.append_block(body_block);
        module.body().append_operation(func.into());
    }

    Ok(())
}

#[cfg(test)]
mod tests;
