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
    Block, BlockLike, FuncDefOpLike, FunctionType, LlzkContext, Location, Module, OperationLike,
    RegionLike, Type, Value, dialect,
};

use crate::brillig_writer::BrilligWriter;
use crate::error::Error;

use super::cfg::Cfg;
use super::memory::{DynamicMemory, StaticMemory, should_be_dynamic};
use super::structured_translator::{ProcedureEmitter, translate_structured};
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
pub(crate) struct BrilligRegistry<'c, 'p> {
    entries: HashMap<BrilligRegistryKey, BrilligEntry<'c, 'p>>,
}

/// A single Brillig function scheduled for module-level emission.
struct BrilligEntry<'c, 'p> {
    input_types: Vec<Type<'c>>,
    output_types: Vec<Type<'c>>,
    bytecode: &'p BrilligBytecode<FieldElement>,
}

impl<'c, 'p> BrilligRegistry<'c, 'p> {
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
        input_types: Vec<Type<'c>>,
        output_types: Vec<Type<'c>>,
        bytecode: &'p BrilligBytecode<FieldElement>,
    ) -> Result<(), Error> {
        debug_assert_eq!(input_types.len(), key.input_count);
        debug_assert_eq!(output_types.len(), key.output_count);
        self.entries.entry(key).or_insert(BrilligEntry {
            input_types,
            output_types,
            bytecode,
        });
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
    registry: &BrilligRegistry<'c, '_>,
) -> Result<(), Error> {
    let location = Location::unknown(context);
    // Order so emitted IR is deterministic across runs.
    let mut entries: Vec<(&BrilligRegistryKey, &BrilligEntry<'c, '_>)> =
        registry.entries.iter().collect();
    entries.sort_by_key(|(k, _)| (k.id.0, k.input_count, k.output_count));

    for (key, entry) in entries {
        let name = BrilligRegistry::function_name(*key);
        let func_type = FunctionType::new(context, &entry.input_types, &entry.output_types);
        let func = dialect::function::def(location, &name, func_type, &[], None)?;
        func.set_allow_witness_attr(true);
        func.set_allow_non_native_field_ops_attr(true);

        let arg_sig: Vec<(Type<'c>, Location<'c>)> =
            entry.input_types.iter().map(|ty| (*ty, location)).collect();
        let body_block = Block::new(&arg_sig);
        let calldata: Vec<Value<'c, '_>> = (0..entry.input_types.len())
            .map(|i| body_block.argument(i).unwrap().into())
            .collect();
        let mut writer = BrilligWriter::new(context, &body_block);
        let cfg = Cfg::build(&entry.bytecode.bytecode)?;
        let structured = structure_function(&cfg)?;

        let mut emitter = ProcedureEmitter::new(
            context,
            module,
            location,
            entry.bytecode,
            &cfg,
            &structured.procedures,
            *key,
        );

        // One Memory shared by the main body and every procedure of this
        // Brillig function.
        let dynamic_sp = should_be_dynamic(&entry.bytecode.bytecode);
        let returns = if dynamic_sp {
            translate_structured(
                &mut writer,
                &mut DynamicMemory::new(),
                &mut emitter,
                &structured,
                &calldata,
                entry.output_types.len(),
            )?
        } else {
            translate_structured(
                &mut writer,
                &mut StaticMemory::new(),
                &mut emitter,
                &structured,
                &calldata,
                entry.output_types.len(),
            )?
        };

        body_block.append_operation(dialect::function::r#return(location, &returns));
        func.region(0)?.append_block(body_block);
        module.body().append_operation(func.into());
    }

    Ok(())
}

#[cfg(test)]
mod tests;
