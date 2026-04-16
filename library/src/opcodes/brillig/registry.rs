//! Program-level collector for `BrilligCall` sites.
//!
//! 1. While translating circuits, each `BrilligCall::emit_compute` emits a
//!    call site against `@brillig_{id}` and registers the shape + bytecode
//!    here.
//! 2. After every circuit has been translated, [`emit_brillig_functions`]
//!    walks the registry and appends one `@brillig_{id}` function per entry
//!    to the module body.
//!
//! Deduplication is keyed on `BrilligFunctionId` — multiple callers of the
//! same function share a single LLZK function, provided their marshalling
//! shapes agree. Shape disagreement is reported as `UnsupportedBrillig`.

use std::collections::HashMap;

use acir::{
    FieldElement,
    circuit::brillig::{BrilligBytecode, BrilligFunctionId},
};
use llzk::prelude::{
    Block, BlockLike, FuncDefOpLike, FunctionType, LlzkContext, Location, Module, OperationLike,
    RegionLike, Type, Value, dialect,
};

use crate::block_writer::BlockWriter;
use crate::error::Error;

use super::translator::translate_bytecode;

/// Collector of unique Brillig call sites across a program.
pub(crate) struct BrilligRegistry<'c, 'p> {
    entries: HashMap<BrilligFunctionId, BrilligEntry<'c, 'p>>,
}

/// A single Brillig function scheduled for module-level emission.
pub(crate) struct BrilligEntry<'c, 'p> {
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

    /// Returns the canonical LLZK symbol name for a Brillig function id.
    pub(crate) fn function_name(id: BrilligFunctionId) -> String {
        format!("brillig_{}", id.0)
    }

    /// Records a call site for `id`. On first registration the marshalling
    /// shape is stored; on subsequent registrations the shape must match, or
    /// an `UnsupportedBrillig` error is returned.
    pub(crate) fn register(
        &mut self,
        id: BrilligFunctionId,
        input_types: Vec<Type<'c>>,
        output_types: Vec<Type<'c>>,
        bytecode: &'p BrilligBytecode<FieldElement>,
    ) -> Result<(), Error> {
        if let Some(existing) = self.entries.get(&id) {
            if existing.input_types.len() != input_types.len()
                || existing.output_types.len() != output_types.len()
            {
                return Err(Error::UnsupportedBrillig {
                    reason: format!(
                        "brillig function id {} called with inconsistent marshalling shapes: \
                         existing signature has {} input(s) / {} output(s), new call site has \
                         {} input(s) / {} output(s)",
                        id.0,
                        existing.input_types.len(),
                        existing.output_types.len(),
                        input_types.len(),
                        output_types.len(),
                    ),
                });
            }
            return Ok(());
        }
        self.entries.insert(
            id,
            BrilligEntry {
                input_types,
                output_types,
                bytecode,
            },
        );
        Ok(())
    }
}

/// Emits one module-level `@brillig_{id}` function for every registered
/// entry. Must be called after every circuit has been translated — before
/// this runs, call sites reference symbols that do not yet exist.
pub(crate) fn emit_brillig_functions<'c>(
    context: &'c LlzkContext,
    module: &Module<'c>,
    registry: &BrilligRegistry<'c, '_>,
) -> Result<(), Error> {
    let location = Location::unknown(context);
    // Iterate in id order so emitted IR is deterministic.
    let mut entries: Vec<(&BrilligFunctionId, &BrilligEntry<'c, '_>)> =
        registry.entries.iter().collect();
    entries.sort_by_key(|(id, _)| id.0);

    for (id, entry) in entries {
        let name = BrilligRegistry::function_name(*id);
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
        let mut writer = BlockWriter::for_function_body(context, &body_block);
        let returns = translate_bytecode(
            &mut writer,
            entry.bytecode,
            &calldata,
            entry.output_types.len(),
        )?;
        if returns.len() != entry.output_types.len() {
            return Err(Error::UnsupportedBrillig {
                reason: format!(
                    "brillig function id {} declared {} output(s) but bytecode translator \
                     produced {}; register-based output marshalling arrives in later \
                     milestone-3 issues",
                    id.0,
                    entry.output_types.len(),
                    returns.len(),
                ),
            });
        }
        body_block.append_operation(dialect::function::r#return(location, &returns));
        func.region(0)?.append_block(body_block);
        module.body().append_operation(func.into());
    }

    Ok(())
}
