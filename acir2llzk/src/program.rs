//! Compile the outer level `Program` to LLZK `Module`

use acir::{FieldElement, circuit::Program};
use llzk::prelude::{
    BlockLike, LlzkContext, Location, Module, OperationMutLike, StructType, TypeAttribute,
    llzk_module,
};
use llzk_sys::MAIN_ATTR_NAME;

use crate::{
    Error,
    blackboxes::registry::BlackboxFunction,
    brillig::{BrilligRegistry, emit_brillig_functions},
    circuit::CircuitTranslator,
};

const MAIN_STRUCT_NAME: &str = "Circuit0";

/// Translates an ACIR `Program` into an LLZK `Module`.
///
/// Creates the root `module attributes {llzk.lang = "ACIR"}`, translates
/// every circuit in `program.functions`, and emits one
/// module-level `@brillig_{id}` function per unique `BrilligFunctionId`
/// referenced across those circuits.
pub(crate) fn translate_program<'c>(
    context: &'c LlzkContext,
    program: &Program<FieldElement>,
    source_language: &str,
) -> Result<Module<'c>, Error> {
    let location = Location::unknown(context);
    let mut module = llzk_module(location, Some(source_language));
    module.as_operation_mut().set_attribute(
        MAIN_ATTR_NAME.as_ref(),
        TypeAttribute::new(StructType::from_str(context, MAIN_STRUCT_NAME).into()).into(),
    );

    let mut brillig_registry = BrilligRegistry::new();
    for helper in BlackboxFunction::used_in_program(program) {
        module.body().append_operation(helper.emit(context)?.into());
    }

    for (i, circuit) in program.functions.iter().enumerate() {
        let struct_def = CircuitTranslator::new(context, circuit, program)
            .translate(i, &mut brillig_registry)?;
        module.body().append_operation(struct_def.into());
    }

    emit_brillig_functions(context, &module, &brillig_registry)?;

    Ok(module)
}
