//! Compile the outer level `Program` to LLZK `Module`

use acir::{circuit::Program, FieldElement};
use llzk::prelude::{LlzkContext, LlzkModuleBuilder, Module, StructType};

use crate::{
    blackboxes::registry::BlackboxFunction,
    brillig::{emit_brillig_functions, BrilligRegistry},
    circuit::CircuitTranslator,
    Error,
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
    let module = LlzkModuleBuilder::new(context)
        .with_language(source_language)
        .with_main(StructType::from_str(context, MAIN_STRUCT_NAME))
        .build();

    let mut brillig_registry = BrilligRegistry::new();
    for helper in BlackboxFunction::used_in_program(program) {
        helper.emit(context, module.body())?;
    }

    for (i, circuit) in program.functions.iter().enumerate() {
        CircuitTranslator::new(context, circuit, program).translate(
            i,
            &mut brillig_registry,
            module.body(),
        )?;
    }

    emit_brillig_functions(context, &module, &brillig_registry)?;

    Ok(module)
}
