//! Compile the outer level `Program` to LLZK `Module`

use acir::{FieldElement, circuit::Program};
use llzk::prelude::{
    BlockLike, FlatSymbolRefAttribute, LlzkContext, Location, Module, OperationMutLike,
    StringAttribute, StructType, TypeAttribute, llzk_module,
};
use llzk_sys::{LANG_ATTR_NAME, MAIN_ATTR_NAME};

use crate::{Error, blackboxes::registry::BlackboxFunction, circuit::CircuitTranslator};

const MAIN_STRUCT_NAME: &str = "Circuit0";

/// Translates an ACIR `Program` into an LLZK `Module`.
///
/// Creates the root `module attributes {llzk.lang = "ACIR"}` and calls
/// [`CircuitTranslator`] for each circuit in `program.functions`.
pub fn translate_program<'c>(
    context: &'c LlzkContext,
    program: &Program<FieldElement>,
) -> Result<Module<'c>, Error> {
    let location = Location::unknown(context);
    let mut module = llzk_module(location);
    module.as_operation_mut().set_attribute(
        MAIN_ATTR_NAME.as_ref(),
        TypeAttribute::new(
            StructType::new(FlatSymbolRefAttribute::new(context, MAIN_STRUCT_NAME), &[]).into(),
        )
        .into(),
    );

    module.as_operation_mut().set_attribute(
        LANG_ATTR_NAME.as_ref(),
        StringAttribute::new(context, "ACIR").into(),
    );

    for helper in BlackboxFunction::ALL {
        if helper.is_used(program) {
            module.body().append_operation(helper.emit(context)?.into());
        }
    }

    for (i, circuit) in program.functions.iter().enumerate() {
        let struct_def = CircuitTranslator::new(context, circuit, program).translate(i)?;
        module.body().append_operation(struct_def.into());
    }

    Ok(module)
}
