use acir::{FieldElement, circuit::Program};
use llzk::prelude::{BlockLike, LlzkContext, LlzkError, Location, Module, llzk_module};

use crate::circuit::translate_circuit;

/// Translates an ACIR `Program` into an LLZK `Module`.
///
/// Creates the root `module attributes {llzk.lang = "noir"}` and calls
/// `translate_circuit` for each circuit in `program.functions`.
pub fn translate_program<'c>(
    context: &'c LlzkContext,
    program: &Program<FieldElement>,
) -> Result<Module<'c>, LlzkError> {
    let location = Location::unknown(context);
    let module = llzk_module(location);

    for (i, circuit) in program.functions.iter().enumerate() {
        let struct_def = translate_circuit(context, circuit, i)?;
        module.body().append_operation(struct_def.into());
    }

    Ok(module)
}
