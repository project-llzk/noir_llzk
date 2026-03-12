use std::collections::HashSet;

use acir::{FieldElement, circuit::Circuit};
use llzk::{
    attributes::NamedAttribute,
    prelude::{
        BlockLike, FeltType, LlzkContext, LlzkError, Location, Operation, PublicAttribute,
        StructDefOp, StructDefOpLike, StructType, Type, dialect,
    },
};

/// Translates a single ACIR `Circuit` into an LLZK `StructDefOp`.
///
/// Creates `struct.def @Circuit{N}` with:
/// - `struct.member @w{i} : !felt.type` for each witness `0..current_witness_index`
/// - `{llzk.pub}` annotation on witnesses in `public_parameters` or `return_values`
/// - Empty `@compute` and `@constrain` function stubs with correct signatures
///
/// Parameter order: private parameters first (in index order), then public
/// parameters (in index order).
pub fn translate_circuit<'c>(
    context: &'c LlzkContext,
    circuit: &Circuit<FieldElement>,
    circuit_index: usize,
) -> Result<StructDefOp<'c>, LlzkError> {
    let location = Location::unknown(context);
    let struct_name = format!("Circuit{circuit_index}");
    let felt_type = FeltType::new(context);

    // Determine which witnesses are public
    let public_witnesses: HashSet<u32> = circuit
        .public_parameters
        .0
        .iter()
        .map(|w| w.0)
        .chain(circuit.return_values.0.iter().map(|w| w.0))
        .collect();

    // Create struct def with empty body
    let struct_def = dialect::r#struct::def(
        location,
        &struct_name,
        &[],
        [] as [Result<Operation, LlzkError>; 0],
    )?;

    // Add struct members for each witness
    for i in 0..circuit.current_witness_index {
        let member_name = format!("w{i}");
        let is_public = public_witnesses.contains(&i);
        let member =
            dialect::r#struct::member(location, &member_name, felt_type, false, is_public)?;
        struct_def.body().append_operation(member.into());
    }

    // Build input parameter list: private params (sorted) then public params (sorted)
    let struct_type = StructType::from_str(context, &struct_name);

    let mut private_sorted: Vec<u32> = circuit.private_parameters.iter().map(|w| w.0).collect();
    private_sorted.sort();
    let mut public_sorted: Vec<u32> = circuit.public_parameters.0.iter().map(|w| w.0).collect();
    public_sorted.sort();

    let inputs: Vec<(Type<'c>, Location<'c>)> = private_sorted
        .iter()
        .chain(public_sorted.iter())
        .map(|_| (felt_type.into(), location))
        .collect();

    // Build arg_attrs: no pub attr for private params, pub attr for public params
    let pub_attr_vec = vec![PublicAttribute::new_named_attr(context)];
    let no_attr_vec: Vec<NamedAttribute> = vec![];
    let arg_attrs: Vec<Vec<_>> = private_sorted
        .iter()
        .map(|_| no_attr_vec.clone())
        .chain(public_sorted.iter().map(|_| pub_attr_vec.clone()))
        .collect();

    // Create @compute stub
    let compute =
        dialect::r#struct::helpers::compute_fn(location, struct_type, &inputs, Some(&arg_attrs))?;
    struct_def.body().append_operation(compute.into());

    // Create @constrain stub
    let constrain =
        dialect::r#struct::helpers::constrain_fn(location, struct_type, &inputs, Some(&arg_attrs))?;
    struct_def.body().append_operation(constrain.into());

    Ok(struct_def)
}
