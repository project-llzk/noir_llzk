use std::collections::HashSet;

use acir::{FieldElement, circuit::Circuit};
use llzk::{
    attributes::NamedAttribute,
    prelude::{
        BlockLike, FeltType, LlzkContext, LlzkError, Location, Operation, PublicAttribute,
        StructDefOp, StructDefOpLike, StructType, Type, dialect,
    },
};

use crate::{Error, FIELD_NAME, constrain::emit_constrain_body};

/// Translates a single ACIR `Circuit` into an LLZK `StructDefOp`.
///
/// Creates `struct.def @Circuit{N}` with:
/// - `struct.member @w{i} : !felt.type` for each witness `0..current_witness_index`
/// - `{llzk.pub}` annotation on witnesses in `public_parameters` or `return_values`
/// - Empty `@compute` and `@constrain` function stubs with correct signatures
///
/// Parameter order: private parameters first (in index order), then public
/// parameters (in index order).
pub(crate) fn translate_circuit<'c>(
    context: &'c LlzkContext,
    circuit: &Circuit<FieldElement>,
    circuit_index: usize,
) -> Result<StructDefOp<'c>, Error> {
    let location = Location::unknown(context);
    let struct_name = format!("Circuit{circuit_index}");

    let struct_def = dialect::r#struct::def(
        location,
        &struct_name,
        &[],
        [] as [Result<Operation, LlzkError>; 0],
    )?;

    emit_members(context, &struct_def, circuit)?;

    let inputs = build_input_list(context, circuit);
    let arg_attrs = build_input_attrs(context, circuit);

    emit_compute_fn(context, &struct_def, &struct_name, &inputs, &arg_attrs)?;
    emit_constrain_fn(
        context,
        &struct_def,
        &struct_name,
        circuit,
        &inputs,
        &arg_attrs,
    )?;

    Ok(struct_def)
}

/// Emits `struct.member @w{i} : !felt.type` for each witness, marking public
/// witnesses with `{llzk.pub}`.
fn emit_members<'c>(
    context: &'c LlzkContext,
    struct_def: &StructDefOp<'c>,
    circuit: &Circuit<FieldElement>,
) -> Result<(), Error> {
    let location = Location::unknown(context);
    let felt_type = FeltType::with_field(context, FIELD_NAME);

    let public_witnesses: HashSet<u32> = circuit
        .public_parameters
        .0
        .iter()
        .map(|w| w.0)
        .chain(circuit.return_values.0.iter().map(|w| w.0))
        .collect();

    // `current_witness_index` is the highest index, not the next one (see Noir's
    // `acvm-repo/acir/src/circuit/mod.rs`), so the range is inclusive.
    for i in 0..=circuit.current_witness_index {
        let member_name = format!("w{i}");
        let is_public = public_witnesses.contains(&i);
        let member =
            dialect::r#struct::member(location, &member_name, felt_type, false, is_public)?;
        struct_def.body().append_operation(member.into());
    }

    Ok(())
}

/// Builds the input parameter list: private params (sorted) then public params (sorted).
fn build_input_list<'c>(
    context: &'c LlzkContext,
    circuit: &Circuit<FieldElement>,
) -> Vec<(Type<'c>, Location<'c>)> {
    let location = Location::unknown(context);
    let felt_type = FeltType::with_field(context, FIELD_NAME);

    let mut private_sorted: Vec<u32> = circuit.private_parameters.iter().map(|w| w.0).collect();
    private_sorted.sort();
    let mut public_sorted: Vec<u32> = circuit.public_parameters.0.iter().map(|w| w.0).collect();
    public_sorted.sort();

    private_sorted
        .iter()
        .chain(public_sorted.iter())
        .map(|_| (felt_type.into(), location))
        .collect()
}

/// Builds the `arg_attrs` list: no attribute for private params, `{llzk.pub}` for public params.
fn build_input_attrs<'c>(
    context: &'c LlzkContext,
    circuit: &Circuit<FieldElement>,
) -> Vec<Vec<NamedAttribute<'c>>> {
    let pub_attr_vec = vec![PublicAttribute::new_named_attr(context)];
    let no_attr_vec: Vec<NamedAttribute> = vec![];

    let mut private_sorted: Vec<u32> = circuit.private_parameters.iter().map(|w| w.0).collect();
    private_sorted.sort();
    let mut public_sorted: Vec<u32> = circuit.public_parameters.0.iter().map(|w| w.0).collect();
    public_sorted.sort();

    private_sorted
        .iter()
        .map(|_| no_attr_vec.clone())
        .chain(public_sorted.iter().map(|_| pub_attr_vec.clone()))
        .collect()
}

/// Creates the `@compute` function stub and appends it to the struct body.
fn emit_compute_fn<'c>(
    context: &'c LlzkContext,
    struct_def: &StructDefOp<'c>,
    struct_name: &str,
    inputs: &[(Type<'c>, Location<'c>)],
    arg_attrs: &[Vec<NamedAttribute<'c>>],
) -> Result<(), Error> {
    let location = Location::unknown(context);
    let struct_type = StructType::from_str(context, struct_name);

    let compute =
        dialect::r#struct::helpers::compute_fn(location, struct_type, inputs, Some(arg_attrs))?;
    struct_def.body().append_operation(compute.into());

    Ok(())
}

/// Creates the `@constrain` function and emits constraint logic from the circuit opcodes.
fn emit_constrain_fn<'c>(
    context: &'c LlzkContext,
    struct_def: &StructDefOp<'c>,
    struct_name: &str,
    circuit: &Circuit<FieldElement>,
    inputs: &[(Type<'c>, Location<'c>)],
    arg_attrs: &[Vec<NamedAttribute<'c>>],
) -> Result<(), Error> {
    let location = Location::unknown(context);
    let struct_type = StructType::from_str(context, struct_name);

    let constrain =
        dialect::r#struct::helpers::constrain_fn(location, struct_type, inputs, Some(arg_attrs))?;
    struct_def.body().append_operation(constrain.into());

    emit_constrain_body(context, struct_def, circuit)?;

    Ok(())
}
