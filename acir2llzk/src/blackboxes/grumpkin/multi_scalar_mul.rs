use std::collections::BTreeSet;

use acir::{
    brillig::{BlackBoxOp, Opcode as BrilligOpcode},
    circuit::{opcodes::BlackBoxFuncCall, Opcode, Program},
    AcirField, FieldElement,
};
use llzk::{
    builder::OpBuilder,
    prelude::{
        dialect::{bool, function},
        BlockLike, BlockRef, FuncDefOpLike, LlzkContext, Location, Type, Value,
    },
};

use crate::{
    blackboxes::common::{append_felt_constant, create_helper_function},
    common::{append_if_with_results, as_value},
    error::Error,
};

use super::common::{
    emit_curve_add_result, emit_infinity_point, point_to_array, EmbeddedPointValue,
};

pub(crate) const SCALAR_LOW_BITS: usize = 128;
pub(crate) const SCALAR_HIGH_BITS: usize = 126;
pub(crate) const SCALAR_TOTAL_BITS: usize = SCALAR_LOW_BITS + SCALAR_HIGH_BITS;

pub(crate) fn used_arities(program: &Program<FieldElement>) -> BTreeSet<usize> {
    let acir_arities = program
        .functions
        .iter()
        .flat_map(|circuit| circuit.opcodes.iter())
        .filter_map(multi_scalar_mul_arity);
    let brillig_arities = program
        .unconstrained_functions
        .iter()
        .flat_map(|func| func.bytecode.iter())
        .filter_map(brillig_multi_scalar_mul_arity);
    acir_arities.chain(brillig_arities).collect()
}

pub(in crate::blackboxes) fn multi_scalar_mul_helper_name(num_points: usize) -> String {
    format!("multi_scalar_mul_{num_points}")
}

pub(in crate::blackboxes) fn emit_multi_scalar_mul_helper<'c>(
    context: &'c LlzkContext,
    block: BlockRef<'c, '_>,
    num_points: usize,
) -> Result<(), Error> {
    let location = Location::unknown(context);
    let num_inputs = num_points * 3 + num_points * SCALAR_TOTAL_BITS + 1;
    let helper_name = multi_scalar_mul_helper_name(num_points);
    let (function, block) =
        create_helper_function(context, block, location, &helper_name, num_inputs, 3)?;
    function.set_allow_non_native_field_ops_attr(true);

    let points = (0..num_points)
        .map(|index| {
            let base = index * 3;
            Ok((
                block.argument(base)?.into(),
                block.argument(base + 1)?.into(),
                block.argument(base + 2)?.into(),
            ))
        })
        .collect::<Result<Vec<EmbeddedPointValue<'c, '_>>, Error>>()?;
    let scalar_bits_offset = num_points * 3;
    let scalar_bits = (0..num_points)
        .map(|index| {
            (0..SCALAR_TOTAL_BITS)
                .map(|bit_index| {
                    block.argument(scalar_bits_offset + index * SCALAR_TOTAL_BITS + bit_index)
                })
                .map(|arg| arg.map(Into::into).map_err(Error::from))
                .collect::<Result<Vec<Value<'c, '_>>, Error>>()
        })
        .collect::<Result<Vec<Vec<Value<'c, '_>>>, Error>>()?;
    let predicate: Value<'c, '_> = block.argument(num_inputs - 1)?.into();

    let builder = OpBuilder::at_block_end(context, block);
    let one = append_felt_constant(&builder, context, location, &FieldElement::one())?;
    let predicate_is_true = as_value(bool::eq(&builder, location, predicate, one)?)?;
    let felt = Type::from(context.felt_type());
    let result_types = [felt, felt, felt];
    let [output_x, output_y, output_infinite] = append_if_with_results(
        &builder,
        location,
        predicate_is_true,
        &result_types,
        |builder| {
            emit_multi_scalar_mul_result(builder, context, location, &points, &scalar_bits)
                .map(point_to_array)
        },
        |builder| emit_infinity_point(builder, context, location).map(point_to_array),
    )?;
    function::r#return(&builder, location, &[output_x, output_y, output_infinite]);
    Ok(())
}

fn emit_multi_scalar_mul_result<'c: 'a, 'a>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    points: &[EmbeddedPointValue<'c, 'a>],
    scalar_bits: &[Vec<Value<'c, 'a>>],
) -> Result<EmbeddedPointValue<'c, 'a>, Error> {
    debug_assert_eq!(points.len(), scalar_bits.len());

    let mut acc: EmbeddedPointValue<'c, 'a> = emit_infinity_point(builder, context, location)?;
    for (&point, bits) in points.iter().zip(scalar_bits) {
        let scaled = emit_scalar_mul_result(builder, context, location, point, bits)?;
        acc = emit_curve_add_result(builder, context, location, acc, scaled)?;
    }
    Ok(acc)
}

fn emit_scalar_mul_result<'c: 'a, 'a>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    point: EmbeddedPointValue<'c, 'a>,
    scalar_bits: &[Value<'c, 'a>],
) -> Result<EmbeddedPointValue<'c, 'a>, Error> {
    let felt = Type::from(context.felt_type());
    let result_types = [felt, felt, felt];
    let one = append_felt_constant(builder, context, location, &FieldElement::one())?;
    let mut acc: EmbeddedPointValue<'c, 'a> = emit_infinity_point(builder, context, location)?;

    for &bit in scalar_bits.iter().rev() {
        acc = emit_curve_add_result(builder, context, location, acc, acc)?;
        let bit_is_one = as_value(bool::eq(builder, location, bit, one)?)?;

        let result = append_if_with_results(
            builder,
            location,
            bit_is_one,
            &result_types,
            |builder| {
                let added = emit_curve_add_result(&builder, context, location, acc, point)?;
                Ok([added.0, added.1, added.2])
            },
            |_| Ok([acc.0, acc.1, acc.2]),
        )?;

        acc = (result[0], result[1], result[2]);
    }

    Ok(acc)
}

fn multi_scalar_mul_arity(opcode: &Opcode<FieldElement>) -> Option<usize> {
    match opcode {
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::MultiScalarMul { points, .. }) => {
            Some(points.len() / 3)
        }
        _ => None,
    }
}

fn brillig_multi_scalar_mul_arity(opcode: &BrilligOpcode<FieldElement>) -> Option<usize> {
    match opcode {
        BrilligOpcode::BlackBox(BlackBoxOp::MultiScalarMul { points, .. }) => {
            Some(points.size.0 as usize / 3)
        }
        _ => None,
    }
}
