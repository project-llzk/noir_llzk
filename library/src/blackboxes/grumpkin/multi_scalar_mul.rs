use std::collections::BTreeSet;

use acir::{
    AcirField, FieldElement,
    circuit::{Opcode, Program, opcodes::BlackBoxFuncCall},
};
use llzk::prelude::{
    Block, BlockLike, FuncDefOp, FuncDefOpLike, FunctionType, Location, OperationLike, Region,
    RegionLike, Value, dialect, melior_dialects::scf,
};

use crate::{common::append_if_with_results, error::Error};

use super::common::{
    EmbeddedPointValue, append_felt_constant, append_op_with_result, emit_curve_add_result,
    emit_infinity_point, felt_type, point_to_array,
};

pub(crate) const SCALAR_LOW_BITS: usize = 128;
pub(crate) const SCALAR_HIGH_BITS: usize = 126;
pub(crate) const SCALAR_TOTAL_BITS: usize = SCALAR_LOW_BITS + SCALAR_HIGH_BITS;

pub(crate) fn used_arities(program: &Program<FieldElement>) -> BTreeSet<usize> {
    program
        .functions
        .iter()
        .flat_map(|circuit| circuit.opcodes.iter())
        .filter_map(multi_scalar_mul_arity)
        .collect()
}

pub(crate) fn multi_scalar_mul_helper_name(num_points: usize) -> String {
    format!("multi_scalar_mul_{num_points}")
}

pub(crate) fn emit_multi_scalar_mul_helper<'c>(
    context: &'c llzk::prelude::LlzkContext,
    num_points: usize,
) -> Result<FuncDefOp<'c>, Error> {
    let location = Location::unknown(context);
    let felt = felt_type(context);
    let num_inputs = num_points * 3 + num_points * SCALAR_TOTAL_BITS + 1;
    let inputs = vec![(felt, location); num_inputs];
    let input_types = vec![felt; num_inputs];
    let function_type = FunctionType::new(context, &input_types, &[felt, felt, felt]);
    let helper_name = multi_scalar_mul_helper_name(num_points);
    let function = dialect::function::def(location, &helper_name, function_type, &[], None)?;
    function.set_allow_non_native_field_ops_attr(true);

    let block = Block::new(&inputs);
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

    let one = append_felt_constant(&block, context, location, &FieldElement::one())?;
    let predicate_is_true =
        append_op_with_result(&block, dialect::bool::eq(location, predicate, one)?)?;
    let result_types = [felt, felt, felt];
    let [output_x, output_y, output_infinite] = append_if_with_results(
        &block,
        location,
        predicate_is_true,
        &result_types,
        |then_block| {
            emit_multi_scalar_mul_result(then_block, context, location, &points, &scalar_bits)
                .map(point_to_array)
        },
        |else_block| emit_infinity_point(else_block, context, location).map(point_to_array),
    )?;
    block.append_operation(dialect::function::r#return(
        location,
        &[output_x, output_y, output_infinite],
    ));
    function.region(0)?.append_block(block);
    Ok(function)
}

fn emit_multi_scalar_mul_result<'c, 'a, 'v>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    points: &[EmbeddedPointValue<'c, 'v>],
    scalar_bits: &[Vec<Value<'c, 'v>>],
) -> Result<EmbeddedPointValue<'c, 'a>, Error> {
    debug_assert_eq!(points.len(), scalar_bits.len());

    let mut acc: EmbeddedPointValue<'c, 'a> = emit_infinity_point(block, context, location)?;
    for (&point, bits) in points.iter().zip(scalar_bits) {
        let scaled = emit_scalar_mul_result(block, context, location, point, bits)?;
        acc = emit_curve_add_result(block, context, location, acc, scaled)?;
    }
    Ok(acc)
}

fn emit_scalar_mul_result<'c, 'a, 'v>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    point: EmbeddedPointValue<'c, 'v>,
    scalar_bits: &[Value<'c, 'v>],
) -> Result<EmbeddedPointValue<'c, 'a>, Error> {
    let result_types = [felt_type(context), felt_type(context), felt_type(context)];
    let mut acc: EmbeddedPointValue<'c, 'a> = emit_infinity_point(block, context, location)?;

    for &bit in scalar_bits.iter().rev() {
        acc = emit_curve_add_result(block, context, location, acc, acc)?;
        let bit_is_one = append_is_one(block, context, location, bit)?;
        let current_acc: EmbeddedPointValue<'c, 'a> = acc;
        let then_region = Region::new();
        let then_block = Block::new(&[]);
        let then_point = emit_curve_add_result(&then_block, context, location, current_acc, point)?;
        then_block.append_operation(scf::r#yield(
            &[then_point.0, then_point.1, then_point.2],
            location,
        ));
        then_region.append_block(then_block);

        let else_region = Region::new();
        let else_block = Block::new(&[]);
        else_block.append_operation(scf::r#yield(
            &[current_acc.0, current_acc.1, current_acc.2],
            location,
        ));
        else_region.append_block(else_block);

        let result = block.append_operation(scf::r#if(
            bit_is_one,
            &result_types,
            then_region,
            else_region,
            location,
        ));
        acc = (
            result.result(0)?.into(),
            result.result(1)?.into(),
            result.result(2)?.into(),
        );
    }

    Ok(acc)
}

fn append_is_one<'c, 'a, 'v>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    value: Value<'c, 'v>,
) -> Result<Value<'c, 'a>, Error> {
    let one = append_felt_constant(block, context, location, &FieldElement::one())?;
    append_op_with_result(block, dialect::bool::eq(location, value, one)?)
}

fn multi_scalar_mul_arity(opcode: &Opcode<FieldElement>) -> Option<usize> {
    match opcode {
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::MultiScalarMul { points, .. }) => {
            Some(points.len() / 3)
        }
        _ => None,
    }
}
