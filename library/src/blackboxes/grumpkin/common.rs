use acir::{AcirField, FieldElement};
use llzk::prelude::{
    Block, BlockLike, Location, Region, RegionLike, Value, dialect, melior_dialects::scf,
};

use crate::{
    blackboxes::common::{append_felt_constant, append_op_with_result, felt_type},
    block_writer::BlockWriter,
    common::{
        append_if_with_results, build_yielding_region, emit_gated_eq, insert_if_with_results,
    },
    error::Error,
    writer::Writer,
};

const GRUMPKIN_B: i128 = -17;

pub(crate) type AffinePointValue<'c, 'a> = (Value<'c, 'a>, Value<'c, 'a>);
pub(crate) type EmbeddedPointValue<'c, 'a> = (Value<'c, 'a>, Value<'c, 'a>, Value<'c, 'a>);

pub(crate) fn emit_gated_on_curve<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    predicate: Value<'c, 'b>,
    x: Value<'c, 'b>,
    y: Value<'c, 'b>,
) -> Result<(), Error> {
    let y_sq = writer.insert_mul(y, y)?;
    let x_sq = writer.insert_mul(x, x)?;
    let x_cu = writer.insert_mul(x_sq, x)?;
    let curve_b = writer.emit_constant(&FieldElement::from(GRUMPKIN_B))?;
    let rhs = writer.insert_add(x_cu, curve_b)?;
    emit_gated_eq(writer, predicate, y_sq, rhs)
}

pub(crate) fn emit_is_one<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    value: Value<'c, 'b>,
) -> Result<Value<'c, 'b>, Error> {
    let one = writer.emit_constant(&FieldElement::one())?;
    writer.insert_op_with_result(dialect::bool::eq(writer.location(), value, one)?)
}

pub(crate) fn emit_predicate_gate<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    predicate: Value<'c, 'b>,
) -> Result<(Value<'c, 'b>, Value<'c, 'b>), Error> {
    let predicate_is_true = emit_is_one(writer, predicate)?;
    let context = writer.context();
    let location = writer.location();
    let result_types = [felt_type(context)];
    let [predicate_gate] = insert_if_with_results(
        writer,
        predicate_is_true,
        &result_types,
        |then_block| {
            Ok([append_felt_constant(
                then_block,
                context,
                location,
                &FieldElement::one(),
            )?])
        },
        |else_block| {
            Ok([append_felt_constant(
                else_block,
                context,
                location,
                &FieldElement::zero(),
            )?])
        },
    )?;
    Ok((predicate_is_true, predicate_gate))
}

pub(crate) fn emit_finite_curve_add_result<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    input1: AffinePointValue<'c, '_>,
    input2: AffinePointValue<'c, '_>,
) -> Result<(Value<'c, 'a>, Value<'c, 'a>, Value<'c, 'a>), Error> {
    let (input1_x, input1_y) = input1;
    let (input2_x, input2_y) = input2;
    let felt_type = felt_type(context);

    let x_equal = append_op_with_result(block, dialect::bool::eq(location, input1_x, input2_x)?)?;

    let result_types = [felt_type, felt_type, felt_type];
    append_if_with_results(
        block,
        location,
        x_equal,
        &result_types,
        |x_equal_then_block| {
            let y_equal = append_op_with_result(
                x_equal_then_block,
                dialect::bool::eq(location, input1_y, input2_y)?,
            )?;
            let zero =
                append_felt_constant(x_equal_then_block, context, location, &FieldElement::zero())?;
            let y_is_zero = append_op_with_result(
                x_equal_then_block,
                dialect::bool::eq(location, input1_y, zero)?,
            )?;
            let nested_result_types = [felt_type, felt_type, felt_type];
            let y_equal_then = build_yielding_region(location, |y_equal_then_block| {
                let y_zero_then = build_yielding_region(location, |y_zero_then_block| {
                    emit_infinity_point(y_zero_then_block, context, location).map(point_to_array)
                })?;
                let y_zero_else = build_yielding_region(location, |y_zero_else_block| {
                    emit_affine_curve_formula(
                        y_zero_else_block,
                        context,
                        location,
                        (input1_x, input1_y),
                        (input2_x, input2_y),
                        true,
                    )
                    .map(point_to_array)
                })?;
                let result = y_equal_then_block.append_operation(scf::r#if(
                    y_is_zero,
                    &nested_result_types,
                    y_zero_then,
                    y_zero_else,
                    location,
                ));
                Ok([
                    result.result(0)?.into(),
                    result.result(1)?.into(),
                    result.result(2)?.into(),
                ])
            })?;
            let y_equal_else = build_yielding_region(location, |y_equal_else_block| {
                emit_infinity_point(y_equal_else_block, context, location).map(point_to_array)
            })?;
            let result = x_equal_then_block.append_operation(scf::r#if(
                y_equal,
                &nested_result_types,
                y_equal_then,
                y_equal_else,
                location,
            ));
            Ok([
                result.result(0)?.into(),
                result.result(1)?.into(),
                result.result(2)?.into(),
            ])
        },
        |x_equal_else_block| {
            emit_affine_curve_formula(
                x_equal_else_block,
                context,
                location,
                (input1_x, input1_y),
                (input2_x, input2_y),
                false,
            )
            .map(point_to_array)
        },
    )
    .map(point_from_array)
}

pub(crate) fn emit_curve_add_result<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    input1: EmbeddedPointValue<'c, '_>,
    input2: EmbeddedPointValue<'c, '_>,
) -> Result<(Value<'c, 'a>, Value<'c, 'a>, Value<'c, 'a>), Error> {
    let (input1_x, input1_y, input1_infinite) = input1;
    let (input2_x, input2_y, input2_infinite) = input2;
    let felt_type = felt_type(context);
    let zero = append_felt_constant(block, context, location, &FieldElement::zero())?;
    let input1_is_finite =
        append_op_with_result(block, dialect::bool::eq(location, input1_infinite, zero)?)?;
    let input2_is_finite =
        append_op_with_result(block, dialect::bool::eq(location, input2_infinite, zero)?)?;
    let input1_is_infinite =
        append_op_with_result(block, dialect::bool::not(location, input1_is_finite)?)?;
    let result_types = [felt_type, felt_type, felt_type];
    let input1_infinite_then = Region::new();
    let input1_infinite_then_block = Block::new(&[]);
    input1_infinite_then_block
        .append_operation(scf::r#yield(&[input2.0, input2.1, input2.2], location));
    input1_infinite_then.append_block(input1_infinite_then_block);

    let input1_infinite_else = Region::new();
    let input1_infinite_else_block = Block::new(&[]);
    let input2_infinite_then = Region::new();
    let input2_infinite_then_block = Block::new(&[]);
    input2_infinite_then_block
        .append_operation(scf::r#yield(&[input1.0, input1.1, input1.2], location));
    input2_infinite_then.append_block(input2_infinite_then_block);

    let input2_infinite_else = build_yielding_region(location, |finite_block| {
        emit_finite_curve_add_result(
            finite_block,
            context,
            location,
            (input1_x, input1_y),
            (input2_x, input2_y),
        )
        .map(point_to_array)
    })?;
    let result = input1_infinite_else_block.append_operation(scf::r#if(
        input2_is_finite,
        &result_types,
        input2_infinite_else,
        input2_infinite_then,
        location,
    ));
    input1_infinite_else_block.append_operation(scf::r#yield(
        &[
            result.result(0)?.into(),
            result.result(1)?.into(),
            result.result(2)?.into(),
        ],
        location,
    ));
    input1_infinite_else.append_block(input1_infinite_else_block);

    let result = block.append_operation(scf::r#if(
        input1_is_infinite,
        &result_types,
        input1_infinite_then,
        input1_infinite_else,
        location,
    ));
    Ok((
        result.result(0)?.into(),
        result.result(1)?.into(),
        result.result(2)?.into(),
    ))
}

pub(crate) fn emit_affine_curve_formula<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    input1: AffinePointValue<'c, '_>,
    input2: AffinePointValue<'c, '_>,
    is_doubling: bool,
) -> Result<(Value<'c, 'a>, Value<'c, 'a>, Value<'c, 'a>), Error> {
    let (input1_x, input1_y) = input1;
    let (input2_x, input2_y) = input2;

    let lambda = if is_doubling {
        let three = append_felt_constant(block, context, location, &FieldElement::from(3_u128))?;
        let two = append_felt_constant(block, context, location, &FieldElement::from(2_u128))?;
        let x_sq = append_op_with_result(block, dialect::felt::mul(location, input1_x, input1_x)?)?;
        let numerator = append_op_with_result(block, dialect::felt::mul(location, three, x_sq)?)?;
        let denominator =
            append_op_with_result(block, dialect::felt::mul(location, two, input1_y)?)?;
        append_op_with_result(block, dialect::felt::div(location, numerator, denominator)?)?
    } else {
        let dy = append_op_with_result(block, dialect::felt::sub(location, input2_y, input1_y)?)?;
        let dx = append_op_with_result(block, dialect::felt::sub(location, input2_x, input1_x)?)?;
        append_op_with_result(block, dialect::felt::div(location, dy, dx)?)?
    };

    let lambda_sq = append_op_with_result(block, dialect::felt::mul(location, lambda, lambda)?)?;
    let x_sum = if is_doubling {
        append_op_with_result(block, dialect::felt::add(location, input1_x, input1_x)?)?
    } else {
        append_op_with_result(block, dialect::felt::add(location, input1_x, input2_x)?)?
    };
    let output_x = append_op_with_result(block, dialect::felt::sub(location, lambda_sq, x_sum)?)?;
    let x_diff = append_op_with_result(block, dialect::felt::sub(location, input1_x, output_x)?)?;
    let lambda_times_diff =
        append_op_with_result(block, dialect::felt::mul(location, lambda, x_diff)?)?;
    let output_y = append_op_with_result(
        block,
        dialect::felt::sub(location, lambda_times_diff, input1_y)?,
    )?;
    let output_infinite = append_felt_constant(block, context, location, &FieldElement::zero())?;

    Ok((output_x, output_y, output_infinite))
}

pub(crate) fn emit_infinity_point<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
) -> Result<(Value<'c, 'a>, Value<'c, 'a>, Value<'c, 'a>), Error> {
    let zero_x = append_felt_constant(block, context, location, &FieldElement::zero())?;
    let zero_y = append_felt_constant(block, context, location, &FieldElement::zero())?;
    let one_inf = append_felt_constant(block, context, location, &FieldElement::one())?;
    Ok((zero_x, zero_y, one_inf))
}

pub(crate) fn point_to_array<'c, 'a>(point: EmbeddedPointValue<'c, 'a>) -> [Value<'c, 'a>; 3] {
    [point.0, point.1, point.2]
}

pub(crate) fn point_from_array<'c, 'a>(point: [Value<'c, 'a>; 3]) -> EmbeddedPointValue<'c, 'a> {
    (point[0], point[1], point[2])
}
