use acir::{AcirField, FieldElement};
use llzk::{
    builder::OpBuilder,
    prelude::{
        LlzkContext, Location, Type, Value,
        dialect::{bool, felt},
    },
};

use crate::{
    blackboxes::common::append_felt_constant,
    block_writer::BlockWriter,
    common::{
        append_if_with_results, as_value, constrain_bool, emit_gated_eq, insert_if_with_results,
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
    as_value(bool::eq(
        &OpBuilder::new(writer.context(), writer.insertion_point()),
        writer.location(),
        value,
        one,
    )?)
}

/// Constrains `value` to be in `{0, 1}` when `gate` is `1`.
pub(crate) fn emit_gated_boolean<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    gate: Value<'c, 'b>,
    value: Value<'c, 'b>,
    one: Value<'c, 'b>,
    zero: Value<'c, 'b>,
) -> Result<(), Error> {
    let neg_value = writer.insert_neg(value)?;
    let one_minus_value = writer.insert_add(one, neg_value)?;
    let product = writer.insert_mul(value, one_minus_value)?;
    emit_gated_eq(writer, gate, product, zero)
}

pub(crate) fn emit_predicate_gate<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    predicate: Value<'c, 'b>,
) -> Result<(Value<'c, 'b>, Value<'c, 'b>), Error> {
    // Constrain predicate to have boolean evaluation
    constrain_bool(writer, predicate)?;
    let predicate_is_true = emit_is_one(writer, predicate)?;
    let context = writer.context();
    let location = writer.location();
    let result_types = [Type::from(context.felt_type())];
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

pub(crate) fn emit_finite_curve_add_result<'c: 'a, 'a>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    input1: AffinePointValue<'c, '_>,
    input2: AffinePointValue<'c, '_>,
) -> Result<(Value<'c, 'a>, Value<'c, 'a>, Value<'c, 'a>), Error> {
    let (input1_x, input1_y) = input1;
    let (input2_x, input2_y) = input2;
    let felt_type = Type::from(context.felt_type());

    let x_equal = as_value(bool::eq(builder, location, input1_x, input2_x)?)?;

    let result_types = [felt_type, felt_type, felt_type];
    append_if_with_results(
        builder,
        location,
        x_equal,
        &result_types,
        |builder| {
            let y_equal = as_value(bool::eq(builder, location, input1_y, input2_y)?)?;

            append_if_with_results(
                builder,
                location,
                y_equal,
                &result_types,
                |builder| {
                    let zero =
                        append_felt_constant(builder, context, location, &FieldElement::zero())?;
                    let y_is_zero = as_value(bool::eq(builder, location, input1_y, zero)?)?;
                    append_if_with_results(
                        builder,
                        location,
                        y_is_zero,
                        &result_types,
                        |builder| {
                            emit_infinity_point(builder, context, location).map(point_to_array)
                        },
                        |builder| {
                            emit_affine_curve_formula(
                                builder,
                                context,
                                location,
                                (input1_x, input1_y),
                                (input2_x, input2_y),
                                true,
                            )
                            .map(point_to_array)
                        },
                    )
                },
                |builder| emit_infinity_point(builder, context, location).map(point_to_array),
            )
        },
        |builder| {
            emit_affine_curve_formula(
                builder,
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

pub(crate) fn emit_curve_add_result<'c: 'a, 'a>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    input1: EmbeddedPointValue<'c, 'a>,
    input2: EmbeddedPointValue<'c, 'a>,
) -> Result<(Value<'c, 'a>, Value<'c, 'a>, Value<'c, 'a>), Error> {
    let (input1_x, input1_y, input1_infinite) = input1;
    let (input2_x, input2_y, input2_infinite) = input2;
    let felt_type = Type::from(context.felt_type());
    let result_types = [felt_type, felt_type, felt_type];

    let zero = append_felt_constant(builder, context, location, &FieldElement::zero())?;

    let input1_is_finite = as_value(bool::eq(builder, location, input1_infinite, zero)?)?;
    let input2_is_finite = as_value(bool::eq(builder, location, input2_infinite, zero)?)?;
    let input1_is_infinite = as_value(bool::not(builder, location, input1_is_finite)?)?;

    let result = append_if_with_results(
        builder,
        location,
        input1_is_infinite,
        &result_types,
        |_| Ok([input2.0, input2.1, input2.2]),
        |builder| {
            append_if_with_results(
                builder,
                location,
                input2_is_finite,
                &result_types,
                |_| Ok([input1.0, input1.1, input1.2]),
                |builder| {
                    emit_finite_curve_add_result(
                        builder,
                        context,
                        location,
                        (input1_x, input1_y),
                        (input2_x, input2_y),
                    )
                    .map(point_to_array)
                },
            )
        },
    )?;
    Ok((result[0], result[1], result[2]))
}

pub(crate) fn emit_affine_curve_formula<'c: 'a, 'a>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    input1: AffinePointValue<'c, '_>,
    input2: AffinePointValue<'c, '_>,
    is_doubling: bool,
) -> Result<(Value<'c, 'a>, Value<'c, 'a>, Value<'c, 'a>), Error> {
    let (input1_x, input1_y) = input1;
    let (input2_x, input2_y) = input2;

    let lambda = if is_doubling {
        let three = append_felt_constant(builder, context, location, &FieldElement::from(3_u128))?;
        let two = append_felt_constant(builder, context, location, &FieldElement::from(2_u128))?;
        let x_sq = as_value(felt::mul(builder, location, input1_x, input1_x)?)?;
        let numerator = as_value(felt::mul(builder, location, three, x_sq)?)?;
        let denominator = as_value(felt::mul(builder, location, two, input1_y)?)?;
        as_value(felt::div(builder, location, numerator, denominator)?)?
    } else {
        let dy = as_value(felt::sub(builder, location, input2_y, input1_y)?)?;
        let dx = as_value(felt::sub(builder, location, input2_x, input1_x)?)?;
        as_value(felt::div(builder, location, dy, dx)?)?
    };

    let lambda_sq = as_value(felt::mul(builder, location, lambda, lambda)?)?;
    let x_sum = if is_doubling {
        as_value(felt::add(builder, location, input1_x, input1_x)?)?
    } else {
        as_value(felt::add(builder, location, input1_x, input2_x)?)?
    };
    let output_x = as_value(felt::sub(builder, location, lambda_sq, x_sum)?)?;
    let x_diff = as_value(felt::sub(builder, location, input1_x, output_x)?)?;
    let lambda_times_diff = as_value(felt::mul(builder, location, lambda, x_diff)?)?;
    let output_y = as_value(felt::sub(builder, location, lambda_times_diff, input1_y)?)?;
    let output_infinite = append_felt_constant(builder, context, location, &FieldElement::zero())?;

    Ok((output_x, output_y, output_infinite))
}

pub(crate) fn emit_infinity_point<'c: 'a, 'a>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
) -> Result<(Value<'c, 'a>, Value<'c, 'a>, Value<'c, 'a>), Error> {
    let zero_x = append_felt_constant(builder, context, location, &FieldElement::zero())?;
    let zero_y = append_felt_constant(builder, context, location, &FieldElement::zero())?;
    let one_inf = append_felt_constant(builder, context, location, &FieldElement::one())?;
    Ok((zero_x, zero_y, one_inf))
}

pub(crate) fn point_to_array<'c, 'a>(point: EmbeddedPointValue<'c, 'a>) -> [Value<'c, 'a>; 3] {
    [point.0, point.1, point.2]
}

pub(crate) fn point_from_array<'c, 'a>(point: [Value<'c, 'a>; 3]) -> EmbeddedPointValue<'c, 'a> {
    (point[0], point[1], point[2])
}
