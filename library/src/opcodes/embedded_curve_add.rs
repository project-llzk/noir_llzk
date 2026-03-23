use std::collections::BTreeSet;

use acir::{
    AcirField, FieldElement,
    circuit::Opcode,
    circuit::opcodes::{BlackBoxFuncCall, FunctionInput},
    native_types::Witness,
};
use llzk::prelude::{
    Block, BlockLike, FeltType, Location, Operation, Type, Value, dialect,
    melior_dialects::scf,
};

use crate::{
    FIELD_NAME,
    block_writer::BlockWriter,
    common::{
        append_if_with_results, build_yielding_region, emit_gated_eq, field_to_felt_const,
        insert_if_with_results,
    },
    error::Error,
    opcodes::{OpcodeEmitter, collect_input_witness, emit_blackbox_input},
};

/// Grumpkin curve parameter `b` in the short Weierstrass form `y² = x³ + b`.
const GRUMPKIN_B: i128 = -17;

pub(crate) struct EmbeddedCurveAdd<'a> {
    pub(crate) input1: &'a [FunctionInput<FieldElement>; 3],
    pub(crate) input2: &'a [FunctionInput<FieldElement>; 3],
    pub(crate) predicate: &'a FunctionInput<FieldElement>,
    pub(crate) outputs: (Witness, Witness, Witness),
}

impl OpcodeEmitter for EmbeddedCurveAdd<'_> {
    fn get_witnesses(&self) -> BTreeSet<u32> {
        let mut witnesses = BTreeSet::from([self.outputs.0.0, self.outputs.1.0, self.outputs.2.0]);

        for input in self.input1.iter().chain(self.input2.iter()) {
            collect_input_witness(&mut witnesses, input);
        }
        collect_input_witness(&mut witnesses, self.predicate);

        witnesses
    }

    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let input1_x = emit_blackbox_input(writer, &self.input1[0])?;
        let input1_y = emit_blackbox_input(writer, &self.input1[1])?;
        let input1_infinite = emit_blackbox_input(writer, &self.input1[2])?;
        let input2_x = emit_blackbox_input(writer, &self.input2[0])?;
        let input2_y = emit_blackbox_input(writer, &self.input2[1])?;
        let input2_infinite = emit_blackbox_input(writer, &self.input2[2])?;
        let predicate = emit_blackbox_input(writer, self.predicate)?;
        let predicate_is_true = emit_is_one(writer, predicate)?;
        let context = writer.context();
        let location = writer.location();
        let result_types = [felt_type(context), felt_type(context), felt_type(context)];
        let [output_x, output_y, output_infinite] = insert_if_with_results(
            writer,
            predicate_is_true,
            &result_types,
            |then_block| {
                emit_curve_add_result(
                    then_block,
                    context,
                    location,
                    (input1_x, input1_y, input1_infinite),
                    (input2_x, input2_y, input2_infinite),
                )
                .map(point_to_array)
            },
            |else_block| emit_infinity_point(else_block, context, location).map(point_to_array),
        )?;

        writer.write_member(&format!("w{}", self.outputs.0.0), output_x)?;
        writer.write_member(&format!("w{}", self.outputs.1.0), output_y)?;
        writer.write_member(&format!("w{}", self.outputs.2.0), output_infinite)?;
        writer.mark_known(self.outputs.0.0, output_x);
        writer.mark_known(self.outputs.1.0, output_y);
        writer.mark_known(self.outputs.2.0, output_infinite);
        Ok(())
    }

    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let input1_x = emit_blackbox_input(writer, &self.input1[0])?;
        let input1_y = emit_blackbox_input(writer, &self.input1[1])?;
        let input1_infinite = emit_blackbox_input(writer, &self.input1[2])?;
        let input2_x = emit_blackbox_input(writer, &self.input2[0])?;
        let input2_y = emit_blackbox_input(writer, &self.input2[1])?;
        let input2_infinite = emit_blackbox_input(writer, &self.input2[2])?;
        let predicate = emit_blackbox_input(writer, self.predicate)?;
        let output_x = writer.read_witness(self.outputs.0.0)?;
        let output_y = writer.read_witness(self.outputs.1.0)?;
        let output_infinite = writer.read_witness(self.outputs.2.0)?;

        let zero = writer.emit_constant(&FieldElement::zero())?;
        let one = writer.emit_constant(&FieldElement::one())?;
        let (predicate_is_true, predicate_is_true_felt) = emit_predicate_gate(writer, predicate)?;

        // ── Gated input constraints (no division, safe unconditionally) ──

        // Noir's EmbeddedCurveAdd requires finite inputs.
        emit_gated_eq(writer, predicate_is_true_felt, input1_infinite, zero)?;
        emit_gated_eq(writer, predicate_is_true_felt, input2_infinite, zero)?;

        // On-curve: predicate * (y² - (x³ + b)) == 0
        // Grumpkin has cofactor 1, so this subsumes the subgroup check.
        emit_gated_on_curve(writer, predicate_is_true_felt, input1_x, input1_y)?;
        emit_gated_on_curve(writer, predicate_is_true_felt, input2_x, input2_y)?;

        // ── Curve math (needs scf::if — divisions may fail when predicate is false) ──

        let context = writer.context();
        let location = writer.location();
        let no_results: [Type<'c>; 0] = [];
        let _ = insert_if_with_results(
            writer,
            predicate_is_true,
            &no_results,
            |then_block| {
                let (expected_x, expected_y, expected_infinite) = emit_finite_curve_add_result(
                    then_block,
                    context,
                    location,
                    (input1_x, input1_y),
                    (input2_x, input2_y),
                )?;
                then_block.append_operation(dialect::constrain::eq(location, output_x, expected_x));
                then_block.append_operation(dialect::constrain::eq(location, output_y, expected_y));
                then_block.append_operation(dialect::constrain::eq(
                    location,
                    output_infinite,
                    expected_infinite,
                ));
                Ok([])
            },
            |_else_block| Ok([]),
        )?;

        // ── Gated predicate-false output constraints ──

        let predicate_is_false = writer.insert_neg(predicate_is_true_felt)?;
        let predicate_is_false = writer.insert_add(one, predicate_is_false)?;
        emit_gated_eq(writer, predicate_is_false, output_x, zero)?;
        emit_gated_eq(writer, predicate_is_false, output_y, zero)?;
        emit_gated_eq(writer, predicate_is_false, output_infinite, one)?;

        Ok(())
    }
}

pub(crate) fn from_opcode<'a>(opcode: &'a Opcode<FieldElement>) -> Option<EmbeddedCurveAdd<'a>> {
    match opcode {
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::EmbeddedCurveAdd {
            input1,
            input2,
            predicate,
            outputs,
        }) => Some(EmbeddedCurveAdd {
            input1,
            input2,
            predicate,
            outputs: *outputs,
        }),
        _ => None,
    }
}

/// Emits a gated on-curve constraint: `predicate * (y² - (x³ + b)) == 0`.
fn emit_gated_on_curve<'c, 'b>(
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

fn emit_is_one<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    value: Value<'c, 'b>,
) -> Result<Value<'c, 'b>, Error> {
    let one = writer.emit_constant(&FieldElement::one())?;
    writer.insert_op_with_result(dialect::bool::eq(writer.location(), value, one)?)
}

fn emit_predicate_gate<'c, 'b>(
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

type AffinePointValue<'c, 'a> = (Value<'c, 'a>, Value<'c, 'a>);
type EmbeddedPointValue<'c, 'a> = (Value<'c, 'a>, Value<'c, 'a>, Value<'c, 'a>);

fn emit_curve_add_result<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    input1: EmbeddedPointValue<'c, '_>,
    input2: EmbeddedPointValue<'c, '_>,
) -> Result<(Value<'c, 'a>, Value<'c, 'a>, Value<'c, 'a>), Error> {
    let (input1_x, input1_y, input1_infinite) = input1;
    let (input2_x, input2_y, input2_infinite) = input2;
    let felt_type: Type<'c> = FeltType::with_field(context, FIELD_NAME).into();
    let zero = append_felt_constant(block, context, location, &FieldElement::zero())?;
    let input1_is_zero =
        append_op_with_result(block, dialect::bool::eq(location, input1_infinite, zero)?)?;
    let input2_is_zero =
        append_op_with_result(block, dialect::bool::eq(location, input2_infinite, zero)?)?;
    let input1_is_infinite =
        append_op_with_result(block, dialect::bool::not(location, input1_is_zero)?)?;
    let input2_is_infinite =
        append_op_with_result(block, dialect::bool::not(location, input2_is_zero)?)?;
    let any_input_infinite = append_op_with_result(
        block,
        dialect::bool::or(location, input1_is_infinite, input2_is_infinite)?,
    )?;
    let result_types = [felt_type, felt_type, felt_type];
    append_if_with_results(
        block,
        location,
        any_input_infinite,
        &result_types,
        |then_block| emit_infinity_point(then_block, context, location).map(point_to_array),
        |else_block| {
            emit_finite_curve_add_result(
                else_block,
                context,
                location,
                (input1_x, input1_y),
                (input2_x, input2_y),
            )
            .map(point_to_array)
        },
    )
    .map(point_from_array)
}

/// Emits curve addition for inputs known to be finite (infinity flags == 0).
///
/// Handles all runtime cases: x different (chord), x equal + y equal (doubling),
/// x equal + y different (inverse → infinity), and doubling at y=0 (→ infinity).
fn emit_finite_curve_add_result<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    input1: AffinePointValue<'c, '_>,
    input2: AffinePointValue<'c, '_>,
) -> Result<(Value<'c, 'a>, Value<'c, 'a>, Value<'c, 'a>), Error> {
    let (input1_x, input1_y) = input1;
    let (input2_x, input2_y) = input2;
    let felt_type: Type<'c> = FeltType::with_field(context, FIELD_NAME).into();

    let x_equal = append_op_with_result(block, dialect::bool::eq(location, input1_x, input2_x)?)?;

    // x_equal, y_equal → check y == 0 (doubling at tangent vertical)
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

fn emit_affine_curve_formula<'c, 'a>(
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

fn emit_infinity_point<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
) -> Result<(Value<'c, 'a>, Value<'c, 'a>, Value<'c, 'a>), Error> {
    let zero_x = append_felt_constant(block, context, location, &FieldElement::zero())?;
    let zero_y = append_felt_constant(block, context, location, &FieldElement::zero())?;
    let one_inf = append_felt_constant(block, context, location, &FieldElement::one())?;
    Ok((zero_x, zero_y, one_inf))
}

fn append_felt_constant<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    value: &FieldElement,
) -> Result<Value<'c, 'a>, Error> {
    let attr = field_to_felt_const(context, value);
    append_op_with_result(block, dialect::felt::constant(location, attr)?)
}

fn append_op_with_result<'c, 'a>(
    block: &'a Block<'c>,
    op: Operation<'c>,
) -> Result<Value<'c, 'a>, Error> {
    Ok(block.append_operation(op).result(0)?.into())
}

fn felt_type<'c>(context: &'c llzk::prelude::LlzkContext) -> Type<'c> {
    FeltType::with_field(context, FIELD_NAME).into()
}

fn point_to_array<'c, 'a>(point: EmbeddedPointValue<'c, 'a>) -> [Value<'c, 'a>; 3] {
    [point.0, point.1, point.2]
}

fn point_from_array<'c, 'a>(point: [Value<'c, 'a>; 3]) -> EmbeddedPointValue<'c, 'a> {
    (point[0], point[1], point[2])
}
