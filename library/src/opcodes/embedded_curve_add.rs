use std::collections::BTreeSet;

use acir::{
    AcirField, FieldElement,
    circuit::Opcode,
    circuit::opcodes::{BlackBoxFuncCall, FunctionInput},
    native_types::Witness,
};
use llzk::prelude::{
    Block, BlockLike, FeltType, Location, Operation, Region, RegionLike, Type, Value, dialect,
    melior_dialects::scf,
};

use crate::{
    FIELD_NAME,
    block_writer::BlockWriter,
    common::field_to_felt_const,
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
        let felt_type: Type<'c> = FeltType::with_field(writer.context, FIELD_NAME).into();

        let then_region = Region::new();
        let then_block = Block::new(&[]);
        let (output_x, output_y, output_infinite) = emit_curve_add_result(
            &then_block,
            writer.context,
            writer.location,
            (input1_x, input1_y, input1_infinite),
            (input2_x, input2_y, input2_infinite),
        )?;
        then_block.append_operation(scf::r#yield(
            &[output_x, output_y, output_infinite],
            writer.location,
        ));
        then_region.append_block(then_block);

        let else_region = Region::new();
        let else_block = Block::new(&[]);
        let zero_x = append_felt_constant(
            &else_block,
            writer.context,
            writer.location,
            &FieldElement::zero(),
        )?;
        let zero_y = append_felt_constant(
            &else_block,
            writer.context,
            writer.location,
            &FieldElement::zero(),
        )?;
        let one_inf = append_felt_constant(
            &else_block,
            writer.context,
            writer.location,
            &FieldElement::one(),
        )?;
        else_block.append_operation(scf::r#yield(&[zero_x, zero_y, one_inf], writer.location));
        else_region.append_block(else_block);

        let result_op = writer.insert_op(scf::r#if(
            predicate_is_true,
            &[felt_type, felt_type, felt_type],
            then_region,
            else_region,
            writer.location,
        ));
        let output_x: Value<'c, 'b> = result_op.result(0)?.into();
        let output_y: Value<'c, 'b> = result_op.result(1)?.into();
        let output_infinite: Value<'c, 'b> = result_op.result(2)?.into();

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
        let predicate_is_true = emit_is_one(writer, predicate)?;
        let output_x = writer.read_witness(self.outputs.0.0)?;
        let output_y = writer.read_witness(self.outputs.1.0)?;
        let output_infinite = writer.read_witness(self.outputs.2.0)?;

        let then_region = Region::new();
        let then_block = Block::new(&[]);
        // Noir's EmbeddedCurveAdd requires finite inputs. Constraining the
        // infinity flags to zero subsumes any boolean check.
        constrain_to_constant(
            &then_block,
            writer.context,
            writer.location,
            input1_infinite,
            &FieldElement::zero(),
        )?;
        constrain_to_constant(
            &then_block,
            writer.context,
            writer.location,
            input2_infinite,
            &FieldElement::zero(),
        )?;
        constrain_on_curve(
            &then_block,
            writer.context,
            writer.location,
            input1_x,
            input1_y,
        )?;
        constrain_on_curve(
            &then_block,
            writer.context,
            writer.location,
            input2_x,
            input2_y,
        )?;
        // Grumpkin has cofactor 1, so Noir's subgroup check is vacuous once the
        // point is known to be on the curve.

        // Both infinity flags are already constrained to zero above, so the
        // full infinity-handling tree is unreachable. Use the finite-only
        // version to avoid emitting dead IR.
        let (expected_x, expected_y, expected_infinite) = emit_finite_curve_add_result(
            &then_block,
            writer.context,
            writer.location,
            (input1_x, input1_y),
            (input2_x, input2_y),
        )?;
        then_block.append_operation(dialect::constrain::eq(
            writer.location,
            output_x,
            expected_x,
        ));
        then_block.append_operation(dialect::constrain::eq(
            writer.location,
            output_y,
            expected_y,
        ));
        then_block.append_operation(dialect::constrain::eq(
            writer.location,
            output_infinite,
            expected_infinite,
        ));
        then_block.append_operation(scf::r#yield(&[], writer.location));
        then_region.append_block(then_block);

        let else_region = Region::new();
        let else_block = Block::new(&[]);
        constrain_to_constant(
            &else_block,
            writer.context,
            writer.location,
            output_x,
            &FieldElement::zero(),
        )?;
        constrain_to_constant(
            &else_block,
            writer.context,
            writer.location,
            output_y,
            &FieldElement::zero(),
        )?;
        constrain_to_constant(
            &else_block,
            writer.context,
            writer.location,
            output_infinite,
            &FieldElement::one(),
        )?;
        else_block.append_operation(scf::r#yield(&[], writer.location));
        else_region.append_block(else_block);

        writer.insert_op(scf::r#if(
            predicate_is_true,
            &[],
            then_region,
            else_region,
            writer.location,
        ));
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

fn emit_is_one<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    value: Value<'c, 'b>,
) -> Result<Value<'c, 'b>, Error> {
    let one = append_felt_constant_via_writer(writer, &FieldElement::one())?;
    writer.insert_op_with_result(dialect::bool::eq(writer.location, value, one)?)
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

    let finite_then = Region::new();
    let finite_then_block = Block::new(&[]);
    let finite = emit_finite_curve_add_result(
        &finite_then_block,
        context,
        location,
        (input1_x, input1_y),
        (input2_x, input2_y),
    )?;
    finite_then_block.append_operation(scf::r#yield(&[finite.0, finite.1, finite.2], location));
    finite_then.append_block(finite_then_block);

    let finite_else = Region::new();
    let finite_else_block = Block::new(&[]);
    let infinity = emit_infinity_point(&finite_else_block, context, location)?;
    finite_else_block.append_operation(scf::r#yield(
        &[infinity.0, infinity.1, infinity.2],
        location,
    ));
    finite_else.append_block(finite_else_block);

    let result = block.append_operation(scf::r#if(
        any_input_infinite,
        &[felt_type, felt_type, felt_type],
        finite_else,
        finite_then,
        location,
    ));

    Ok((
        result.result(0)?.into(),
        result.result(1)?.into(),
        result.result(2)?.into(),
    ))
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

    // x_equal → check y
    let x_equal_then = Region::new();
    let x_equal_then_block = Block::new(&[]);
    let y_equal = append_op_with_result(
        &x_equal_then_block,
        dialect::bool::eq(location, input1_y, input2_y)?,
    )?;

    // x_equal, y_equal → check y == 0 (doubling at tangent vertical)
    let y_equal_then = Region::new();
    let y_equal_then_block = Block::new(&[]);
    let zero = append_felt_constant(
        &y_equal_then_block,
        context,
        location,
        &FieldElement::zero(),
    )?;
    let y_is_zero = append_op_with_result(
        &y_equal_then_block,
        dialect::bool::eq(location, input1_y, zero)?,
    )?;

    // y == 0 → infinity (vertical tangent)
    let y_zero_then = Region::new();
    let y_zero_then_block = Block::new(&[]);
    let inf = emit_infinity_point(&y_zero_then_block, context, location)?;
    y_zero_then_block.append_operation(scf::r#yield(&[inf.0, inf.1, inf.2], location));
    y_zero_then.append_block(y_zero_then_block);

    // y != 0 → doubling formula
    let y_zero_else = Region::new();
    let y_zero_else_block = Block::new(&[]);
    let doubled = emit_affine_curve_formula(
        &y_zero_else_block,
        context,
        location,
        (input1_x, input1_y),
        (input2_x, input2_y),
        true,
    )?;
    y_zero_else_block.append_operation(scf::r#yield(&[doubled.0, doubled.1, doubled.2], location));
    y_zero_else.append_block(y_zero_else_block);

    let y_eq_result = y_equal_then_block.append_operation(scf::r#if(
        y_is_zero,
        &[felt_type, felt_type, felt_type],
        y_zero_then,
        y_zero_else,
        location,
    ));
    let yr_x: Value<'c, '_> = y_eq_result.result(0)?.into();
    let yr_y: Value<'c, '_> = y_eq_result.result(1)?.into();
    let yr_inf: Value<'c, '_> = y_eq_result.result(2)?.into();
    y_equal_then_block.append_operation(scf::r#yield(&[yr_x, yr_y, yr_inf], location));
    y_equal_then.append_block(y_equal_then_block);

    // x_equal, y_different → inverse points, return infinity
    let y_equal_else = Region::new();
    let y_equal_else_block = Block::new(&[]);
    let inf = emit_infinity_point(&y_equal_else_block, context, location)?;
    y_equal_else_block.append_operation(scf::r#yield(&[inf.0, inf.1, inf.2], location));
    y_equal_else.append_block(y_equal_else_block);

    let x_eq_result = x_equal_then_block.append_operation(scf::r#if(
        y_equal,
        &[felt_type, felt_type, felt_type],
        y_equal_then,
        y_equal_else,
        location,
    ));
    let xr_x: Value<'c, '_> = x_eq_result.result(0)?.into();
    let xr_y: Value<'c, '_> = x_eq_result.result(1)?.into();
    let xr_inf: Value<'c, '_> = x_eq_result.result(2)?.into();
    x_equal_then_block.append_operation(scf::r#yield(&[xr_x, xr_y, xr_inf], location));
    x_equal_then.append_block(x_equal_then_block);

    // x_different → chord formula (general addition)
    let x_equal_else = Region::new();
    let x_equal_else_block = Block::new(&[]);
    let added = emit_affine_curve_formula(
        &x_equal_else_block,
        context,
        location,
        (input1_x, input1_y),
        (input2_x, input2_y),
        false,
    )?;
    x_equal_else_block.append_operation(scf::r#yield(&[added.0, added.1, added.2], location));
    x_equal_else.append_block(x_equal_else_block);

    let result = block.append_operation(scf::r#if(
        x_equal,
        &[felt_type, felt_type, felt_type],
        x_equal_then,
        x_equal_else,
        location,
    ));

    Ok((
        result.result(0)?.into(),
        result.result(1)?.into(),
        result.result(2)?.into(),
    ))
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

fn constrain_on_curve<'c>(
    block: &Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    x: Value<'c, '_>,
    y: Value<'c, '_>,
) -> Result<(), Error> {
    let y_sq = append_op_with_result(block, dialect::felt::mul(location, y, y)?)?;
    let x_sq = append_op_with_result(block, dialect::felt::mul(location, x, x)?)?;
    let x_cu = append_op_with_result(block, dialect::felt::mul(location, x_sq, x)?)?;
    let curve_b = append_felt_constant(block, context, location, &FieldElement::from(GRUMPKIN_B))?;
    let rhs = append_op_with_result(block, dialect::felt::add(location, x_cu, curve_b)?)?;
    block.append_operation(dialect::constrain::eq(location, y_sq, rhs));
    Ok(())
}

fn constrain_to_constant<'c>(
    block: &Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    value: Value<'c, '_>,
    constant: &FieldElement,
) -> Result<(), Error> {
    let expected = append_felt_constant(block, context, location, constant)?;
    block.append_operation(dialect::constrain::eq(location, value, expected));
    Ok(())
}

fn append_felt_constant_via_writer<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    value: &FieldElement,
) -> Result<Value<'c, 'b>, Error> {
    let attr = field_to_felt_const(writer.context, value);
    writer.insert_op_with_result(dialect::felt::constant(writer.location, attr)?)
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
