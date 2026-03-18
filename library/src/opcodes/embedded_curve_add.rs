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
    opcodes::{OpcodeEmitter, bitwise},
};

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
            bitwise::collect_input_witness(&mut witnesses, input);
        }
        bitwise::collect_input_witness(&mut witnesses, self.predicate);

        witnesses
    }

    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let input1_x = bitwise::emit_blackbox_input(writer, &self.input1[0])?;
        let input1_y = bitwise::emit_blackbox_input(writer, &self.input1[1])?;
        let input2_x = bitwise::emit_blackbox_input(writer, &self.input2[0])?;
        let input2_y = bitwise::emit_blackbox_input(writer, &self.input2[1])?;
        let predicate = bitwise::emit_blackbox_input(writer, self.predicate)?;
        let predicate_is_true = emit_is_one(writer, predicate)?;
        let felt_type: Type<'c> = FeltType::with_field(writer.context, FIELD_NAME).into();

        let then_region = Region::new();
        let then_block = Block::new(&[]);
        let (output_x, output_y, output_infinite) = emit_curve_add_result(
            &then_block,
            writer.context,
            writer.location,
            (input1_x, input1_y),
            (input2_x, input2_y),
            self.is_doubling(),
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
        let input1_x = bitwise::emit_blackbox_input(writer, &self.input1[0])?;
        let input1_y = bitwise::emit_blackbox_input(writer, &self.input1[1])?;
        let input1_infinite = bitwise::emit_blackbox_input(writer, &self.input1[2])?;
        let input2_x = bitwise::emit_blackbox_input(writer, &self.input2[0])?;
        let input2_y = bitwise::emit_blackbox_input(writer, &self.input2[1])?;
        let input2_infinite = bitwise::emit_blackbox_input(writer, &self.input2[2])?;
        let predicate = bitwise::emit_blackbox_input(writer, self.predicate)?;
        let predicate_is_true = emit_is_one(writer, predicate)?;
        let output_x = writer.read_witness(self.outputs.0.0)?;
        let output_y = writer.read_witness(self.outputs.1.0)?;
        let output_infinite = writer.read_witness(self.outputs.2.0)?;

        let then_region = Region::new();
        let then_block = Block::new(&[]);
        emit_boolean_constraint(
            &then_block,
            writer.context,
            writer.location,
            input1_infinite,
        )?;
        emit_boolean_constraint(
            &then_block,
            writer.context,
            writer.location,
            input2_infinite,
        )?;
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

        let (expected_x, expected_y, expected_infinite) = emit_curve_add_result(
            &then_block,
            writer.context,
            writer.location,
            (input1_x, input1_y),
            (input2_x, input2_y),
            self.is_doubling(),
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

impl EmbeddedCurveAdd<'_> {
    fn is_doubling(&self) -> bool {
        self.input1
            .iter()
            .zip(self.input2.iter())
            .all(|(lhs, rhs)| same_input(lhs, rhs))
    }
}

fn same_input(lhs: &FunctionInput<FieldElement>, rhs: &FunctionInput<FieldElement>) -> bool {
    match (lhs, rhs) {
        (FunctionInput::Witness(lhs), FunctionInput::Witness(rhs)) => lhs.0 == rhs.0,
        (FunctionInput::Constant(lhs), FunctionInput::Constant(rhs)) => lhs == rhs,
        _ => false,
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

fn emit_curve_add_result<'c, 'a>(
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
    let neg_seventeen =
        append_felt_constant(block, context, location, &-FieldElement::from(17_u128))?;
    let rhs = append_op_with_result(block, dialect::felt::add(location, x_cu, neg_seventeen)?)?;
    block.append_operation(dialect::constrain::eq(location, y_sq, rhs));
    Ok(())
}

fn emit_boolean_constraint<'c>(
    block: &Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    value: Value<'c, '_>,
) -> Result<(), Error> {
    let one = append_felt_constant(block, context, location, &FieldElement::one())?;
    let zero = append_felt_constant(block, context, location, &FieldElement::zero())?;
    let value_minus_one = append_op_with_result(block, dialect::felt::sub(location, value, one)?)?;
    let product =
        append_op_with_result(block, dialect::felt::mul(location, value, value_minus_one)?)?;
    block.append_operation(dialect::constrain::eq(location, product, zero));
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
