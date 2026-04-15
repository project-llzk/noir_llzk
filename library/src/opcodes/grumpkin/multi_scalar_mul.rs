use std::collections::BTreeSet;

use acir::{
    AcirField, FieldElement,
    circuit::Opcode,
    circuit::opcodes::{BlackBoxFuncCall, FunctionInput},
    native_types::Witness,
};
use llzk::prelude::Value;

use crate::{
    blackboxes::{
        grumpkin::{
            common::{EmbeddedPointValue, emit_gated_on_curve, emit_predicate_gate},
            multi_scalar_mul::{SCALAR_HIGH_BITS, SCALAR_LOW_BITS, SCALAR_TOTAL_BITS},
        },
        registry::BlackboxFunction,
    },
    block_writer::BlockWriter,
    common::emit_gated_eq,
    error::Error,
    opcodes::{OpcodeEmitter, collect_input_witness, emit_blackbox_input},
};

const GRUMPKIN_SCALAR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

pub(crate) struct MultiScalarMul<'a> {
    points: &'a [FunctionInput<FieldElement>],
    scalars: &'a [FunctionInput<FieldElement>],
    predicate: &'a FunctionInput<FieldElement>,
    outputs: (Witness, Witness, Witness),
}

impl OpcodeEmitter for MultiScalarMul<'_> {
    fn get_witnesses(&self) -> BTreeSet<u32> {
        let mut witnesses = BTreeSet::from([self.outputs.0.0, self.outputs.1.0, self.outputs.2.0]);

        for input in self.points.iter().chain(self.scalars.iter()) {
            collect_input_witness(&mut witnesses, input);
        }
        collect_input_witness(&mut witnesses, self.predicate);

        witnesses
    }

    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let num_points = validate_multi_scalar_mul_inputs(self.points, self.scalars)?;
        let points = emit_points(writer, self.points)?;
        let scalar_bits = emit_scalar_decompositions(writer, num_points)?;
        let predicate = emit_blackbox_input(writer, self.predicate)?;
        let helper_call = self.call_helper(writer, &points, &scalar_bits, predicate)?;
        let output_x = helper_call.result(0)?.into();
        let output_y = helper_call.result(1)?.into();
        let output_infinite = helper_call.result(2)?.into();

        writer.write_member(&format!("w{}", self.outputs.0.0), output_x)?;
        writer.write_member(&format!("w{}", self.outputs.1.0), output_y)?;
        writer.write_member(&format!("w{}", self.outputs.2.0), output_infinite)?;
        writer.mark_known(self.outputs.0.0, output_x);
        writer.mark_known(self.outputs.1.0, output_y);
        writer.mark_known(self.outputs.2.0, output_infinite);
        Ok(())
    }

    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let num_points = validate_multi_scalar_mul_inputs(self.points, self.scalars)?;
        let points = emit_points(writer, self.points)?;
        let scalar_inputs = emit_scalar_inputs(writer, self.scalars)?;
        let scalar_bits = emit_scalar_decompositions(writer, num_points)?;
        let predicate = emit_blackbox_input(writer, self.predicate)?;
        let output_x = writer.read_witness(self.outputs.0.0)?;
        let output_y = writer.read_witness(self.outputs.1.0)?;
        let output_infinite = writer.read_witness(self.outputs.2.0)?;

        let one = writer.emit_constant(&FieldElement::one())?;
        let zero = writer.emit_constant(&FieldElement::zero())?;
        let (_, predicate_gate) = emit_predicate_gate(writer, predicate)?;

        for &(x, y, is_infinite) in &points {
            emit_gated_boolean(writer, predicate_gate, is_infinite, one, zero)?;
            let finite_gate = writer.insert_neg(is_infinite)?;
            let finite_gate = writer.insert_add(one, finite_gate)?;
            let finite_gate = writer.insert_mul(predicate_gate, finite_gate)?;
            emit_gated_on_curve(writer, finite_gate, x, y)?;
        }

        for ((lo, hi), bits) in scalar_inputs.iter().zip(&scalar_bits) {
            emit_scalar_constraints(writer, *lo, *hi, bits, predicate_gate, one, zero)?;
        }

        let helper_call = self.call_helper(writer, &points, &scalar_bits, predicate)?;
        let expected_x = helper_call.result(0)?.into();
        let expected_y = helper_call.result(1)?.into();
        let expected_infinite = helper_call.result(2)?.into();
        writer.insert_constrain_eq(output_x, expected_x);
        writer.insert_constrain_eq(output_y, expected_y);
        writer.insert_constrain_eq(output_infinite, expected_infinite);

        Ok(())
    }
}

pub(crate) fn from_opcode<'a>(opcode: &'a Opcode<FieldElement>) -> Option<MultiScalarMul<'a>> {
    match opcode {
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::MultiScalarMul {
            points,
            scalars,
            predicate,
            outputs,
        }) => Some(MultiScalarMul {
            points,
            scalars,
            predicate,
            outputs: *outputs,
        }),
        _ => None,
    }
}

fn emit_points<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    points: &[FunctionInput<FieldElement>],
) -> Result<Vec<EmbeddedPointValue<'c, 'b>>, Error> {
    debug_assert!(points.len().is_multiple_of(3));

    points
        .chunks_exact(3)
        .map(|chunk| {
            Ok((
                emit_blackbox_input(writer, &chunk[0])?,
                emit_blackbox_input(writer, &chunk[1])?,
                emit_blackbox_input(writer, &chunk[2])?,
            ))
        })
        .collect()
}

fn emit_scalar_inputs<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    scalars: &[FunctionInput<FieldElement>],
) -> Result<Vec<(Value<'c, 'b>, Value<'c, 'b>)>, Error> {
    debug_assert!(scalars.len().is_multiple_of(2));

    scalars
        .chunks_exact(2)
        .map(|chunk| {
            Ok((
                emit_blackbox_input(writer, &chunk[0])?,
                emit_blackbox_input(writer, &chunk[1])?,
            ))
        })
        .collect()
}

fn emit_scalar_decompositions<'c, 'b>(
    writer: &BlockWriter<'c, 'b>,
    num_scalars: usize,
) -> Result<Vec<Vec<Value<'c, 'b>>>, Error> {
    (0..num_scalars).map(|_| emit_scalar_bits(writer)).collect()
}

fn emit_scalar_bits<'c, 'b>(writer: &BlockWriter<'c, 'b>) -> Result<Vec<Value<'c, 'b>>, Error> {
    let felt_type = writer.felt_type();
    (0..SCALAR_TOTAL_BITS)
        .map(|_| writer.insert_nondet(felt_type))
        .collect()
}

fn emit_scalar_constraints<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    lo: Value<'c, 'b>,
    hi: Value<'c, 'b>,
    bits: &[Value<'c, 'b>],
    gate: Value<'c, 'b>,
    one: Value<'c, 'b>,
    zero: Value<'c, 'b>,
) -> Result<(), Error> {
    debug_assert_eq!(bits.len(), SCALAR_TOTAL_BITS);

    let lo_bits = &bits[..SCALAR_LOW_BITS];
    let hi_bits = &bits[SCALAR_LOW_BITS..];

    for &bit in bits {
        emit_gated_boolean(writer, gate, bit, one, zero)?;
    }

    let lo_value = reconstruct_scalar_limb(writer, lo_bits)?;
    let hi_value = reconstruct_scalar_limb(writer, hi_bits)?;
    emit_gated_eq(writer, gate, lo_value, lo)?;
    emit_gated_eq(writer, gate, hi_value, hi)?;

    let modulus_bits = grumpkin_scalar_modulus_bits_le();
    let mut prefix_equal = one;
    for bit_index in (0..SCALAR_TOTAL_BITS).rev() {
        let bit = bits[bit_index];
        if modulus_bits[bit_index] {
            prefix_equal = writer.insert_mul(prefix_equal, bit)?;
        } else {
            let prefix_and_bit = writer.insert_mul(prefix_equal, bit)?;
            emit_gated_eq(writer, gate, prefix_and_bit, zero)?;
        }
    }
    emit_gated_eq(writer, gate, prefix_equal, zero)?;

    Ok(())
}

fn reconstruct_scalar_limb<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    bits: &[Value<'c, 'b>],
) -> Result<Value<'c, 'b>, Error> {
    let mut coeff = FieldElement::one();
    let mut acc = bits[0];
    let two = FieldElement::from(2u128);
    for &bit in &bits[1..] {
        coeff = coeff * two;
        let coeff_val = writer.emit_constant(&coeff)?;
        let term = writer.insert_mul(bit, coeff_val)?;
        acc = writer.insert_add(acc, term)?;
    }
    Ok(acc)
}

fn emit_gated_boolean<'c, 'b>(
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

fn validate_scalar_limb(input: &FunctionInput<FieldElement>, num_bits: u32) -> Result<(), Error> {
    match input {
        FunctionInput::Constant(c) if c.num_bits() > num_bits => Err(Error::ConstantOutOfRange {
            value: *c,
            num_bits,
        }),
        _ => Ok(()),
    }
}

fn validate_multi_scalar_mul_inputs(
    points: &[FunctionInput<FieldElement>],
    scalars: &[FunctionInput<FieldElement>],
) -> Result<usize, Error> {
    if !points.len().is_multiple_of(3) || !scalars.len().is_multiple_of(2) {
        return Err(Error::UnsupportedOpcode(
            "malformed MultiScalarMul arity".to_string(),
        ));
    }

    let num_points = points.len() / 3;
    if num_points != scalars.len() / 2 {
        return Err(Error::UnsupportedOpcode(
            "MultiScalarMul expects one scalar per point".to_string(),
        ));
    }

    for chunk in scalars.chunks_exact(2) {
        validate_scalar_limb(&chunk[0], SCALAR_LOW_BITS as u32)?;
        validate_scalar_limb(&chunk[1], SCALAR_HIGH_BITS as u32)?;
    }

    Ok(num_points)
}

fn grumpkin_scalar_modulus_bits_le() -> [bool; SCALAR_TOTAL_BITS] {
    let mut bits = [false; SCALAR_TOTAL_BITS];
    for (bit_index, slot) in bits.iter_mut().enumerate() {
        let byte = GRUMPKIN_SCALAR_MODULUS_BE[31 - (bit_index / 8)];
        *slot = ((byte >> (bit_index % 8)) & 1) == 1;
    }
    bits
}

impl MultiScalarMul<'_> {
    fn call_helper<'c, 'b>(
        &self,
        writer: &mut BlockWriter<'c, 'b>,
        points: &[EmbeddedPointValue<'c, 'b>],
        scalar_bits: &[Vec<Value<'c, 'b>>],
        predicate: Value<'c, 'b>,
    ) -> Result<llzk::prelude::OperationRef<'c, 'b>, Error> {
        let num_points = points.len();
        let mut args = Vec::with_capacity(num_points * (3 + SCALAR_TOTAL_BITS) + 1);
        for &(x, y, infinite) in points {
            args.extend([x, y, infinite]);
        }
        for bits in scalar_bits {
            args.extend(bits.iter().copied());
        }
        args.push(predicate);
        writer.call_blackbox_function(BlackboxFunction::MultiScalarMul { num_points }, &args)
    }
}
