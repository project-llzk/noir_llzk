pub(crate) mod and;
pub(crate) mod rangecheck;
pub(crate) mod xor;

use std::collections::BTreeSet;

use acir::{AcirField, FieldElement, circuit::opcodes::FunctionInput};
use llzk::prelude::{Value, dialect};

use crate::{block_writer::BlockWriter, error::Error};

/// Emits the LLZK value for an ACIR [`FunctionInput`]: either a witness read
/// or a felt constant.
pub(crate) fn emit_blackbox_input<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    input: &FunctionInput<FieldElement>,
) -> Result<Value<'c, 'b>, Error> {
    match input {
        FunctionInput::Witness(w) => writer.read_witness(w.0),
        FunctionInput::Constant(c) => writer.emit_constant(c),
    }
}

/// Emits a felt constant equal to `(1 << num_bits) - 1`, i.e. a bitmask
/// selecting the lowest `num_bits` bits.
pub(crate) fn emit_bit_mask<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    num_bits: u32,
) -> Result<Value<'c, 'b>, Error> {
    let mask = if num_bits == 0 {
        FieldElement::zero()
    } else {
        FieldElement::from(2u128).pow(&FieldElement::from(num_bits as u128)) - FieldElement::one()
    };
    writer.emit_constant(&mask)
}

/// Collects witness indices from an ACIR [`FunctionInput`].
pub(crate) fn collect_input_witness(
    witnesses: &mut BTreeSet<u32>,
    input: &FunctionInput<FieldElement>,
) {
    if let FunctionInput::Witness(w) = input {
        witnesses.insert(w.0);
    }
}

/// Returns true if the field element fits within `num_bits` bits.
pub(crate) fn constant_fits_in_bits(fe: &FieldElement, num_bits: u32) -> bool {
    if num_bits == 0 {
        return fe.is_zero();
    }
    fe.num_bits() <= num_bits
}

/// Returns whether `input` needs a bit-width mask and constraint.
pub(crate) fn input_needs_mask(
    input: &FunctionInput<FieldElement>,
    num_bits: u32,
) -> Result<bool, Error> {
    match input {
        FunctionInput::Witness(_) => Ok(true),
        FunctionInput::Constant(c) if constant_fits_in_bits(c, num_bits) => Ok(false),
        FunctionInput::Constant(c) => Err(Error::ConstantOutOfRange {
            value: *c,
            num_bits,
        }),
    }
}

/// Returns the input value, constraining witnesses to the selected bit width.
pub(crate) fn emit_constrained_input<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    input: &FunctionInput<FieldElement>,
    num_bits: u32,
    mask: Option<Value<'c, 'b>>,
) -> Result<Value<'c, 'b>, Error> {
    let val = emit_blackbox_input(writer, input)?;
    let needs_mask = input_needs_mask(input, num_bits)?;
    if !needs_mask {
        return Ok(val);
    }

    let Some(mask) = mask else {
        return Ok(val);
    };

    let masked =
        writer.insert_op_with_result(dialect::felt::bit_and(writer.location, val, mask)?)?;
    writer.insert_op(dialect::constrain::eq(writer.location, val, masked));
    Ok(masked)
}
