pub(crate) mod and;
pub(crate) mod rangecheck;
pub(crate) mod xor;

use crate::writer::Writer;
use crate::{block_writer::BlockWriter, error::Error};
use acir::{AcirField, FieldElement, circuit::opcodes::FunctionInput};
use llzk::prelude::Value;

pub(crate) use super::{collect_input_witness, emit_blackbox_input};

/// Returns whether `input` needs a bit-width mask and constraint.
fn input_needs_mask(input: &FunctionInput<FieldElement>, num_bits: u32) -> Result<bool, Error> {
    match input {
        FunctionInput::Witness(_) => Ok(num_bits < FieldElement::max_num_bits()),
        FunctionInput::Constant(c) if c.num_bits() <= num_bits => Ok(false),
        FunctionInput::Constant(c) => Err(Error::ConstantOutOfRange {
            value: *c,
            num_bits,
        }),
    }
}

/// Emits a felt constant equal to `2^num_bits`, used as the exclusive upper
/// bound for an unsigned `<` range check.
fn emit_range_upper_bound<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    num_bits: u32,
) -> Result<Value<'c, 'b>, Error> {
    let bound = FieldElement::from(2u128).pow(&FieldElement::from(num_bits as u128));
    writer.emit_constant(&bound)
}

/// Constrains `value` to fit within `num_bits` when the ACIR input requires it.
fn constrain_input_width<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    input: &FunctionInput<FieldElement>,
    value: Value<'c, 'b>,
    num_bits: u32,
) -> Result<(), Error> {
    if !input_needs_mask(input, num_bits)? {
        return Ok(());
    }

    let bound = emit_range_upper_bound(writer, num_bits)?;
    let in_range = writer.insert_bool_lt(value, bound)?;
    writer.insert_constrain_bool_true(in_range)
}
