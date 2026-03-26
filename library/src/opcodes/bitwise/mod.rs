pub(crate) mod and;
pub(crate) mod rangecheck;
pub(crate) mod xor;

use std::collections::BTreeSet;

use crate::{block_writer::BlockWriter, error::Error};
use acir::{AcirField, FieldElement, circuit::opcodes::FunctionInput};
use llzk::prelude::Value;

/// Emits the LLZK value for an ACIR [`FunctionInput`]: either a witness read
/// or a felt constant.
fn emit_blackbox_input<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    input: &FunctionInput<FieldElement>,
) -> Result<Value<'c, 'b>, Error> {
    match input {
        FunctionInput::Witness(w) => writer.read_witness(w.0),
        FunctionInput::Constant(c) => writer.emit_constant(c),
    }
}

/// Collects witness indices from an ACIR [`FunctionInput`].
fn collect_input_witness(witnesses: &mut BTreeSet<u32>, input: &FunctionInput<FieldElement>) {
    if let FunctionInput::Witness(w) = input {
        witnesses.insert(w.0);
    }
}

/// Returns whether `input` needs a bit-width mask and constraint.
fn input_needs_mask(input: &FunctionInput<FieldElement>, num_bits: u32) -> Result<bool, Error> {
    match input {
        FunctionInput::Witness(_) => Ok(true),
        FunctionInput::Constant(c) if c.num_bits() <= num_bits => Ok(false),
        FunctionInput::Constant(c) => Err(Error::ConstantOutOfRange {
            value: *c,
            num_bits,
        }),
    }
}

/// Emits a felt constant equal to `(1 << num_bits) - 1`, i.e. a bitmask
/// selecting the lowest `num_bits` bits.
fn emit_bit_mask<'c, 'b>(
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

    let mask = emit_bit_mask(writer, num_bits)?;
    let masked = writer.insert_bit_and(value, mask)?;
    writer.insert_constrain_eq(value, masked);
    Ok(())
}
