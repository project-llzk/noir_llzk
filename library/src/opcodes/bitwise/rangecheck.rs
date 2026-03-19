use std::collections::BTreeSet;

use acir::{
    AcirField, FieldElement,
    circuit::Opcode,
    circuit::opcodes::{BlackBoxFuncCall, FunctionInput},
};

use super::{collect_input_witness, emit_blackbox_input};
use crate::{block_writer::BlockWriter, error::Error, opcodes::OpcodeEmitter};

pub(crate) struct Rangecheck<'a> {
    pub(crate) input: &'a FunctionInput<FieldElement>,
    pub(crate) num_bits: u32,
}

impl OpcodeEmitter for Rangecheck<'_> {
    fn get_witnesses(&self) -> BTreeSet<u32> {
        let mut witnesses = BTreeSet::new();
        collect_input_witness(&mut witnesses, self.input);
        witnesses
    }

    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        if !input_needs_mask(self.input, self.num_bits)? {
            return Ok(());
        }

        let val = emit_blackbox_input(writer, self.input)?;
        let mask = emit_bit_mask(writer, self.num_bits)?;
        let masked = writer.insert_bit_and(val, mask)?;
        writer.insert_constrain_eq(val, masked);
        Ok(())
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
) -> Result<llzk::prelude::Value<'c, 'b>, Error> {
    let mask = if num_bits == 0 {
        FieldElement::zero()
    } else {
        FieldElement::from(2u128).pow(&FieldElement::from(num_bits as u128)) - FieldElement::one()
    };
    writer.emit_constant(&mask)
}

pub(crate) fn from_opcode<'a>(opcode: &'a Opcode<FieldElement>) -> Option<Rangecheck<'a>> {
    match opcode {
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE { input, num_bits }) => Some(Rangecheck {
            input,
            num_bits: *num_bits,
        }),
        _ => None,
    }
}
