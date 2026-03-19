use std::collections::BTreeSet;

use acir::{
    FieldElement,
    circuit::Opcode,
    circuit::opcodes::{BlackBoxFuncCall, FunctionInput},
};

use super::{collect_input_witness, emit_bit_mask, emit_constrained_input, input_needs_mask};
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

        let mask = Some(emit_bit_mask(writer, self.num_bits)?);
        let _ = emit_constrained_input(writer, self.input, self.num_bits, mask)?;
        Ok(())
    }
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
