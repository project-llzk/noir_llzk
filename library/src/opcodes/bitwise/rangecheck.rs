use std::collections::BTreeSet;

use acir::{
    FieldElement,
    circuit::Opcode,
    circuit::opcodes::{BlackBoxFuncCall, FunctionInput},
};

use crate::{
    block_writer::BlockWriter,
    error::Error,
    opcodes::{
        OpcodeEmitter, collect_input_witness, constrain_input_width, emit_blackbox_input,
        input_needs_range_check,
    },
};

pub(crate) struct Rangecheck<'a> {
    input: &'a FunctionInput<FieldElement>,
    num_bits: u32,
}

impl OpcodeEmitter for Rangecheck<'_> {
    fn get_witnesses(&self) -> BTreeSet<u32> {
        let mut witnesses = BTreeSet::new();
        collect_input_witness(&mut witnesses, self.input);
        witnesses
    }

    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        if !input_needs_range_check(self.input, self.num_bits)? {
            return Ok(());
        }
        let val = emit_blackbox_input(writer, self.input)?;
        constrain_input_width(writer, self.input, val, self.num_bits)
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
