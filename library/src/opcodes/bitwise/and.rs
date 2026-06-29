use std::collections::BTreeSet;

use acir::{
    FieldElement,
    circuit::Opcode,
    circuit::opcodes::{BlackBoxFuncCall, FunctionInput},
    native_types::Witness,
};

use crate::{
    block_writer::BlockWriter,
    error::Error,
    opcodes::{OpcodeEmitter, collect_input_witness, constrain_input_width, emit_blackbox_input},
    writer::Writer,
};

pub(crate) struct And<'a> {
    lhs: &'a FunctionInput<FieldElement>,
    rhs: &'a FunctionInput<FieldElement>,
    num_bits: u32,
    output: Witness,
}

impl OpcodeEmitter for And<'_> {
    fn get_witnesses(&self) -> BTreeSet<u32> {
        let mut witnesses = BTreeSet::from([self.output.0]);
        collect_input_witness(&mut witnesses, self.lhs);
        collect_input_witness(&mut witnesses, self.rhs);
        witnesses
    }

    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let lhs = emit_blackbox_input(writer, self.lhs)?;
        let rhs = emit_blackbox_input(writer, self.rhs)?;

        let result = writer.insert_felt_bit_and(lhs, rhs)?;

        writer.write_member(&format!("w{}", self.output.0), result)?;
        writer.mark_known(self.output.0, result);
        Ok(())
    }

    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let output = writer.read_witness(self.output.0)?;
        let lhs = emit_blackbox_input(writer, self.lhs)?;
        let rhs = emit_blackbox_input(writer, self.rhs)?;

        constrain_input_width(writer, self.lhs, lhs, self.num_bits)?;
        constrain_input_width(writer, self.rhs, rhs, self.num_bits)?;

        let and_result = writer.insert_felt_bit_and(lhs, rhs)?;
        writer.insert_constrain_eq(output, and_result);
        Ok(())
    }
}

pub(crate) fn from_opcode<'a>(opcode: &'a Opcode<FieldElement>) -> Option<And<'a>> {
    match opcode {
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::AND {
            lhs,
            rhs,
            num_bits,
            output,
        }) => Some(And {
            lhs,
            rhs,
            num_bits: *num_bits,
            output: *output,
        }),
        _ => None,
    }
}
