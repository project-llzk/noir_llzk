use std::collections::BTreeSet;

use acir::{
    FieldElement,
    circuit::Opcode,
    circuit::opcodes::{BlackBoxFuncCall, FunctionInput},
    native_types::Witness,
};

use super::{collect_input_witness, emit_blackbox_input};
use crate::{block_writer::BlockWriter, error::Error, opcodes::OpcodeEmitter};

pub(crate) struct Xor<'a> {
    pub(crate) lhs: &'a FunctionInput<FieldElement>,
    pub(crate) rhs: &'a FunctionInput<FieldElement>,
    pub(crate) output: Witness,
}

impl OpcodeEmitter for Xor<'_> {
    fn get_witnesses(&self) -> BTreeSet<u32> {
        let mut witnesses = BTreeSet::from([self.output.0]);
        collect_input_witness(&mut witnesses, self.lhs);
        collect_input_witness(&mut witnesses, self.rhs);
        witnesses
    }

    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let lhs = emit_blackbox_input(writer, self.lhs)?;
        let rhs = emit_blackbox_input(writer, self.rhs)?;

        let result = writer.insert_bit_xor(lhs, rhs)?;

        writer.write_member(&format!("w{}", self.output.0), result)?;
        writer.mark_known(self.output.0, result);
        Ok(())
    }

    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let output = writer.read_witness(self.output.0)?;
        let lhs = emit_blackbox_input(writer, self.lhs)?;
        let rhs = emit_blackbox_input(writer, self.rhs)?;

        let xor_result = writer.insert_bit_xor(lhs, rhs)?;
        writer.insert_constrain_eq(output, xor_result);
        Ok(())
    }
}

pub(crate) fn from_opcode<'a>(opcode: &'a Opcode<FieldElement>) -> Option<Xor<'a>> {
    match opcode {
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::XOR {
            lhs,
            rhs,
            num_bits: _,
            output,
        }) => Some(Xor {
            lhs,
            rhs,
            output: *output,
        }),
        _ => None,
    }
}
