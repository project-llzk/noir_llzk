use std::collections::BTreeSet;

use acir::{
    FieldElement,
    circuit::Opcode,
    circuit::opcodes::{BlackBoxFuncCall, FunctionInput},
    native_types::Witness,
};
use llzk::prelude::dialect;

use super::{collect_input_witness, emit_bit_mask, emit_blackbox_input};
use crate::{block_writer::BlockWriter, error::Error, opcodes::OpcodeEmitter};

pub(crate) struct Xor<'a> {
    pub(crate) lhs: &'a FunctionInput<FieldElement>,
    pub(crate) rhs: &'a FunctionInput<FieldElement>,
    pub(crate) num_bits: u32,
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
        let mask = emit_bit_mask(writer, self.num_bits)?;

        // Unlike AND, (lhs ^ mask) ^ (rhs ^ mask) != (lhs ^ rhs) ^ mask in general,
        // so compute raw XOR then mask the result.
        let raw_xor =
            writer.insert_op_with_result(dialect::felt::bit_xor(writer.location, lhs, rhs)?)?;
        let result = writer.insert_op_with_result(dialect::felt::bit_and(
            writer.location,
            raw_xor,
            mask,
        )?)?;

        writer.write_member(&format!("w{}", self.output.0), result)?;
        writer.mark_known(self.output.0, result);
        Ok(())
    }

    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let output = writer.read_witness(self.output.0)?;
        let lhs = emit_blackbox_input(writer, self.lhs)?;
        let rhs = emit_blackbox_input(writer, self.rhs)?;

        let xor_result =
            writer.insert_op_with_result(dialect::felt::bit_xor(writer.location, lhs, rhs)?)?;
        writer.insert_op(dialect::constrain::eq(writer.location, output, xor_result));
        Ok(())
    }
}

pub(crate) fn from_opcode<'a>(opcode: &'a Opcode<FieldElement>) -> Option<Xor<'a>> {
    match opcode {
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::XOR {
            lhs,
            rhs,
            num_bits,
            output,
        }) => Some(Xor {
            lhs,
            rhs,
            num_bits: *num_bits,
            output: *output,
        }),
        _ => None,
    }
}
