use std::collections::BTreeSet;

use acir::{
    FieldElement,
    circuit::Opcode,
    circuit::opcodes::{BlackBoxFuncCall, FunctionInput},
    native_types::Witness,
};

use crate::{
    blackboxes::{
        hash::blake3::{BLAKE3_DIGEST_BYTES, blake3_num_blocks_for_len},
        registry::BlackboxFunction,
    },
    block_writer::BlockWriter,
    error::Error,
    opcodes::{
        OpcodeEmitter, collect_io_witnesses, constrain_digest_outputs, constrain_inputs_width,
        emit_padded_byte_inputs, validate_byte_input, write_digest_outputs,
    },
    writer::Writer,
};

pub(crate) struct Blake3<'a> {
    inputs: &'a [FunctionInput<FieldElement>],
    outputs: &'a [Witness; BLAKE3_DIGEST_BYTES],
}

impl OpcodeEmitter for Blake3<'_> {
    fn get_witnesses(&self) -> BTreeSet<u32> {
        collect_io_witnesses(self.inputs, self.outputs)
    }

    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let result = self.call_helper(writer)?;
        write_digest_outputs(writer, self.outputs, result)
    }

    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        constrain_inputs_width(writer, self.inputs, 8)?;
        let result = self.call_helper(writer)?;
        constrain_digest_outputs(writer, self.outputs, result)
    }
}

impl Blake3<'_> {
    fn call_helper<'c, 'b>(
        &self,
        writer: &mut BlockWriter<'c, 'b>,
    ) -> Result<llzk::prelude::OperationRef<'c, 'b>, Error> {
        let num_blocks = blake3_num_blocks_for_len(self.inputs.len());
        let mut inputs = emit_padded_byte_inputs(writer, self.inputs, num_blocks * 64)?;
        let final_block_len = self.inputs.len() - (num_blocks - 1) * 64;
        let final_block_len = writer.emit_constant(&FieldElement::from(final_block_len as u128))?;
        inputs.push(final_block_len);
        writer.call_blackbox_function(BlackboxFunction::Blake3 { num_blocks }, &inputs)
    }
}

pub(crate) fn from_opcode<'a>(
    opcode: &'a Opcode<FieldElement>,
) -> Result<Option<Blake3<'a>>, Error> {
    match opcode {
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Blake3 { inputs, outputs }) => {
            for input in inputs {
                validate_byte_input(input)?;
            }
            Ok(Some(Blake3 { inputs, outputs }))
        }
        _ => Ok(None),
    }
}
