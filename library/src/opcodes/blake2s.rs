use std::collections::BTreeSet;

use acir::{
    FieldElement,
    circuit::Opcode,
    circuit::opcodes::{BlackBoxFuncCall, FunctionInput},
    native_types::Witness,
};

use crate::{
    blackboxes::{
        hash::blake2s::{BLAKE2S_DIGEST_BYTES, blake2s_num_blocks_for_len},
        registry::BlackboxFunction,
    },
    block_writer::BlockWriter,
    error::Error,
    opcodes::{
        OpcodeEmitter, collect_io_witnesses, constrain_digest_outputs, emit_padded_byte_inputs,
        validate_byte_input, write_digest_outputs,
    },
};

pub(crate) struct Blake2s<'a> {
    inputs: &'a [FunctionInput<FieldElement>],
    outputs: &'a [Witness; BLAKE2S_DIGEST_BYTES],
}

impl OpcodeEmitter for Blake2s<'_> {
    fn get_witnesses(&self) -> BTreeSet<u32> {
        collect_io_witnesses(self.inputs, self.outputs)
    }

    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let result = self.call_helper(writer)?;
        write_digest_outputs(writer, self.outputs, result)
    }

    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let result = self.call_helper(writer)?;
        constrain_digest_outputs(writer, self.outputs, result)
    }
}

impl Blake2s<'_> {
    fn call_helper<'c, 'b>(
        &self,
        writer: &mut BlockWriter<'c, 'b>,
    ) -> Result<llzk::prelude::OperationRef<'c, 'b>, Error> {
        let num_blocks = blake2s_num_blocks_for_len(self.inputs.len());
        let mut inputs = emit_padded_byte_inputs(writer, self.inputs, num_blocks * 64)?;
        let len = self.inputs.len() as u64;
        let real_length_lo =
            writer.emit_constant(&FieldElement::from((len & 0xFFFF_FFFF) as u128))?;
        let real_length_hi = writer.emit_constant(&FieldElement::from((len >> 32) as u128))?;
        inputs.push(real_length_lo);
        inputs.push(real_length_hi);
        writer.call_blackbox_function(BlackboxFunction::Blake2s { num_blocks }, &inputs)
    }
}

pub(crate) fn from_opcode<'a>(
    opcode: &'a Opcode<FieldElement>,
) -> Result<Option<Blake2s<'a>>, Error> {
    match opcode {
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Blake2s { inputs, outputs }) => {
            for input in inputs {
                validate_byte_input(input)?;
            }
            Ok(Some(Blake2s { inputs, outputs }))
        }
        _ => Ok(None),
    }
}
