use std::collections::BTreeSet;

use acir::{
    FieldElement,
    circuit::Opcode,
    circuit::opcodes::{BlackBoxFuncCall, FunctionInput},
    native_types::Witness,
};

use crate::{
    blackboxes::{hash::blake2s::BLAKE2S_DIGEST_BYTES, registry::BlackboxFunction},
    block_writer::BlockWriter,
    error::Error,
    opcodes::{
        OpcodeEmitter, collect_io_witnesses, constrain_digest_outputs, emit_blackbox_input,
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
        let inputs = self
            .inputs
            .iter()
            .map(|input| emit_blackbox_input(writer, input))
            .collect::<Result<Vec<_>, _>>()?;
        writer.call_blackbox_function(
            BlackboxFunction::Blake2s {
                num_inputs: self.inputs.len(),
            },
            &inputs,
        )
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
