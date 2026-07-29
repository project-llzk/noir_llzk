use std::collections::BTreeSet;

use acir::{
    FieldElement,
    circuit::Opcode,
    circuit::opcodes::{BlackBoxFuncCall, FunctionInput},
    native_types::Witness,
};

use crate::{
    blackboxes::{hash::sha256::SHA256_STATE_WORDS, registry::BlackboxFunction},
    block_writer::BlockWriter,
    error::Error,
    opcodes::{
        OpcodeEmitter, collect_io_witnesses_iter, constrain_digest_outputs, constrain_inputs_width,
        emit_blackbox_input, validate_u32_input, write_digest_outputs,
    },
    writer::Writer,
};

pub(crate) struct Sha256Compression<'a> {
    inputs: &'a [FunctionInput<FieldElement>; 16],
    hash_values: &'a [FunctionInput<FieldElement>; 8],
    outputs: &'a [Witness; SHA256_STATE_WORDS],
}

impl OpcodeEmitter for Sha256Compression<'_> {
    fn get_witnesses(&self) -> BTreeSet<u32> {
        collect_io_witnesses_iter(
            self.inputs.iter().chain(self.hash_values.iter()),
            self.outputs,
        )
    }

    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let result = self.call_helper(writer)?;
        write_digest_outputs(writer, self.outputs, result)
    }

    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        constrain_inputs_width(
            writer,
            self.inputs.iter().chain(self.hash_values.iter()),
            32,
        )?;
        let result = self.call_helper(writer)?;
        constrain_digest_outputs(writer, self.outputs, result)
    }
}

impl Sha256Compression<'_> {
    fn call_helper<'c, 'b>(
        &self,
        writer: &mut BlockWriter<'c, 'b>,
    ) -> Result<llzk::prelude::OperationRef<'c, 'b>, Error> {
        let args = self
            .inputs
            .iter()
            .chain(self.hash_values.iter())
            .map(|input| emit_blackbox_input(writer, input))
            .collect::<Result<Vec<_>, _>>()?;
        writer.call_blackbox_function(BlackboxFunction::Sha256Compression, &args)
    }
}

pub(crate) fn from_opcode<'a>(
    opcode: &'a Opcode<FieldElement>,
) -> Result<Option<Sha256Compression<'a>>, Error> {
    match opcode {
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Sha256Compression {
            inputs,
            hash_values,
            outputs,
        }) => {
            for input in inputs.iter().chain(hash_values.iter()) {
                validate_u32_input(input)?;
            }
            Ok(Some(Sha256Compression {
                inputs,
                hash_values,
                outputs,
            }))
        }
        _ => Ok(None),
    }
}
