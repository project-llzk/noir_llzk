use std::collections::BTreeSet;

use acir::{
    FieldElement,
    circuit::Opcode,
    circuit::opcodes::{BlackBoxFuncCall, FunctionInput},
    native_types::Witness,
};

use crate::{
    blackboxes::{cipher::aes128::AES_BLOCK_SIZE, registry::BlackboxFunction},
    block_writer::BlockWriter,
    error::Error,
    opcodes::{
        OpcodeEmitter, collect_io_witnesses_iter, constrain_digest_outputs, emit_blackbox_input,
        validate_byte_input, write_digest_outputs,
    },
    writer::Writer,
};

pub(crate) struct Aes128Encrypt<'a> {
    inputs: &'a [FunctionInput<FieldElement>],
    iv: &'a [FunctionInput<FieldElement>; 16],
    key: &'a [FunctionInput<FieldElement>; 16],
    outputs: &'a [Witness],
}

impl OpcodeEmitter for Aes128Encrypt<'_> {
    fn get_witnesses(&self) -> BTreeSet<u32> {
        collect_io_witnesses_iter(
            self.inputs
                .iter()
                .chain(self.iv.iter())
                .chain(self.key.iter()),
            self.outputs,
        )
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

impl Aes128Encrypt<'_> {
    fn call_helper<'c, 'b>(
        &self,
        writer: &mut BlockWriter<'c, 'b>,
    ) -> Result<llzk::prelude::OperationRef<'c, 'b>, Error> {
        let args = self
            .inputs
            .iter()
            .chain(self.iv.iter())
            .chain(self.key.iter())
            .map(|input| emit_blackbox_input(writer, input))
            .collect::<Result<Vec<_>, _>>()?;
        writer.call_blackbox_function(
            BlackboxFunction::Aes128Encrypt {
                num_inputs: self.inputs.len(),
            },
            &args,
        )
    }
}

pub(crate) fn from_opcode<'a>(
    opcode: &'a Opcode<FieldElement>,
) -> Result<Option<Aes128Encrypt<'a>>, Error> {
    match opcode {
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::AES128Encrypt {
            inputs,
            iv,
            key,
            outputs,
        }) => {
            if inputs.len() % AES_BLOCK_SIZE != 0 {
                return Err(Error::UnsupportedOpcode(format!(
                    "AES128Encrypt input length {} is not a multiple of {AES_BLOCK_SIZE}",
                    inputs.len(),
                )));
            }
            if outputs.len() != inputs.len() {
                return Err(Error::UnsupportedOpcode(format!(
                    "AES128Encrypt output length {} doesn't match input length {}",
                    outputs.len(),
                    inputs.len(),
                )));
            }
            for input in inputs.iter().chain(iv.iter()).chain(key.iter()) {
                validate_byte_input(input)?;
            }
            Ok(Some(Aes128Encrypt {
                inputs,
                iv,
                key,
                outputs,
            }))
        }
        _ => Ok(None),
    }
}
