use std::collections::BTreeSet;

use acir::{
    circuit::opcodes::{BlackBoxFuncCall, FunctionInput},
    circuit::Opcode,
    native_types::Witness,
    FieldElement,
};

use crate::{
    blackboxes::{hash::keccak::KECCAK_STATE_WORDS, registry::BlackboxFunction},
    block_writer::BlockWriter,
    error::Error,
    opcodes::{
        collect_io_witnesses_iter, constrain_digest_outputs, constrain_inputs_width,
        validate_u64_input, write_digest_outputs, OpcodeEmitter,
    },
    writer::Writer,
};

pub(crate) struct Keccakf1600<'a> {
    inputs: &'a [FunctionInput<FieldElement>; KECCAK_STATE_WORDS],
    outputs: &'a [Witness; KECCAK_STATE_WORDS],
}

impl OpcodeEmitter for Keccakf1600<'_> {
    fn get_witnesses(&self) -> BTreeSet<u32> {
        collect_io_witnesses_iter(self.inputs.iter(), self.outputs)
    }

    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let result = self.call_helper(writer)?;
        write_digest_outputs(writer, self.outputs, result)
    }

    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        constrain_inputs_width(writer, self.inputs.iter(), 64)?;
        let result = self.call_helper(writer)?;
        constrain_digest_outputs(writer, self.outputs, result)
    }
}

impl Keccakf1600<'_> {
    fn call_helper<'c, 'b>(
        &self,
        writer: &mut BlockWriter<'c, 'b>,
    ) -> Result<llzk::prelude::OperationRef<'c, 'b>, Error> {
        let args = self
            .inputs
            .iter()
            .map(|input| writer.emit_blackbox_input(input))
            .collect::<Result<Vec<_>, _>>()?;
        writer.call_blackbox_function(BlackboxFunction::Keccakf1600, &args)
    }
}

pub(crate) fn from_opcode<'a>(
    opcode: &'a Opcode<FieldElement>,
) -> Result<Option<Keccakf1600<'a>>, Error> {
    match opcode {
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Keccakf1600 { inputs, outputs }) => {
            for input in inputs.iter() {
                validate_u64_input(input)?;
            }
            Ok(Some(Keccakf1600 { inputs, outputs }))
        }
        _ => Ok(None),
    }
}
