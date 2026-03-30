use std::collections::BTreeSet;

use acir::{
    AcirField, FieldElement,
    circuit::Opcode,
    circuit::opcodes::{BlackBoxFuncCall, FunctionInput},
    native_types::Witness,
};

use crate::{
    blackboxes::{hash::blake2s::BLAKE2S_DIGEST_BYTES, registry::BlackboxFunction},
    block_writer::BlockWriter,
    error::Error,
    opcodes::{OpcodeEmitter, collect_input_witness, emit_blackbox_input},
};

pub(crate) struct Blake2s<'a> {
    inputs: &'a [FunctionInput<FieldElement>],
    outputs: &'a [Witness; BLAKE2S_DIGEST_BYTES],
}

impl OpcodeEmitter for Blake2s<'_> {
    fn get_witnesses(&self) -> BTreeSet<u32> {
        let mut witnesses = BTreeSet::new();
        for output in self.outputs {
            witnesses.insert(output.0);
        }
        for input in self.inputs {
            collect_input_witness(&mut witnesses, input);
        }
        witnesses
    }

    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let result = self.call_helper(writer)?;
        for (index, output) in self.outputs.iter().enumerate() {
            let value = result.result(index)?.into();
            writer.write_member(&format!("w{}", output.0), value)?;
            writer.mark_known(output.0, value);
        }
        Ok(())
    }

    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let result = self.call_helper(writer)?;
        for (index, output) in self.outputs.iter().enumerate() {
            let expected = result.result(index)?.into();
            let actual = writer.read_witness(output.0)?;
            writer.insert_constrain_eq(actual, expected);
        }
        Ok(())
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

fn validate_byte_input(input: &FunctionInput<FieldElement>) -> Result<(), Error> {
    match input {
        FunctionInput::Constant(value) if value.num_bits() > 8 => Err(Error::ConstantOutOfRange {
            value: *value,
            num_bits: 8,
        }),
        _ => Ok(()),
    }
}
