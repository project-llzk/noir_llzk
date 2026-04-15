use std::collections::BTreeSet;

use acir::{
    FieldElement,
    circuit::Opcode,
    circuit::opcodes::{BlackBoxFuncCall, FunctionInput},
    native_types::Witness,
};

use llzk::prelude::Value;

use crate::{
    blackboxes::{hash::poseidon2::STATE_WIDTH, registry::BlackboxFunction},
    block_writer::BlockWriter,
    error::Error,
    opcodes::{OpcodeEmitter, collect_input_witness, emit_blackbox_input},
};

pub(crate) struct Poseidon2Permutation<'a> {
    inputs: &'a [FunctionInput<FieldElement>],
    outputs: &'a [Witness],
}

impl OpcodeEmitter for Poseidon2Permutation<'_> {
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

impl<'a> Poseidon2Permutation<'a> {
    fn call_helper<'c, 'b>(
        &self,
        writer: &mut BlockWriter<'c, 'b>,
    ) -> Result<llzk::prelude::OperationRef<'c, 'b>, Error> {
        let inputs = read_inputs(writer, self.inputs)?;
        writer.call_blackbox_function(BlackboxFunction::Poseidon2Permutation, &inputs)
    }
}

pub(crate) fn from_opcode<'a>(
    opcode: &'a Opcode<FieldElement>,
) -> Result<Option<Poseidon2Permutation<'a>>, Error> {
    match opcode {
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Poseidon2Permutation { inputs, outputs }) => {
            if inputs.len() != STATE_WIDTH || outputs.len() != STATE_WIDTH {
                return Err(Error::UnsupportedOpcode(format!(
                    "Poseidon2Permutation requires exactly {STATE_WIDTH} inputs and outputs, got {} and {}",
                    inputs.len(),
                    outputs.len(),
                )));
            }
            Ok(Some(Poseidon2Permutation { inputs, outputs }))
        }
        _ => Ok(None),
    }
}

fn read_inputs<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    inputs: &[FunctionInput<FieldElement>],
) -> Result<[Value<'c, 'b>; STATE_WIDTH], Error> {
    Ok([
        emit_blackbox_input(writer, &inputs[0])?,
        emit_blackbox_input(writer, &inputs[1])?,
        emit_blackbox_input(writer, &inputs[2])?,
        emit_blackbox_input(writer, &inputs[3])?,
    ])
}
