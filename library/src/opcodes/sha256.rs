use std::collections::BTreeSet;

use acir::{
    AcirField, FieldElement,
    circuit::Opcode,
    circuit::opcodes::{BlackBoxFuncCall, FunctionInput},
    native_types::Witness,
};

use crate::{
    blackboxes::{hash::sha256::SHA256_STATE_WORDS, registry::BlackboxFunction},
    block_writer::BlockWriter,
    error::Error,
    opcodes::{OpcodeEmitter, collect_input_witness, emit_blackbox_input},
};

pub(crate) struct Sha256Compression<'a> {
    inputs: &'a [FunctionInput<FieldElement>; 16],
    hash_values: &'a [FunctionInput<FieldElement>; 8],
    outputs: &'a [Witness; SHA256_STATE_WORDS],
}

impl OpcodeEmitter for Sha256Compression<'_> {
    fn get_witnesses(&self) -> BTreeSet<u32> {
        let mut witnesses = BTreeSet::new();
        for output in self.outputs {
            witnesses.insert(output.0);
        }
        for input in self.inputs.iter().chain(self.hash_values.iter()) {
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

/// Validates that constant inputs fit in a u32. Witness inputs are trusted to
/// be u32-ranged by prior constraints in Noir-generated ACIR. If this trust
/// boundary changes, add `bool.cmp lt(val, 2^32)` + `bool.assert` for witness
/// inputs in `emit_constrain`.
fn validate_u32_input(input: &FunctionInput<FieldElement>) -> Result<(), Error> {
    match input {
        FunctionInput::Constant(value) if value.num_bits() > 32 => Err(Error::ConstantOutOfRange {
            value: *value,
            num_bits: 32,
        }),
        _ => Ok(()),
    }
}
