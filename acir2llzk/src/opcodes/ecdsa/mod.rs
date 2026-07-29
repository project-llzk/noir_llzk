//! ACIR `EcdsaSecp256{k1,r1}` opcode shims.

use std::collections::BTreeSet;

use acir::{
    FieldElement,
    circuit::Opcode,
    circuit::opcodes::{BlackBoxFuncCall, FunctionInput},
    native_types::Witness,
};

use crate::{
    blackboxes::{ecdsa::ECDSA_HELPER_INPUTS, registry::BlackboxFunction},
    block_writer::BlockWriter,
    common::constrain_bool,
    error::Error,
    opcodes::{
        OpcodeEmitter, collect_input_witness, constrain_inputs_width, emit_blackbox_input,
        validate_byte_input, validate_constant_fits,
    },
    writer::Writer,
};

pub(crate) struct Ecdsa<'a> {
    public_key_x: &'a [FunctionInput<FieldElement>; 32],
    public_key_y: &'a [FunctionInput<FieldElement>; 32],
    signature: &'a [FunctionInput<FieldElement>; 64],
    hashed_message: &'a [FunctionInput<FieldElement>; 32],
    predicate: &'a FunctionInput<FieldElement>,
    output: Witness,
    helper: BlackboxFunction,
}

impl<'a> Ecdsa<'a> {
    fn helper_args<'c, 'b>(
        &self,
        writer: &mut BlockWriter<'c, 'b>,
    ) -> Result<Vec<llzk::prelude::Value<'c, 'b>>, Error> {
        let mut args = Vec::with_capacity(ECDSA_HELPER_INPUTS);
        for input in self
            .public_key_x
            .iter()
            .chain(self.public_key_y.iter())
            .chain(self.signature.iter())
            .chain(self.hashed_message.iter())
            .chain(std::iter::once(self.predicate))
        {
            args.push(emit_blackbox_input(writer, input)?);
        }
        Ok(args)
    }
}

impl OpcodeEmitter for Ecdsa<'_> {
    fn get_witnesses(&self) -> BTreeSet<u32> {
        let mut witnesses = BTreeSet::from([self.output.0]);
        for input in self
            .public_key_x
            .iter()
            .chain(self.public_key_y.iter())
            .chain(self.signature.iter())
            .chain(self.hashed_message.iter())
            .chain(std::iter::once(self.predicate))
        {
            collect_input_witness(&mut witnesses, input);
        }
        witnesses
    }

    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let args = self.helper_args(writer)?;
        let call = writer.call_blackbox_function(self.helper, &args)?;
        let is_valid = call.result(0)?.into();
        writer.write_member(&format!("w{}", self.output.0), is_valid)?;
        writer.mark_known(self.output.0, is_valid);
        Ok(())
    }

    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let all_inputs = self
            .public_key_x
            .iter()
            .chain(self.public_key_y.iter())
            .chain(self.signature.iter())
            .chain(self.hashed_message.iter());
        constrain_inputs_width(writer, all_inputs, 8)?;
        let predicate_val = emit_blackbox_input(writer, self.predicate)?;
        constrain_bool(writer, predicate_val)?;
        let args = self.helper_args(writer)?;
        let call = writer.call_blackbox_function(self.helper, &args)?;
        let expected = call.result(0)?.into();
        let actual = writer.read_witness(self.output.0)?;
        writer.insert_constrain_eq(actual, expected);
        Ok(())
    }
}

pub(crate) fn from_opcode<'a>(
    opcode: &'a Opcode<FieldElement>,
) -> Result<Option<Ecdsa<'a>>, Error> {
    let (helper, public_key_x, public_key_y, signature, hashed_message, predicate, output) =
        match opcode {
            Opcode::BlackBoxFuncCall(BlackBoxFuncCall::EcdsaSecp256k1 {
                public_key_x,
                public_key_y,
                signature,
                hashed_message,
                predicate,
                output,
            }) => (
                BlackboxFunction::EcdsaSecp256k1Compute,
                public_key_x,
                public_key_y,
                signature,
                hashed_message,
                predicate,
                output,
            ),
            Opcode::BlackBoxFuncCall(BlackBoxFuncCall::EcdsaSecp256r1 {
                public_key_x,
                public_key_y,
                signature,
                hashed_message,
                predicate,
                output,
            }) => (
                BlackboxFunction::EcdsaSecp256r1Compute,
                public_key_x,
                public_key_y,
                signature,
                hashed_message,
                predicate,
                output,
            ),
            _ => return Ok(None),
        };

    // Reject oversized byte constants at parse time.
    for input in public_key_x
        .iter()
        .chain(public_key_y.iter())
        .chain(signature.iter())
        .chain(hashed_message.iter())
    {
        validate_byte_input(input)?;
    }
    validate_constant_fits(predicate, 1)?;
    Ok(Some(Ecdsa {
        public_key_x,
        public_key_y,
        signature,
        hashed_message,
        predicate,
        output: *output,
        helper,
    }))
}
