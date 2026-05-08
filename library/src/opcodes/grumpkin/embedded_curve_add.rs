use std::collections::BTreeSet;

use acir::{
    AcirField, FieldElement,
    circuit::Opcode,
    circuit::opcodes::{BlackBoxFuncCall, FunctionInput},
    native_types::Witness,
};

use crate::{
    blackboxes::grumpkin::common::{emit_gated_on_curve, emit_predicate_gate},
    blackboxes::registry::BlackboxFunction,
    block_writer::BlockWriter,
    common::emit_gated_eq,
    error::Error,
    opcodes::{OpcodeEmitter, collect_input_witness, emit_blackbox_input},
    writer::Writer,
};

pub(crate) struct EmbeddedCurveAdd<'a> {
    input1: &'a [FunctionInput<FieldElement>; 3],
    input2: &'a [FunctionInput<FieldElement>; 3],
    predicate: &'a FunctionInput<FieldElement>,
    outputs: (Witness, Witness, Witness),
}

struct EmbeddedCurveAddInputs<'c, 'b> {
    input1_x: llzk::prelude::Value<'c, 'b>,
    input1_y: llzk::prelude::Value<'c, 'b>,
    input1_infinite: llzk::prelude::Value<'c, 'b>,
    input2_x: llzk::prelude::Value<'c, 'b>,
    input2_y: llzk::prelude::Value<'c, 'b>,
    input2_infinite: llzk::prelude::Value<'c, 'b>,
    predicate: llzk::prelude::Value<'c, 'b>,
}

impl OpcodeEmitter for EmbeddedCurveAdd<'_> {
    fn get_witnesses(&self) -> BTreeSet<u32> {
        let mut witnesses = BTreeSet::from([self.outputs.0.0, self.outputs.1.0, self.outputs.2.0]);

        for input in self.input1.iter().chain(self.input2.iter()) {
            collect_input_witness(&mut witnesses, input);
        }
        collect_input_witness(&mut witnesses, self.predicate);

        witnesses
    }

    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let inputs = self.read_inputs(writer)?;
        let helper_call = self.call_helper(writer, &inputs)?;
        let output_x = helper_call.result(0)?.into();
        let output_y = helper_call.result(1)?.into();
        let output_infinite = helper_call.result(2)?.into();

        writer.write_member(&format!("w{}", self.outputs.0.0), output_x)?;
        writer.write_member(&format!("w{}", self.outputs.1.0), output_y)?;
        writer.write_member(&format!("w{}", self.outputs.2.0), output_infinite)?;
        writer.mark_known(self.outputs.0.0, output_x);
        writer.mark_known(self.outputs.1.0, output_y);
        writer.mark_known(self.outputs.2.0, output_infinite);
        Ok(())
    }

    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let inputs = self.read_inputs(writer)?;
        let output_x = writer.read_witness(self.outputs.0.0)?;
        let output_y = writer.read_witness(self.outputs.1.0)?;
        let output_infinite = writer.read_witness(self.outputs.2.0)?;

        let zero = writer.emit_constant(&FieldElement::zero())?;
        let (_, predicate_is_true_felt) = emit_predicate_gate(writer, inputs.predicate)?;

        emit_gated_eq(writer, predicate_is_true_felt, inputs.input1_infinite, zero)?;
        emit_gated_eq(writer, predicate_is_true_felt, inputs.input2_infinite, zero)?;

        emit_gated_on_curve(
            writer,
            predicate_is_true_felt,
            inputs.input1_x,
            inputs.input1_y,
        )?;
        emit_gated_on_curve(
            writer,
            predicate_is_true_felt,
            inputs.input2_x,
            inputs.input2_y,
        )?;

        let helper_call = self.call_helper(writer, &inputs)?;
        let expected_x = helper_call.result(0)?.into();
        let expected_y = helper_call.result(1)?.into();
        let expected_infinite = helper_call.result(2)?.into();
        writer.insert_constrain_eq(output_x, expected_x);
        writer.insert_constrain_eq(output_y, expected_y);
        writer.insert_constrain_eq(output_infinite, expected_infinite);

        Ok(())
    }
}

pub(crate) fn from_opcode<'a>(opcode: &'a Opcode<FieldElement>) -> Option<EmbeddedCurveAdd<'a>> {
    match opcode {
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::EmbeddedCurveAdd {
            input1,
            input2,
            predicate,
            outputs,
        }) => Some(EmbeddedCurveAdd {
            input1,
            input2,
            predicate,
            outputs: *outputs,
        }),
        _ => None,
    }
}

impl EmbeddedCurveAdd<'_> {
    fn read_inputs<'c, 'b>(
        &self,
        writer: &mut BlockWriter<'c, 'b>,
    ) -> Result<EmbeddedCurveAddInputs<'c, 'b>, Error> {
        Ok(EmbeddedCurveAddInputs {
            input1_x: emit_blackbox_input(writer, &self.input1[0])?,
            input1_y: emit_blackbox_input(writer, &self.input1[1])?,
            input1_infinite: emit_blackbox_input(writer, &self.input1[2])?,
            input2_x: emit_blackbox_input(writer, &self.input2[0])?,
            input2_y: emit_blackbox_input(writer, &self.input2[1])?,
            input2_infinite: emit_blackbox_input(writer, &self.input2[2])?,
            predicate: emit_blackbox_input(writer, self.predicate)?,
        })
    }

    fn call_helper<'c, 'b>(
        &self,
        writer: &mut BlockWriter<'c, 'b>,
        inputs: &EmbeddedCurveAddInputs<'c, 'b>,
    ) -> Result<llzk::prelude::OperationRef<'c, 'b>, Error> {
        let args = [
            inputs.input1_x,
            inputs.input1_y,
            inputs.input1_infinite,
            inputs.input2_x,
            inputs.input2_y,
            inputs.input2_infinite,
            inputs.predicate,
        ];
        writer.call_blackbox_function(BlackboxFunction::EmbeddedCurveAdd, &args)
    }
}
