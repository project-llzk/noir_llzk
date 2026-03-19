pub(crate) mod and;
pub(crate) mod rangecheck;
pub(crate) mod xor;

use std::collections::BTreeSet;

use crate::{block_writer::BlockWriter, error::Error};
use acir::{FieldElement, circuit::opcodes::FunctionInput};
use llzk::prelude::Value;

/// Emits the LLZK value for an ACIR [`FunctionInput`]: either a witness read
/// or a felt constant.
pub(crate) fn emit_blackbox_input<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    input: &FunctionInput<FieldElement>,
) -> Result<Value<'c, 'b>, Error> {
    match input {
        FunctionInput::Witness(w) => writer.read_witness(w.0),
        FunctionInput::Constant(c) => writer.emit_constant(c),
    }
}

/// Collects witness indices from an ACIR [`FunctionInput`].
pub(crate) fn collect_input_witness(
    witnesses: &mut BTreeSet<u32>,
    input: &FunctionInput<FieldElement>,
) {
    if let FunctionInput::Witness(w) = input {
        witnesses.insert(w.0);
    }
}
