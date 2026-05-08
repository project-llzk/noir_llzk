pub(crate) mod aes128;
pub(crate) mod assert_zero;
pub(crate) mod bitwise;
pub(crate) mod blake2s;
pub(crate) mod blake3;
pub(crate) mod brillig_call;
pub(crate) mod call;
pub(crate) mod ecdsa;
pub(crate) mod grumpkin;
pub(crate) mod keccak;
pub(crate) mod memory_ops;
pub(crate) mod poseidon2;
pub(crate) mod sha256;

use std::collections::BTreeSet;

use acir::{AcirField, FieldElement, circuit::opcodes::FunctionInput, native_types::Witness};
use llzk::prelude::{LlzkContext, OperationRef, StructDefOp, Value};

use crate::{block_writer::BlockWriter, error::Error};

/// Trait implemented by each ACIR opcode's translator.
///
/// Default no-op implementations are provided for phases that not all opcodes
/// participate in:
/// - [`emit_member`]: only `Call` adds a subcomponent struct member.
/// - [`emit_constrain`]: Brillig opcodes are unconstrained.
///
/// To add a new opcode: create a struct, implement this trait (only the
/// relevant methods), and add a match arm to the [`TryFrom`] impl below.
pub(crate) trait OpcodeEmitter {
    /// Returns all witness indices referenced by this opcode.
    fn get_witnesses(&self) -> BTreeSet<u32>;

    /// Emits any `struct.member` declaration required by this opcode.
    ///
    /// Default: no-op. Only `Call` needs to override this.
    fn emit_member<'c>(
        &self,
        _context: &'c LlzkContext,
        _struct_def: &StructDefOp<'c>,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Emits witness-solving operations into the `@compute` function body.
    ///
    /// Default: no-op.
    fn emit_compute<'c, 'b>(&self, _writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        Ok(())
    }

    /// Emits constraint assertions into the `@constrain` function body.
    ///
    /// Default: no-op. Brillig opcodes do not emit constraints.
    fn emit_constrain<'c, 'b>(&self, _writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        Ok(())
    }
}

/// Trait object so the three emission loops in `circuit.rs` stay uniform without matching on an enum.
pub(crate) type TranslatedOpcode<'a> = Box<dyn OpcodeEmitter + 'a>;

// ── Shared helpers for blackbox opcodes ────────────────────────────────

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

pub(crate) fn validate_constant_fits(
    input: &FunctionInput<FieldElement>,
    num_bits: u32,
) -> Result<(), Error> {
    match input {
        FunctionInput::Constant(value) if value.num_bits() > num_bits => {
            Err(Error::ConstantOutOfRange {
                value: *value,
                num_bits,
            })
        }
        _ => Ok(()),
    }
}

pub(crate) fn validate_byte_input(input: &FunctionInput<FieldElement>) -> Result<(), Error> {
    validate_constant_fits(input, 8)
}

pub(crate) fn validate_u32_input(input: &FunctionInput<FieldElement>) -> Result<(), Error> {
    validate_constant_fits(input, 32)
}

pub(crate) fn validate_u64_input(input: &FunctionInput<FieldElement>) -> Result<(), Error> {
    validate_constant_fits(input, 64)
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

pub(crate) fn collect_io_witnesses(
    inputs: &[FunctionInput<FieldElement>],
    outputs: &[Witness],
) -> BTreeSet<u32> {
    collect_io_witnesses_iter(inputs.iter(), outputs)
}

pub(crate) fn collect_io_witnesses_iter<'a>(
    inputs: impl IntoIterator<Item = &'a FunctionInput<FieldElement>>,
    outputs: &[Witness],
) -> BTreeSet<u32> {
    let mut witnesses = BTreeSet::new();
    for output in outputs {
        witnesses.insert(output.0);
    }
    for input in inputs {
        collect_input_witness(&mut witnesses, input);
    }
    witnesses
}

pub(crate) fn write_digest_outputs<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    outputs: &[Witness],
    result: OperationRef<'c, 'b>,
) -> Result<(), Error> {
    for (index, output) in outputs.iter().enumerate() {
        let value = result.result(index)?.into();
        writer.write_member(&format!("w{}", output.0), value)?;
        writer.mark_known(output.0, value);
    }
    Ok(())
}

pub(crate) fn constrain_digest_outputs<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    outputs: &[Witness],
    result: OperationRef<'c, 'b>,
) -> Result<(), Error> {
    for (index, output) in outputs.iter().enumerate() {
        let expected = result.result(index)?.into();
        let actual = writer.read_witness(output.0)?;
        writer.insert_constrain_eq(actual, expected);
    }
    Ok(())
}

pub(crate) fn emit_padded_byte_inputs<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    inputs: &[FunctionInput<FieldElement>],
    capacity: usize,
) -> Result<Vec<Value<'c, 'b>>, Error> {
    let mut values = inputs
        .iter()
        .map(|input| emit_blackbox_input(writer, input))
        .collect::<Result<Vec<_>, _>>()?;
    let zero = writer.emit_constant(&FieldElement::zero())?;
    values.resize(capacity, zero);
    Ok(values)
}
