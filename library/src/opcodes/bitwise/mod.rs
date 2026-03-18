pub(crate) mod and;
pub(crate) mod rangecheck;
pub(crate) mod xor;

use std::collections::BTreeSet;

use acir::{AcirField, FieldElement, circuit::opcodes::FunctionInput};
use llzk::{
    dialect::felt::FeltConstAttribute,
    prelude::{Value, dialect},
};
use num_bigint::BigUint;

use crate::{FIELD_NAME, block_writer::BlockWriter, common::field_to_felt_const, error::Error};

/// Emits the LLZK value for an ACIR [`FunctionInput`]: either a witness read
/// or a felt constant.
pub(crate) fn emit_blackbox_input<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    input: &FunctionInput<FieldElement>,
) -> Result<Value<'c, 'b>, Error> {
    match input {
        FunctionInput::Witness(w) => writer.read_witness(w.0),
        FunctionInput::Constant(c) => {
            let attr = field_to_felt_const(writer.context, c);
            writer.insert_op_with_result(dialect::felt::constant(writer.location, attr)?)
        }
    }
}

/// Emits a felt constant equal to `(1 << num_bits) - 1`, i.e. a bitmask
/// selecting the lowest `num_bits` bits.
pub(crate) fn emit_bit_mask<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    num_bits: u32,
) -> Result<Value<'c, 'b>, Error> {
    let mask = if num_bits == 0 {
        BigUint::from(0u8)
    } else {
        (BigUint::from(1u8) << num_bits) - BigUint::from(1u8)
    };
    let attr = FeltConstAttribute::from_biguint(writer.context, &mask, Some(FIELD_NAME));
    writer.insert_op_with_result(dialect::felt::constant(writer.location, attr)?)
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

/// Returns true if the field element fits within `num_bits` bits.
pub(crate) fn constant_fits_in_bits(fe: &FieldElement, num_bits: u32) -> bool {
    if num_bits == 0 {
        return fe.is_zero();
    }
    let bytes = fe.to_le_bytes();
    let val = BigUint::from_bytes_le(&bytes);
    val.bits() <= num_bits as u64
}

/// Returns true if `input` needs a bit-width mask and constraint.
///
/// Constants that already fit in `num_bits` are known at compile time;
/// masking and constraining them would be dead code.
pub(crate) fn input_needs_mask(input: &FunctionInput<FieldElement>, num_bits: u32) -> bool {
    if let FunctionInput::Constant(c) = input {
        !constant_fits_in_bits(c, num_bits)
    } else {
        true
    }
}

/// Emits a constrained input for the constrain phase of a bitwise blackbox.
///
/// For witness inputs: emits `masked = input & mask`, constrains
/// `input == masked`, and returns `masked`.
///
/// For constant inputs that already fit in `num_bits`: emits just the
/// constant value — no mask or constraint needed.
pub(crate) fn emit_constrained_input<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    input: &FunctionInput<FieldElement>,
    num_bits: u32,
    mask: Option<Value<'c, 'b>>,
) -> Result<Value<'c, 'b>, Error> {
    let val = emit_blackbox_input(writer, input)?;

    if let Some(mask) = mask.filter(|_| input_needs_mask(input, num_bits)) {
        let masked =
            writer.insert_op_with_result(dialect::felt::bit_and(writer.location, val, mask)?)?;
        writer.insert_op(dialect::constrain::eq(writer.location, val, masked));
        Ok(masked)
    } else {
        Ok(val)
    }
}
