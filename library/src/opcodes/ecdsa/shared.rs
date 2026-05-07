//! Shared helpers for the secp256k1 and secp256r1 ECDSA wrappers.

use acir::{AcirField, FieldElement, circuit::opcodes::FunctionInput};
use llzk::prelude::{
    Block, BlockLike, FuncDefOp, FuncDefOpLike, FunctionType, Location, OperationLike, RegionLike,
    Type, dialect,
};

use crate::{
    FIELD_NAME,
    block_writer::BlockWriter,
    error::Error,
    multiprec::{LIMBS, Limbs256, try_init_limbs},
    opcodes::emit_blackbox_input,
};

pub(super) const ECDSA_HELPER_INPUTS: usize = 32 + 32 + 64 + 32 + 1;

pub(super) fn emit_ecdsa_compute_helper<'c>(
    context: &'c llzk::prelude::LlzkContext,
    helper_name: &str,
) -> Result<FuncDefOp<'c>, Error> {
    let location = Location::unknown(context);
    let felt: Type = llzk::prelude::FeltType::with_field(context, FIELD_NAME).into();
    let inputs = vec![(felt, location); ECDSA_HELPER_INPUTS];
    let input_types = vec![felt; ECDSA_HELPER_INPUTS];
    let function_type = FunctionType::new(context, &input_types, &[felt]);
    let function = dialect::function::def(location, helper_name, function_type, &[], None)?;
    function.set_allow_witness_attr(true);

    let block = Block::new(&inputs);
    let result = block
        .append_operation(dialect::llzk::nondet(location, felt))
        .result(0)?
        .into();
    block.append_operation(dialect::function::r#return(location, &[result]));
    function.region(0)?.append_block(block);
    Ok(function)
}

pub(super) fn emit_limbs_constant<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    x: &[u64; LIMBS],
    y: &[u64; LIMBS],
) -> Result<(Limbs256<'c, 'b>, Limbs256<'c, 'b>), Error> {
    Ok((pack_u64_limbs(writer, x)?, pack_u64_limbs(writer, y)?))
}

pub(super) fn pack_u64_limbs<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    limbs: &[u64; LIMBS],
) -> Result<Limbs256<'c, 'b>, Error> {
    try_init_limbs(|i| writer.emit_constant(&FieldElement::from(limbs[i] as u128)))
}

pub(super) fn emit_select_value<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    bit: llzk::prelude::Value<'c, 'b>,
    if_one: llzk::prelude::Value<'c, 'b>,
    if_zero: llzk::prelude::Value<'c, 'b>,
) -> Result<llzk::prelude::Value<'c, 'b>, Error> {
    let one = writer.emit_constant(&FieldElement::one())?;
    let neg_bit = writer.insert_neg(bit)?;
    let one_minus_bit = writer.insert_add(one, neg_bit)?;
    let from_one = writer.insert_mul(bit, if_one)?;
    let from_zero = writer.insert_mul(one_minus_bit, if_zero)?;
    writer.insert_add(from_one, from_zero)
}

pub(super) fn emit_select_limbs<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    bit: llzk::prelude::Value<'c, 'b>,
    if_one: &Limbs256<'c, 'b>,
    if_zero: &Limbs256<'c, 'b>,
) -> Result<Limbs256<'c, 'b>, Error> {
    let one = writer.emit_constant(&FieldElement::one())?;
    let neg_bit = writer.insert_neg(bit)?;
    let one_minus_bit = writer.insert_add(one, neg_bit)?;
    try_init_limbs(|i| {
        let from_one = writer.insert_mul(bit, if_one[i])?;
        let from_zero = writer.insert_mul(one_minus_bit, if_zero[i])?;
        writer.insert_add(from_one, from_zero)
    })
}

pub(super) fn emit_not<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    bit: llzk::prelude::Value<'c, 'b>,
) -> Result<llzk::prelude::Value<'c, 'b>, Error> {
    let one = writer.emit_constant(&FieldElement::one())?;
    let neg_bit = writer.insert_neg(bit)?;
    writer.insert_add(one, neg_bit)
}

/// Packs 32 big-endian bytes into 4 little-endian 64-bit limbs:
/// `bytes[0]` (MSB) → `limbs[3]` high byte; `bytes[31]` (LSB) → `limbs[0]` low byte.
pub(super) fn pack_bytes_be_to_le_limbs<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    bytes: &[FunctionInput<FieldElement>; 32],
) -> Result<Limbs256<'c, 'b>, Error> {
    try_init_limbs(|limb_idx| {
        let byte_start = (3 - limb_idx) * 8;
        let mut acc = writer.emit_constant(&FieldElement::from(0u128))?;
        for i in 0..8 {
            let byte_value = emit_blackbox_input(writer, &bytes[byte_start + i])?;
            let shift = 8u32 * (7 - i) as u32;
            let coeff = writer.emit_constant(&FieldElement::from(1u128 << shift))?;
            let term = writer.insert_mul(byte_value, coeff)?;
            acc = writer.insert_add(acc, term)?;
        }
        Ok(acc)
    })
}
