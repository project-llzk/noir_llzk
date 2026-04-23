//! Shared helpers used by both secp256k1 and secp256r1 ECDSA opcode wrappers.

use acir::{FieldElement, circuit::opcodes::FunctionInput};

use crate::{
    block_writer::BlockWriter,
    error::Error,
    multiprec::{LIMBS, Limbs256, try_init_limbs},
    opcodes::emit_blackbox_input,
};

/// Emits an affine point from two 4-limb constants.
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

/// Packs 32 big-endian bytes into 4 little-endian 64-bit limbs.
/// `bytes[0]` is the overall most-significant byte → ends up in `limbs[3]`'s
/// high byte; `bytes[31]` is LSB → `limbs[0]`'s low byte.
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
