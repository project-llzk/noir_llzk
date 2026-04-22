use acir::{AcirField, FieldElement};
use llzk::prelude::Value;

use crate::{block_writer::BlockWriter, error::Error};

use super::{LIMB_BITS, LIMBS, Limbs256};

/// Decomposes a 4-limb value into its 256 little-endian bits.
///
/// Emits one nondet per bit, constrains each bit ∈ {0, 1}, and asserts
/// `Σ_{j=0..63} bit[limb_idx · 64 + j] · 2^j = limbs[limb_idx]` for each of
/// the 4 limbs. Total: 256 nondets.
pub(crate) fn emit_bit_decompose_256<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    limbs: &Limbs256<'c, 'a>,
) -> Result<Vec<Value<'c, 'a>>, Error> {
    let mut all_bits = Vec::with_capacity(LIMBS * LIMB_BITS as usize);
    for limb in limbs.iter() {
        let bits = emit_bit_decompose_u64(writer, *limb)?;
        all_bits.extend(bits);
    }
    Ok(all_bits)
}

/// Decomposes a single 64-bit-bounded limb into 64 boolean bits, least
/// significant first. Constrains bits reconstruct to the input.
fn emit_bit_decompose_u64<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    value: Value<'c, 'a>,
) -> Result<Vec<Value<'c, 'a>>, Error> {
    let felt_ty = writer.felt_type();
    let zero = writer.emit_constant(&FieldElement::zero())?;
    let one = writer.emit_constant(&FieldElement::one())?;

    let mut bits = Vec::with_capacity(LIMB_BITS as usize);
    let mut reconstruction = zero;
    for i in 0..LIMB_BITS {
        let bit = writer.insert_nondet(felt_ty)?;
        // bit ∈ {0, 1}: bit · (1 - bit) = 0.
        let neg_bit = writer.insert_neg(bit)?;
        let one_minus_bit = writer.insert_add(one, neg_bit)?;
        let boolean = writer.insert_mul(bit, one_minus_bit)?;
        writer.insert_constrain_eq(boolean, zero);
        // Accumulate bit · 2^i into the reconstruction.
        if i == 0 {
            reconstruction = bit;
        } else {
            let coeff = writer.emit_constant(&FieldElement::from(1u128 << i))?;
            let term = writer.insert_mul(bit, coeff)?;
            reconstruction = writer.insert_add(reconstruction, term)?;
        }
        bits.push(bit);
    }
    writer.insert_constrain_eq(reconstruction, value);
    Ok(bits)
}
