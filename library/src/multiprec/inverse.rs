use acir::{AcirField, FieldElement};

use crate::{block_writer::BlockWriter, error::Error};

use super::{LIMBS, Limbs256, common::witness_result_limbs, mul::emit_mul_mod_p};

/// Emits `a_inv` such that `a · a_inv ≡ 1 (mod p)`, witnessing `a_inv`
/// non-deterministically and enforcing the product via `emit_mul_mod_p`.
///
/// Assumes `a ≠ 0` and `gcd(a, p) = 1`; caller guarantees.
pub(crate) fn emit_inv_mod_p<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    a: &Limbs256<'c, 'a>,
    p: &[u64; LIMBS],
) -> Result<Limbs256<'c, 'a>, Error> {
    let a_inv = witness_result_limbs(writer)?;
    let product = emit_mul_mod_p(writer, a, &a_inv, p)?;

    let one = writer.emit_constant(&FieldElement::one())?;
    let zero = writer.emit_constant(&FieldElement::zero())?;
    writer.insert_constrain_eq(product[0], one);
    for limb in &product[1..] {
        writer.insert_constrain_eq(*limb, zero);
    }
    Ok(a_inv)
}
