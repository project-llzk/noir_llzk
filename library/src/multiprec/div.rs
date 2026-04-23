use crate::{block_writer::BlockWriter, error::Error};

use super::{
    LIMBS, Limbs256, common::witness_result_limbs, compare::emit_assert_lt_modulus,
    mul::emit_mul_mod_p,
};

/// Emits `q = a · b⁻¹ mod p`. Witnesses `q` non-deterministically and
/// enforces `b · q ≡ a (mod p)` via `emit_mul_mod_p`, which is one mul-check
/// cheaper than inv-then-mul.
///
/// Assumes `b ≠ 0` mod p; caller guarantees.
pub(crate) fn emit_div_mod_p<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    a: &Limbs256<'c, 'a>,
    b: &Limbs256<'c, 'a>,
    p: &[u64; LIMBS],
) -> Result<Limbs256<'c, 'a>, Error> {
    let q = witness_result_limbs(writer)?;
    emit_assert_lt_modulus(writer, &q, p)?;
    let product = emit_mul_mod_p(writer, b, &q, p)?;
    for (p_limb, a_limb) in product.iter().zip(a.iter()) {
        writer.insert_constrain_eq(*p_limb, *a_limb);
    }
    Ok(q)
}
