use acir::{AcirField, FieldElement};

use crate::{block_writer::BlockWriter, error::Error};

use super::{
    LIMBS, Limbs256,
    common::{constrain_signed_trit, two_pow_64, witness_bool, witness_result_limbs},
};

/// Emits `r = (a - b) mod p` where a, b < p and p < 2^256.
///
/// Sets `k = 1` when `a < b` (so `r = a - b + p`), `k = 0` otherwise.
/// The identity `a - b + k·p = r` is enforced as a 4-limb integer equation
/// via carry propagation.
pub(crate) fn emit_sub_mod_p<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    a: &Limbs256<'c, 'a>,
    b: &Limbs256<'c, 'a>,
    p: &[u64; LIMBS],
) -> Result<Limbs256<'c, 'a>, Error> {
    let zero = writer.emit_constant(&FieldElement::zero())?;
    let two_64 = two_pow_64(writer)?;

    let k = witness_bool(writer)?;
    let r = witness_result_limbs(writer)?;

    let mut carry = zero;
    for i in 0..LIMBS {
        let p_limb = writer.emit_constant(&FieldElement::from(p[i] as u128))?;
        let k_p = writer.insert_mul(k, p_limb)?;
        let neg_b = writer.insert_neg(b[i])?;
        let neg_r = writer.insert_neg(r[i])?;
        let a_minus_b = writer.insert_add(a[i], neg_b)?;
        let plus_kp = writer.insert_add(a_minus_b, k_p)?;
        let diff = writer.insert_add(plus_kp, neg_r)?;
        let lhs = writer.insert_add(diff, carry)?;

        let felt_ty = writer.felt_type();
        let next_carry = writer.insert_nondet(felt_ty)?;
        constrain_signed_trit(writer, next_carry)?;
        let rhs = writer.insert_mul(next_carry, two_64)?;
        writer.insert_constrain_eq(lhs, rhs);

        carry = next_carry;
    }
    writer.insert_constrain_eq(carry, zero);

    Ok(r)
}
