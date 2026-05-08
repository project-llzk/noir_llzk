use acir::{AcirField, FieldElement};

use super::{
    LIMBS, Limbs256,
    common::{constrain_signed_trit, two_pow_64, witness_bool, witness_result_limbs},
    compare::emit_assert_lt_modulus,
};
use crate::{block_writer::BlockWriter, error::Error, writer::Writer};

/// Emits `r = (a + b) mod p` where a, b < p and p < 2^256.
///
/// Since a, b < p < 2^256, the quotient `k = (a + b) div p ∈ {0, 1}`.
/// Witnesses k and r non-deterministically, enforces `a + b = k·p + r`
/// as a 4-limb integer identity via carry propagation, plus
/// `k ∈ {0, 1}`, each limb of r < 2^64, and each propagated carry ∈ {-1, 0, 1}.
///
/// Does not enforce `r < p` — caller decides when a fully-reduced form is needed.
pub(crate) fn emit_add_mod_p<'c, 'a>(
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
        let neg_k_p = writer.insert_neg(k_p)?;
        let neg_r = writer.insert_neg(r[i])?;
        let ab = writer.insert_add(a[i], b[i])?;
        let ab_minus_kp = writer.insert_add(ab, neg_k_p)?;
        let diff = writer.insert_add(ab_minus_kp, neg_r)?;
        let lhs = writer.insert_add(diff, carry)?;

        let felt_ty = writer.felt_type();
        let next_carry = writer.insert_nondet(felt_ty)?;
        constrain_signed_trit(writer, next_carry)?;
        let rhs = writer.insert_mul(next_carry, two_64)?;
        writer.insert_constrain_eq(lhs, rhs);

        carry = next_carry;
    }
    writer.insert_constrain_eq(carry, zero);

    emit_assert_lt_modulus(writer, &r, p)?;
    Ok(r)
}
