use acir::{AcirField, FieldElement};
use llzk::prelude::Value;

use crate::{block_writer::BlockWriter, error::Error};

use super::{
    LIMBS, Limbs256,
    common::{witness_bool, witness_result_limbs},
    compare::emit_assert_lt_modulus,
    mul::emit_mul_mod_p,
};

/// Emits `(q, b_nonzero)` where q = a·b⁻¹ mod p when b ≠ 0, else q is
/// unconstrained garbage and `b_nonzero = 0`. `b_nonzero` is a felt ∈ {0, 1}
/// indicating whether the division was meaningful.
///
/// Uses the nonzero-hint pattern on `b` and gates the `b·q ≡ a (mod p)`
/// constraint by `b_nonzero`.
pub(crate) fn emit_safe_div_mod_p<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    a: &Limbs256<'c, 'a>,
    b: &Limbs256<'c, 'a>,
    p: &[u64; LIMBS],
) -> Result<(Limbs256<'c, 'a>, Value<'c, 'a>), Error> {
    let zero = writer.emit_constant(&FieldElement::zero())?;
    let one = writer.emit_constant(&FieldElement::one())?;

    // b_sum = Σ b_i. Since b is canonical (each limb < 2^64), b_sum < 2^66 <
    // p_bn254, so the felt sum equals the integer sum and is zero iff b is zero.
    let mut b_sum = b[0];
    for limb in &b[1..] {
        b_sum = writer.insert_add(b_sum, *limb)?;
    }

    let b_is_zero = witness_bool(writer)?;
    let gate_zero = writer.insert_mul(b_is_zero, b_sum)?;
    writer.insert_constrain_eq(gate_zero, zero);

    // (1 - b_is_zero) · (b_sum · inv_hint - 1) = 0 forces b_sum to be
    // invertible when b_is_zero = 0, i.e., b must be nonzero.
    let felt_ty = writer.felt_type();
    let inv_hint = writer.insert_nondet(felt_ty)?;
    let prod = writer.insert_mul(b_sum, inv_hint)?;
    let neg_one = writer.insert_neg(one)?;
    let prod_minus_one = writer.insert_add(prod, neg_one)?;
    let neg_b_is_zero = writer.insert_neg(b_is_zero)?;
    let b_nonzero = writer.insert_add(one, neg_b_is_zero)?;
    let gate_nonzero = writer.insert_mul(b_nonzero, prod_minus_one)?;
    writer.insert_constrain_eq(gate_nonzero, zero);

    let q = witness_result_limbs(writer)?;
    emit_assert_lt_modulus(writer, &q, p)?;
    let bq = emit_mul_mod_p(writer, b, &q, p)?;
    for (bq_limb, a_limb) in bq.iter().zip(a.iter()) {
        let neg_a = writer.insert_neg(*a_limb)?;
        let diff = writer.insert_add(*bq_limb, neg_a)?;
        let gated = writer.insert_mul(b_nonzero, diff)?;
        writer.insert_constrain_eq(gated, zero);
    }
    Ok((q, b_nonzero))
}
