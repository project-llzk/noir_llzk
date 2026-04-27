use acir::{AcirField, FieldElement};
use llzk::prelude::Value;

use crate::common::emit_gated_eq;
use crate::{block_writer::BlockWriter, error::Error};

use super::{
    LIMBS, Limbs256,
    common::{constrain_signed_trit, two_pow_64, witness_bool, witness_result_limbs},
};

/// Enforces `value < modulus` where `value` is given as 4 little-endian
/// 64-bit-bounded limbs.
///
/// Witnesses `d` such that `value + d = modulus - 1`. Each limb of `d` is
/// range-checked to 64 bits; the per-limb carry chain is exact (final
/// carry = 0). If `value ≥ modulus`, no non-negative `d` in the 4×64-bit
/// representation satisfies the equation, so the constraint is unsatisfiable.
pub(crate) fn emit_assert_lt_modulus<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    value: &Limbs256<'c, 'a>,
    modulus: &[u64; LIMBS],
) -> Result<(), Error> {
    let one = writer.emit_constant(&FieldElement::one())?;
    emit_gated_assert_lt_modulus(writer, one, value, modulus)
}

/// Returns a felt boolean indicating whether `value < modulus`.
///
/// Both branches are proven with nondeterministic witnesses:
/// - if `is_lt = 1`, prove `value + d = modulus - 1`;
/// - if `is_lt = 0`, prove `modulus + d = value`.
pub(crate) fn emit_limbs_lt_modulus_boolean<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    value: &Limbs256<'c, 'a>,
    modulus: &[u64; LIMBS],
) -> Result<Value<'c, 'a>, Error> {
    let one = writer.emit_constant(&FieldElement::one())?;
    let is_lt = witness_bool(writer)?;
    let neg_is_lt = writer.insert_neg(is_lt)?;
    let is_ge = writer.insert_add(one, neg_is_lt)?;

    emit_gated_assert_lt_modulus(writer, is_lt, value, modulus)?;
    emit_gated_assert_ge_modulus(writer, is_ge, value, modulus)?;

    Ok(is_lt)
}

fn emit_gated_assert_lt_modulus<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    gate: Value<'c, 'a>,
    value: &Limbs256<'c, 'a>,
    modulus: &[u64; LIMBS],
) -> Result<(), Error> {
    let zero = writer.emit_constant(&FieldElement::zero())?;
    let two_64 = two_pow_64(writer)?;

    let d = witness_result_limbs(writer)?;
    let m_minus_1 = modulus_minus_one(modulus);

    let mut carry = zero;
    for i in 0..LIMBS {
        let m_limb = writer.emit_constant(&FieldElement::from(m_minus_1[i] as u128))?;
        let neg_m = writer.insert_neg(m_limb)?;
        let sum = writer.insert_add(value[i], d[i])?;
        let diff = writer.insert_add(sum, neg_m)?;
        let lhs = writer.insert_add(diff, carry)?;

        let felt_ty = writer.felt_type();
        let next_carry = writer.insert_nondet(felt_ty)?;
        constrain_signed_trit(writer, next_carry)?;
        let rhs = writer.insert_mul(next_carry, two_64)?;
        emit_gated_eq(writer, gate, lhs, rhs)?;

        carry = next_carry;
    }
    emit_gated_eq(writer, gate, carry, zero)?;

    Ok(())
}

fn emit_gated_assert_ge_modulus<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    gate: Value<'c, 'a>,
    value: &Limbs256<'c, 'a>,
    modulus: &[u64; LIMBS],
) -> Result<(), Error> {
    let zero = writer.emit_constant(&FieldElement::zero())?;
    let two_64 = two_pow_64(writer)?;
    let d = witness_result_limbs(writer)?;

    let mut carry = zero;
    for i in 0..LIMBS {
        let modulus_limb = writer.emit_constant(&FieldElement::from(modulus[i] as u128))?;
        let neg_modulus = writer.insert_neg(modulus_limb)?;
        let neg_d = writer.insert_neg(d[i])?;
        let value_minus_modulus = writer.insert_add(value[i], neg_modulus)?;
        let diff = writer.insert_add(value_minus_modulus, neg_d)?;
        let lhs = writer.insert_add(diff, carry)?;

        let felt_ty = writer.felt_type();
        let next_carry = writer.insert_nondet(felt_ty)?;
        constrain_signed_trit(writer, next_carry)?;
        let rhs = writer.insert_mul(next_carry, two_64)?;
        emit_gated_eq(writer, gate, lhs, rhs)?;

        carry = next_carry;
    }
    emit_gated_eq(writer, gate, carry, zero)?;

    Ok(())
}

/// Returns a felt `is_eq ∈ {0, 1}` equal to 1 iff `a` and `b` are equal
/// as 4-limb values.
///
/// Uses the standard nonzero-hint pattern: witness `is_eq` and an inverse
/// hint `inv`. Constrain `is_eq · sum_of_squared_diffs = 0` (forces
/// sum = 0 when claimed equal) and `(1 - is_eq) · (sum · inv - 1) = 0`
/// (forces sum nonzero to have an inverse when claimed not-equal). Each
/// limb-wise difference fits in 65 bits and its square in 130, so the
/// sum over 4 limbs stays well below the BN254 modulus — no wraparound.
pub(crate) fn emit_limbs_eq_boolean<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    a: &Limbs256<'c, 'a>,
    b: &Limbs256<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    let felt_ty = writer.felt_type();
    let zero = writer.emit_constant(&FieldElement::zero())?;
    let one = writer.emit_constant(&FieldElement::one())?;

    let is_eq = witness_bool(writer)?;

    let mut sum_sq = zero;
    for (a_i, b_i) in a.iter().zip(b.iter()) {
        let neg_b = writer.insert_neg(*b_i)?;
        let diff = writer.insert_add(*a_i, neg_b)?;
        let sq = writer.insert_mul(diff, diff)?;
        sum_sq = writer.insert_add(sum_sq, sq)?;
    }

    let gate_eq = writer.insert_mul(is_eq, sum_sq)?;
    writer.insert_constrain_eq(gate_eq, zero);

    let inv_hint = writer.insert_nondet(felt_ty)?;
    let neg_is_eq = writer.insert_neg(is_eq)?;
    let one_minus_is_eq = writer.insert_add(one, neg_is_eq)?;
    let prod = writer.insert_mul(sum_sq, inv_hint)?;
    let neg_one = writer.insert_neg(one)?;
    let prod_minus_one = writer.insert_add(prod, neg_one)?;
    let gate_neq = writer.insert_mul(one_minus_is_eq, prod_minus_one)?;
    writer.insert_constrain_eq(gate_neq, zero);

    Ok(is_eq)
}

/// Computes `modulus - 1` as little-endian 64-bit limbs. `modulus` must be > 0.
fn modulus_minus_one(modulus: &[u64; LIMBS]) -> [u64; LIMBS] {
    let mut out = *modulus;
    let mut borrow = true;
    for limb in out.iter_mut() {
        if borrow {
            if *limb == 0 {
                *limb = u64::MAX;
            } else {
                *limb -= 1;
                borrow = false;
            }
        }
    }
    assert!(!borrow, "modulus must be > 0");
    out
}
