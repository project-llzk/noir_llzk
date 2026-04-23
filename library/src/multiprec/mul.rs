use acir::{AcirField, FieldElement};
use llzk::prelude::Value;

use crate::{block_writer::BlockWriter, error::Error};

use super::{
    LIMBS, Limbs256,
    common::{two_pow_64, witness_result_limbs},
    compare::emit_assert_lt_modulus,
};

/// Width (in bits) of the unsigned range check applied to each carry after
/// offsetting by `2^(CARRY_RANGE_BITS - 1)`. Carries for 4×64-bit multiplication
/// are bounded by 2^67 in magnitude, so 68 bits suffice; we round up slightly.
const CARRY_RANGE_BITS: u32 = 72;

/// Number of output limbs in a 4×4 limb polynomial product (2n - 1).
const PRODUCT_LIMBS: usize = 2 * LIMBS - 1;

/// Emits `r = (a · b) mod p` where a, b < p and p < 2^256.
///
/// Witnesses the quotient `q = (a·b) div p` (4 limbs) and the remainder `r`
/// (4 limbs), each limb range-checked to 64 bits. Enforces the polynomial
/// identity `a(X)·b(X) = q(X)·p(X) + r(X)` as a 7-limb (base 2^64) integer
/// equation via per-limb carry propagation.
///
/// Does not enforce `r < p`; caller decides.
pub(crate) fn emit_mul_mod_p<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    a: &Limbs256<'c, 'a>,
    b: &Limbs256<'c, 'a>,
    p: &[u64; LIMBS],
) -> Result<Limbs256<'c, 'a>, Error> {
    let zero = writer.emit_constant(&FieldElement::zero())?;
    let two_64 = two_pow_64(writer)?;

    let q = witness_result_limbs(writer)?;
    let r = witness_result_limbs(writer)?;

    let mut p_vals: [Value<'c, 'a>; LIMBS] = [q[0]; LIMBS];
    for (slot, &p_limb) in p_vals.iter_mut().zip(p.iter()) {
        *slot = writer.emit_constant(&FieldElement::from(p_limb as u128))?;
    }

    let mut carry = zero;
    for k in 0..PRODUCT_LIMBS {
        let ab_k = poly_limb(writer, a, b, k)?;
        let qp_k = poly_limb(writer, &q, &p_vals, k)?;
        let neg_qp_k = writer.insert_neg(qp_k)?;
        let mut diff = writer.insert_add(ab_k, neg_qp_k)?;
        if let Some(r_limb) = r.get(k) {
            let neg_r_k = writer.insert_neg(*r_limb)?;
            diff = writer.insert_add(diff, neg_r_k)?;
        }
        let lhs = writer.insert_add(diff, carry)?;

        if k == PRODUCT_LIMBS - 1 {
            // Final limb: lhs must be exactly zero (no outgoing carry).
            writer.insert_constrain_eq(lhs, zero);
        } else {
            let felt_ty = writer.felt_type();
            let next_carry = writer.insert_nondet(felt_ty)?;
            constrain_carry_range(writer, next_carry)?;
            let rhs = writer.insert_mul(next_carry, two_64)?;
            writer.insert_constrain_eq(lhs, rhs);
            carry = next_carry;
        }
    }

    emit_assert_lt_modulus(writer, &r, p)?;
    Ok(r)
}

/// Computes the k-th limb of the polynomial product `x(X) · y(X)` as a
/// felt-expression: `Σ_{i+j=k} x_i · y_j`, for 0 ≤ k ≤ 2·LIMBS - 2.
fn poly_limb<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    x: &[Value<'c, 'a>; LIMBS],
    y: &[Value<'c, 'a>; LIMBS],
    k: usize,
) -> Result<Value<'c, 'a>, Error> {
    let i_start = k.saturating_sub(LIMBS - 1);
    let i_end = k.min(LIMBS - 1);
    let mut acc: Option<Value<'c, 'a>> = None;
    for (i, x_i) in x.iter().enumerate().skip(i_start).take(i_end + 1 - i_start) {
        let j = k - i;
        let term = writer.insert_mul(*x_i, y[j])?;
        acc = Some(match acc {
            None => term,
            Some(prev) => writer.insert_add(prev, term)?,
        });
    }
    match acc {
        Some(v) => Ok(v),
        None => writer.emit_constant(&FieldElement::zero()),
    }
}

/// Enforces `c ∈ [-2^(B-1), 2^(B-1))` via `0 ≤ c + 2^(B-1) < 2^B`, where
/// `B = CARRY_RANGE_BITS`.
fn constrain_carry_range<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    c: Value<'c, 'a>,
) -> Result<(), Error> {
    let offset = writer.emit_constant(
        &FieldElement::from(2u128).pow(&FieldElement::from((CARRY_RANGE_BITS - 1) as u128)),
    )?;
    let bound = writer.emit_constant(
        &FieldElement::from(2u128).pow(&FieldElement::from(CARRY_RANGE_BITS as u128)),
    )?;
    let shifted = writer.insert_add(c, offset)?;
    let ok = writer.insert_bool_lt(shifted, bound)?;
    writer.insert_bool_assert(ok)?;
    Ok(())
}
