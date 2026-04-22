use acir::{AcirField, FieldElement};

use crate::{block_writer::BlockWriter, error::Error};

use super::{
    LIMBS, Limbs256,
    common::{constrain_signed_trit, two_pow_64, witness_result_limbs},
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
        writer.insert_constrain_eq(lhs, rhs);

        carry = next_carry;
    }
    writer.insert_constrain_eq(carry, zero);

    Ok(())
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
