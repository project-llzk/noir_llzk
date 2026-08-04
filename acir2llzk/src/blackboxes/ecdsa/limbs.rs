use acir::{AcirField, FieldElement};
use llzk::{
    builder::OpBuilder,
    prelude::{
        dialect::{bool, cast, felt},
        LlzkContext, Location, Value,
    },
};

use crate::{common::as_value, error::Error, multiprec::LIMBS};

pub(super) use crate::blackboxes::common::append_felt_constant;

pub(super) fn two_pow_64() -> FieldElement {
    FieldElement::from(2u128).pow(&FieldElement::from(64u128))
}

pub(super) fn append_split_low_64<'c: 'a, 'a>(
    builder: &OpBuilder<'c, '_>,
    location: Location<'c>,
    value: Value<'c, 'a>,
    two_64: Value<'c, 'a>,
) -> Result<(Value<'c, 'a>, Value<'c, 'a>), Error> {
    let low = as_value(felt::umod(builder, location, value, two_64)?)?;
    let high = as_value(felt::uintdiv(builder, location, value, two_64)?)?;
    Ok((low, high))
}

pub(super) fn append_limbs_add_with_carry<'c: 'a, 'a>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    lhs: &[Value<'c, 'a>; LIMBS],
    rhs: &[Value<'c, 'a>; LIMBS],
    carry_in: Value<'c, 'a>,
) -> Result<([Value<'c, 'a>; LIMBS], Value<'c, 'a>), Error> {
    let two_64 = append_felt_constant(builder, context, location, &two_pow_64())?;
    let mut limbs = [carry_in; LIMBS];
    let mut carry = carry_in;
    for i in 0..LIMBS {
        let sum = as_value(felt::add(builder, location, lhs[i], rhs[i])?)?;
        let with_carry = as_value(felt::add(builder, location, sum, carry)?)?;
        let (low, next_carry) = append_split_low_64(builder, location, with_carry, two_64)?;
        limbs[i] = low;
        carry = next_carry;
    }
    Ok((limbs, carry))
}

/// Per-limb subtract: compute `(lhs[i] + 2^64) - rhs[i] - borrow`, then split
/// at 2^64. The high bit survives iff there was no underflow; the next borrow
/// is `1 - high`.
pub(super) fn append_limbs_sub_with_borrow<'c: 'a, 'a, const N: usize>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    lhs: &[Value<'c, 'a>; N],
    rhs: &[Value<'c, 'a>; N],
    borrow_in: Value<'c, 'a>,
) -> Result<([Value<'c, 'a>; N], Value<'c, 'a>), Error> {
    let two_64 = append_felt_constant(builder, context, location, &two_pow_64())?;
    let one = append_felt_constant(builder, context, location, &FieldElement::one())?;
    let mut limbs = [borrow_in; N];
    let mut borrow = borrow_in;
    for i in 0..N {
        let neg_rhs = as_value(felt::neg(builder, location, rhs[i])?)?;
        let neg_borrow = as_value(felt::neg(builder, location, borrow)?)?;
        let plus_two_64 = as_value(felt::add(builder, location, lhs[i], two_64)?)?;
        let after_rhs = as_value(felt::add(builder, location, plus_two_64, neg_rhs)?)?;
        let after_borrow = as_value(felt::add(builder, location, after_rhs, neg_borrow)?)?;
        let (low, no_underflow) = append_split_low_64(builder, location, after_borrow, two_64)?;
        limbs[i] = low;
        let neg_no_underflow = as_value(felt::neg(builder, location, no_underflow)?)?;
        borrow = as_value(felt::add(builder, location, one, neg_no_underflow)?)?;
    }
    Ok((limbs, borrow))
}

/// `lhs < rhs` as felt 0/1 via the borrow-out of `lhs - rhs`.
pub(super) fn append_limbs_lt_bool<'c: 'a, 'a>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    lhs: &[Value<'c, 'a>; LIMBS],
    rhs: &[Value<'c, 'a>; LIMBS],
) -> Result<Value<'c, 'a>, Error> {
    let zero = append_felt_constant(builder, context, location, &FieldElement::zero())?;
    let (_, borrow) = append_limbs_sub_with_borrow(builder, context, location, lhs, rhs, zero)?;
    Ok(borrow)
}

/// Limb-wise equality as a felt 0/1. Uses sum-of-squared-diffs: each square
/// fits in ~130 bits and the sum-of-4 stays under ~2^132, so wraparound-free
/// on BN254.
pub(super) fn append_limbs_eq_bool<'c: 'a, 'a>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    lhs: &[Value<'c, 'a>; LIMBS],
    rhs: &[Value<'c, 'a>; LIMBS],
) -> Result<Value<'c, 'a>, Error> {
    let zero = append_felt_constant(builder, context, location, &FieldElement::zero())?;
    let mut sum_sq = zero;
    for i in 0..LIMBS {
        let neg = as_value(felt::neg(builder, location, rhs[i])?)?;
        let diff = as_value(felt::add(builder, location, lhs[i], neg)?)?;
        let sq = as_value(felt::mul(builder, location, diff, diff)?)?;
        sum_sq = as_value(felt::add(builder, location, sum_sq, sq)?)?;
    }
    let eq_i1 = as_value(bool::eq(builder, location, sum_sq, zero)?)?;
    let felt_ty = context.felt_type();
    as_value(cast::tofelt(builder, location, eq_i1, Some(felt_ty)))
}

/// Multiplies two 4-limb values into 8 LE 64-bit limbs. Each column accumulates up to 4
/// 128-bit products (< 2^131, safely inside BN254) before a single carry pass.
pub(super) fn append_limbs_mul_wide<'c: 'a, 'a>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    lhs: &[Value<'c, 'a>; LIMBS],
    rhs: &[Value<'c, 'a>; LIMBS],
) -> Result<[Value<'c, 'a>; 2 * LIMBS], Error> {
    let zero = append_felt_constant(builder, context, location, &FieldElement::zero())?;
    let two_64 = append_felt_constant(builder, context, location, &two_pow_64())?;
    let n_out = 2 * LIMBS;
    let mut columns: [Value<'c, 'a>; 2 * LIMBS] = [zero; 2 * LIMBS];
    for (i, lhs_limb) in lhs.iter().enumerate() {
        for (j, rhs_limb) in rhs.iter().enumerate() {
            let product = as_value(felt::mul(builder, location, *lhs_limb, *rhs_limb)?)?;
            let k = i + j;
            columns[k] = as_value(felt::add(builder, location, columns[k], product)?)?;
        }
    }
    let mut limbs: [Value<'c, 'a>; 2 * LIMBS] = [zero; 2 * LIMBS];
    let mut carry = zero;
    for k in 0..n_out {
        let with_carry = as_value(felt::add(builder, location, columns[k], carry)?)?;
        let (low, next_carry) = append_split_low_64(builder, location, with_carry, two_64)?;
        limbs[k] = low;
        carry = next_carry;
    }
    // Caller bound: (2^256 - 1)^2 < 2^512, so `carry` is zero. Out-of-range
    // inputs propagate cleanly through the surrounding reduction.
    let _ = carry;
    Ok(limbs)
}

/// Returns `1 - x` as a felt (assumes `x ∈ {0, 1}`).
pub(super) fn append_not_bit<'c: 'a, 'a>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    x: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    let one = append_felt_constant(builder, context, location, &FieldElement::one())?;
    let neg = as_value(felt::neg(builder, location, x)?)?;
    as_value(felt::add(builder, location, one, neg)?)
}

/// `bit ∈ {0, 1}` selects `if_one` (1) or `if_zero` (0), per limb.
pub(super) fn append_select_limbs<'c: 'a, 'a>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    bit: Value<'c, 'a>,
    if_one: &[Value<'c, 'a>; LIMBS],
    if_zero: &[Value<'c, 'a>; LIMBS],
) -> Result<[Value<'c, 'a>; LIMBS], Error> {
    let one = append_felt_constant(builder, context, location, &FieldElement::one())?;
    let zero = append_felt_constant(builder, context, location, &FieldElement::zero())?;
    let neg_bit = as_value(felt::neg(builder, location, bit)?)?;
    let one_minus_bit = as_value(felt::add(builder, location, one, neg_bit)?)?;
    let mut result = [zero; LIMBS];
    for i in 0..LIMBS {
        let from_one = as_value(felt::mul(builder, location, bit, if_one[i])?)?;
        let from_zero = as_value(felt::mul(builder, location, one_minus_bit, if_zero[i])?)?;
        result[i] = as_value(felt::add(builder, location, from_one, from_zero)?)?;
    }
    Ok(result)
}
