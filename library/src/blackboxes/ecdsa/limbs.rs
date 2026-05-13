use acir::{AcirField, FieldElement};
use llzk::prelude::{Block, FeltType, Location, Value, dialect};

use crate::{FIELD_NAME, error::Error, multiprec::LIMBS};

pub(super) use crate::blackboxes::common::{append_felt_constant, append_op_with_result};

pub(super) fn two_pow_64() -> FieldElement {
    FieldElement::from(2u128).pow(&FieldElement::from(64u128))
}

pub(super) fn append_split_low_64<'c, 'a>(
    block: &'a Block<'c>,
    location: Location<'c>,
    value: Value<'c, 'a>,
    two_64: Value<'c, 'a>,
) -> Result<(Value<'c, 'a>, Value<'c, 'a>), Error> {
    let low = append_op_with_result(block, dialect::felt::umod(location, value, two_64)?)?;
    let high = append_op_with_result(block, dialect::felt::uintdiv(location, value, two_64)?)?;
    Ok((low, high))
}

pub(super) fn append_limbs_add_with_carry<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    lhs: &[Value<'c, 'a>; LIMBS],
    rhs: &[Value<'c, 'a>; LIMBS],
    carry_in: Value<'c, 'a>,
) -> Result<([Value<'c, 'a>; LIMBS], Value<'c, 'a>), Error> {
    let two_64 = append_felt_constant(block, context, location, &two_pow_64())?;
    let mut limbs = [carry_in; LIMBS];
    let mut carry = carry_in;
    for i in 0..LIMBS {
        let sum = append_op_with_result(block, dialect::felt::add(location, lhs[i], rhs[i])?)?;
        let with_carry = append_op_with_result(block, dialect::felt::add(location, sum, carry)?)?;
        let (low, next_carry) = append_split_low_64(block, location, with_carry, two_64)?;
        limbs[i] = low;
        carry = next_carry;
    }
    Ok((limbs, carry))
}

/// Per-limb subtract: compute `(lhs[i] + 2^64) - rhs[i] - borrow`, then split
/// at 2^64. The high bit survives iff there was no underflow; the next borrow
/// is `1 - high`.
pub(super) fn append_limbs_sub_with_borrow<'c, 'a, const N: usize>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    lhs: &[Value<'c, 'a>; N],
    rhs: &[Value<'c, 'a>; N],
    borrow_in: Value<'c, 'a>,
) -> Result<([Value<'c, 'a>; N], Value<'c, 'a>), Error> {
    let two_64 = append_felt_constant(block, context, location, &two_pow_64())?;
    let one = append_felt_constant(block, context, location, &FieldElement::one())?;
    let mut limbs = [borrow_in; N];
    let mut borrow = borrow_in;
    for i in 0..N {
        let neg_rhs = append_op_with_result(block, dialect::felt::neg(location, rhs[i])?)?;
        let neg_borrow = append_op_with_result(block, dialect::felt::neg(location, borrow)?)?;
        let plus_two_64 =
            append_op_with_result(block, dialect::felt::add(location, lhs[i], two_64)?)?;
        let after_rhs =
            append_op_with_result(block, dialect::felt::add(location, plus_two_64, neg_rhs)?)?;
        let after_borrow =
            append_op_with_result(block, dialect::felt::add(location, after_rhs, neg_borrow)?)?;
        let (low, no_underflow) = append_split_low_64(block, location, after_borrow, two_64)?;
        limbs[i] = low;
        let neg_no_underflow =
            append_op_with_result(block, dialect::felt::neg(location, no_underflow)?)?;
        borrow =
            append_op_with_result(block, dialect::felt::add(location, one, neg_no_underflow)?)?;
    }
    Ok((limbs, borrow))
}

/// `lhs < rhs` as felt 0/1 via the borrow-out of `lhs - rhs`.
pub(super) fn append_limbs_lt_bool<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    lhs: &[Value<'c, 'a>; LIMBS],
    rhs: &[Value<'c, 'a>; LIMBS],
) -> Result<Value<'c, 'a>, Error> {
    let zero = append_felt_constant(block, context, location, &FieldElement::zero())?;
    let (_, borrow) = append_limbs_sub_with_borrow(block, context, location, lhs, rhs, zero)?;
    Ok(borrow)
}

/// Limb-wise equality as a felt 0/1. Uses sum-of-squared-diffs: each square
/// fits in ~130 bits and the sum-of-4 stays under ~2^132, so wraparound-free
/// on BN254.
pub(super) fn append_limbs_eq_bool<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    lhs: &[Value<'c, 'a>; LIMBS],
    rhs: &[Value<'c, 'a>; LIMBS],
) -> Result<Value<'c, 'a>, Error> {
    let zero = append_felt_constant(block, context, location, &FieldElement::zero())?;
    let mut sum_sq = zero;
    for i in 0..LIMBS {
        let neg = append_op_with_result(block, dialect::felt::neg(location, rhs[i])?)?;
        let diff = append_op_with_result(block, dialect::felt::add(location, lhs[i], neg)?)?;
        let sq = append_op_with_result(block, dialect::felt::mul(location, diff, diff)?)?;
        sum_sq = append_op_with_result(block, dialect::felt::add(location, sum_sq, sq)?)?;
    }
    let eq_i1 = append_op_with_result(block, dialect::bool::eq(location, sum_sq, zero)?)?;
    let felt_ty = FeltType::with_field(context, FIELD_NAME);
    append_op_with_result(block, dialect::cast::tofelt(location, eq_i1, Some(felt_ty)))
}

/// Multiplies two 4-limb values into 8 LE 64-bit limbs. Each column accumulates up to 4
/// 128-bit products (< 2^131, safely inside BN254) before a single carry pass.
pub(super) fn append_limbs_mul_wide<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    lhs: &[Value<'c, 'a>; LIMBS],
    rhs: &[Value<'c, 'a>; LIMBS],
) -> Result<[Value<'c, 'a>; 2 * LIMBS], Error> {
    let zero = append_felt_constant(block, context, location, &FieldElement::zero())?;
    let two_64 = append_felt_constant(block, context, location, &two_pow_64())?;
    let n_out = 2 * LIMBS;
    let mut columns: [Value<'c, 'a>; 2 * LIMBS] = [zero; 2 * LIMBS];
    for (i, lhs_limb) in lhs.iter().enumerate() {
        for (j, rhs_limb) in rhs.iter().enumerate() {
            let product =
                append_op_with_result(block, dialect::felt::mul(location, *lhs_limb, *rhs_limb)?)?;
            let k = i + j;
            columns[k] =
                append_op_with_result(block, dialect::felt::add(location, columns[k], product)?)?;
        }
    }
    let mut limbs: [Value<'c, 'a>; 2 * LIMBS] = [zero; 2 * LIMBS];
    let mut carry = zero;
    for k in 0..n_out {
        let with_carry =
            append_op_with_result(block, dialect::felt::add(location, columns[k], carry)?)?;
        let (low, next_carry) = append_split_low_64(block, location, with_carry, two_64)?;
        limbs[k] = low;
        carry = next_carry;
    }
    // Caller bound: (2^256 - 1)^2 < 2^512, so `carry` is zero. Out-of-range
    // inputs propagate cleanly through the surrounding reduction.
    let _ = carry;
    Ok(limbs)
}

/// Returns `1 - x` as a felt (assumes `x ∈ {0, 1}`).
pub(super) fn append_not_bit<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    x: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    let one = append_felt_constant(block, context, location, &FieldElement::one())?;
    let neg = append_op_with_result(block, dialect::felt::neg(location, x)?)?;
    append_op_with_result(block, dialect::felt::add(location, one, neg)?)
}

/// `bit ∈ {0, 1}` selects `if_one` (1) or `if_zero` (0), per limb.
pub(super) fn append_select_limbs<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    bit: Value<'c, 'a>,
    if_one: &[Value<'c, 'a>; LIMBS],
    if_zero: &[Value<'c, 'a>; LIMBS],
) -> Result<[Value<'c, 'a>; LIMBS], Error> {
    let one = append_felt_constant(block, context, location, &FieldElement::one())?;
    let zero = append_felt_constant(block, context, location, &FieldElement::zero())?;
    let neg_bit = append_op_with_result(block, dialect::felt::neg(location, bit)?)?;
    let one_minus_bit = append_op_with_result(block, dialect::felt::add(location, one, neg_bit)?)?;
    let mut result = [zero; LIMBS];
    for i in 0..LIMBS {
        let from_one = append_op_with_result(block, dialect::felt::mul(location, bit, if_one[i])?)?;
        let from_zero = append_op_with_result(
            block,
            dialect::felt::mul(location, one_minus_bit, if_zero[i])?,
        )?;
        result[i] =
            append_op_with_result(block, dialect::felt::add(location, from_one, from_zero)?)?;
    }
    Ok(result)
}
