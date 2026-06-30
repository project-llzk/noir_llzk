use acir::{AcirField, FieldElement};
use llzk::builder::{BlockInsertPointLike, OpBuilder};
use llzk::prelude::{
    Block, BlockLike, FeltType, FlatSymbolRefAttribute, FuncDefOp, FuncDefOpLike, FunctionType,
    LlzkContext, Location, OperationLike, RegionLike, Value, dialect,
};

use crate::{
    FIELD_NAME,
    blackboxes::common::{block_args, felt_type},
    error::Error,
    multiprec::LIMBS,
};

use super::{
    constants::*,
    curve::{Curve, Secp256k1, Secp256r1},
    limbs::{
        append_felt_constant, append_limbs_add_with_carry, append_limbs_lt_bool,
        append_limbs_mul_wide, append_limbs_sub_with_borrow, append_not_bit, append_op_with_result,
        append_select_limbs, append_split_low_64, two_pow_64,
    },
};

/// secp256k1 reduction constant: `p = 2^256 - c` where `c = 2^32 + 977`.
const SECP256K1_C: u128 = (1u128 << 32) + 977;

/// Sums a 4-limb low value with an N-limb high value into `LIMBS + 1` limbs.
/// Caller guarantees the true sum fits (used inside Solinas reduction).
fn append_add_4_plus_n<'c, 'a, const N: usize>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    lo: &[Value<'c, 'a>; LIMBS],
    hi: &[Value<'c, 'a>; N],
) -> Result<[Value<'c, 'a>; LIMBS + 1], Error> {
    let zero = append_felt_constant(block, context, location, &FieldElement::zero())?;
    let two_64 = append_felt_constant(block, context, location, &two_pow_64())?;
    let mut result = [zero; LIMBS + 1];
    let mut carry = zero;
    for k in 0..(LIMBS + 1) {
        let mut sum = carry;
        if k < LIMBS {
            sum = append_op_with_result(block, dialect::felt::add(location, sum, lo[k])?)?;
        }
        if k < N {
            sum = append_op_with_result(block, dialect::felt::add(location, sum, hi[k])?)?;
        }
        let (low, next_carry) = append_split_low_64(block, location, sum, two_64)?;
        result[k] = low;
        carry = next_carry;
    }
    // Caller-bounded: carry is zero here.
    let _ = carry;
    Ok(result)
}

/// One Solinas reduction round: `lo + hi * c` as 5 limbs, where `x = lo + hi * 2^256`.
fn append_solinas_round<'c, 'a, const H: usize>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    lo: &[Value<'c, 'a>; LIMBS],
    hi: &[Value<'c, 'a>; H],
    c: Value<'c, 'a>,
) -> Result<[Value<'c, 'a>; LIMBS + 1], Error> {
    let zero = append_felt_constant(block, context, location, &FieldElement::zero())?;
    let two_64 = append_felt_constant(block, context, location, &two_pow_64())?;
    let mut hi_times_c: [Value<'c, 'a>; LIMBS + 1] = [zero; LIMBS + 1];
    let mut carry = zero;
    for i in 0..H.min(LIMBS + 1) {
        let prod = append_op_with_result(block, dialect::felt::mul(location, hi[i], c)?)?;
        let with_carry = append_op_with_result(block, dialect::felt::add(location, prod, carry)?)?;
        let (low, next_carry) = append_split_low_64(block, location, with_carry, two_64)?;
        hi_times_c[i] = low;
        carry = next_carry;
    }
    for hi_limb in hi_times_c.iter_mut().skip(H) {
        let (low, next_carry) = append_split_low_64(block, location, carry, two_64)?;
        *hi_limb = low;
        carry = next_carry;
    }
    // H ≤ 4 and c < 2^33 ⇒ product fits in 5 limbs, so carry is zero here.
    let _ = carry;
    append_add_4_plus_n(block, context, location, lo, &hi_times_c)
}

/// Reduces an 8-limb value modulo `p_secp256k1` deterministically.
///
/// Three Solinas rounds shrink the spillover beyond `2^256` to a 4-limb value
/// plus a 0/1 carry, then one conditional subtract by `p` lands in `[0, p)`.
pub(super) fn append_reduce_mod_p_secp256k1<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    x: &[Value<'c, 'a>; 2 * LIMBS],
) -> Result<[Value<'c, 'a>; LIMBS], Error> {
    let c = append_felt_constant(block, context, location, &FieldElement::from(SECP256K1_C))?;

    let lo0: [Value<'c, 'a>; LIMBS] = [x[0], x[1], x[2], x[3]];
    let hi0: [Value<'c, 'a>; LIMBS] = [x[4], x[5], x[6], x[7]];
    let r1 = append_solinas_round::<LIMBS>(block, context, location, &lo0, &hi0, c)?;

    let lo1: [Value<'c, 'a>; LIMBS] = [r1[0], r1[1], r1[2], r1[3]];
    let hi1: [Value<'c, 'a>; 1] = [r1[4]];
    let r2 = append_solinas_round::<1>(block, context, location, &lo1, &hi1, c)?;

    let lo2: [Value<'c, 'a>; LIMBS] = [r2[0], r2[1], r2[2], r2[3]];
    let hi2: [Value<'c, 'a>; 1] = [r2[4]];
    let r3 = append_solinas_round::<1>(block, context, location, &lo2, &hi2, c)?;

    let lo3: [Value<'c, 'a>; LIMBS] = [r3[0], r3[1], r3[2], r3[3]];
    let p_limbs = pack_const_limbs(block, context, location, &SECP256K1_P)?;
    let lo3_lt_p = append_limbs_lt_bool(block, context, location, &lo3, &p_limbs)?;
    // need_sub = (limb 4 == 1) OR (lo3 >= p). Felt 0/1 OR is `a + b - a*b`.
    let lo3_ge_p = append_not_bit(block, context, location, lo3_lt_p)?;
    let limb4 = r3[4];
    let or_prod = append_op_with_result(block, dialect::felt::mul(location, limb4, lo3_ge_p)?)?;
    let or_sum = append_op_with_result(block, dialect::felt::add(location, limb4, lo3_ge_p)?)?;
    let neg_or_prod = append_op_with_result(block, dialect::felt::neg(location, or_prod)?)?;
    let need_sub =
        append_op_with_result(block, dialect::felt::add(location, or_sum, neg_or_prod)?)?;

    let zero = append_felt_constant(block, context, location, &FieldElement::zero())?;
    let (sub_result, _borrow) =
        append_limbs_sub_with_borrow(block, context, location, &lo3, &p_limbs, zero)?;
    append_select_limbs(block, context, location, need_sub, &sub_result, &lo3)
}

pub(super) fn pack_const_limbs<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    limbs: &[u64; LIMBS],
) -> Result<[Value<'c, 'a>; LIMBS], Error> {
    let zero = append_felt_constant(block, context, location, &FieldElement::zero())?;
    let mut result = [zero; LIMBS];
    for i in 0..LIMBS {
        result[i] = append_felt_constant(
            block,
            context,
            location,
            &FieldElement::from(limbs[i] as u128),
        )?;
    }
    Ok(result)
}

pub(super) fn append_mul_mod_p_secp256k1<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    lhs: &[Value<'c, 'a>; LIMBS],
    rhs: &[Value<'c, 'a>; LIMBS],
) -> Result<[Value<'c, 'a>; LIMBS], Error> {
    let product = append_limbs_mul_wide(block, context, location, lhs, rhs)?;
    append_reduce_mod_p_secp256k1(block, context, location, &product)
}

/// Computes the Barrett constant `mu_low = floor(2^512 / n) - 2^256` for a
/// 256-bit modulus `n`. The result is the 4-limb low part of the magic
/// constant; the implicit top limb is always 1 (`mu = 2^256 + mu_low`).
fn barrett_mu_low(n: &[u64; LIMBS]) -> [u64; LIMBS] {
    use num_bigint::BigUint;
    let n_big: BigUint = (0..LIMBS).fold(BigUint::from(0u32), |acc, i| {
        acc | (BigUint::from(n[i]) << (64 * i))
    });
    let two_512 = BigUint::from(1u32) << 512;
    let mu = two_512 / &n_big;
    let two_256 = BigUint::from(1u32) << 256;
    let mu_low = mu - two_256;
    let mask = BigUint::from(u64::MAX);
    std::array::from_fn(|i| {
        let limb = (&mu_low >> (64 * i)) & &mask;
        u64::try_from(limb).expect("64-bit limb")
    })
}

/// Deterministic `a * b mod n` for a generic 256-bit modulus via simplified
/// Barrett with `mu = floor(2^512 / n) = 2^256 + mu_low`. Barrett's `q_est`
/// is off by at most 2, so two conditional subtracts settle the remainder.
pub(super) fn append_mul_mod_n_barrett<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    lhs: &[Value<'c, 'a>; LIMBS],
    rhs: &[Value<'c, 'a>; LIMBS],
    n: &[u64; LIMBS],
) -> Result<[Value<'c, 'a>; LIMBS], Error> {
    let zero = append_felt_constant(block, context, location, &FieldElement::zero())?;
    let n_limbs = pack_const_limbs(block, context, location, n)?;
    let mu_low = barrett_mu_low(n);
    let mu_low_limbs = pack_const_limbs(block, context, location, &mu_low)?;

    let p = append_limbs_mul_wide(block, context, location, lhs, rhs)?;
    let p_hi: [Value<'c, 'a>; LIMBS] = [p[4], p[5], p[6], p[7]];

    let p_hi_times_mu = append_limbs_mul_wide(block, context, location, &p_hi, &mu_low_limbs)?;
    let p_hi_mu_high: [Value<'c, 'a>; LIMBS] = [
        p_hi_times_mu[4],
        p_hi_times_mu[5],
        p_hi_times_mu[6],
        p_hi_times_mu[7],
    ];
    let (q_est, _add_carry) =
        append_limbs_add_with_carry(block, context, location, &p_hi, &p_hi_mu_high, zero)?;

    let q_times_n = append_limbs_mul_wide(block, context, location, &q_est, &n_limbs)?;

    // Barrett: r < 3n < 3·2^256, so r_wide[5..8] are zero and r_wide[4]
    // absorbs q_est's underestimate of 0–2.
    let (r_wide, _borrow) = append_limbs_sub_with_borrow::<{ 2 * LIMBS }>(
        block, context, location, &p, &q_times_n, zero,
    )?;
    let r5: [Value<'c, 'a>; LIMBS + 1] = [r_wide[0], r_wide[1], r_wide[2], r_wide[3], r_wide[4]];

    let r_after_first = append_conditional_sub_n_5(block, context, location, &r5, &n_limbs)?;
    let r_after_second =
        append_conditional_sub_n_5(block, context, location, &r_after_first, &n_limbs)?;
    Ok([
        r_after_second[0],
        r_after_second[1],
        r_after_second[2],
        r_after_second[3],
    ])
}

fn append_call_mul_mod_helper<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c LlzkContext,
    location: Location<'c>,
    helper_name: &str,
    lhs: &[Value<'c, 'a>; LIMBS],
    rhs: &[Value<'c, 'a>; LIMBS],
) -> Result<[Value<'c, 'a>; LIMBS], Error> {
    let felt = felt_type(context);
    let args = [
        lhs[0], lhs[1], lhs[2], lhs[3], rhs[0], rhs[1], rhs[2], rhs[3],
    ];
    let call = block.append_operation(
        dialect::function::call(
            &OpBuilder::new(context, block.at_end()),
            location,
            FlatSymbolRefAttribute::new(context, helper_name),
            &args,
            &[felt; LIMBS],
        )?
        .into(),
    );
    Ok([
        call.result(0)?.into(),
        call.result(1)?.into(),
        call.result(2)?.into(),
        call.result(3)?.into(),
    ])
}

/// Toplevel-helper symbol name for the given modulus, or `None` if the
/// caller should fall back to inlining Barrett.
fn mul_mod_helper_name_for(modulus: &[u64; LIMBS]) -> Option<&'static str> {
    if modulus == &SECP256K1_N {
        Some(ECDSA_SECP256K1_MUL_MOD_N_HELPER_NAME)
    } else if modulus == &SECP256R1_N {
        Some(ECDSA_SECP256R1_MUL_MOD_N_HELPER_NAME)
    } else if modulus == &SECP256K1_P {
        Some(ECDSA_SECP256K1_MUL_MOD_P_HELPER_NAME)
    } else if modulus == &SECP256R1_P {
        Some(ECDSA_SECP256R1_MUL_MOD_P_HELPER_NAME)
    } else {
        None
    }
}

fn append_mul_mod_n_helper_call<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c LlzkContext,
    location: Location<'c>,
    lhs: &[Value<'c, 'a>; LIMBS],
    rhs: &[Value<'c, 'a>; LIMBS],
    n: &[u64; LIMBS],
) -> Result<[Value<'c, 'a>; LIMBS], Error> {
    if let Some(name) = mul_mod_helper_name_for(n) {
        append_call_mul_mod_helper(block, context, location, name, lhs, rhs)
    } else {
        append_mul_mod_n_barrett(block, context, location, lhs, rhs, n)
    }
}

fn emit_mul_mod_n_helper_for<'c, C: Curve>(
    context: &'c LlzkContext,
) -> Result<FuncDefOp<'c>, Error> {
    emit_two_in_one_out_helper(context, C::MUL_MOD_N_NAME, |block, ctx, loc, lhs, rhs| {
        append_mul_mod_n_barrett(block, ctx, loc, lhs, rhs, &C::N)
    })
}

fn emit_mul_mod_p_helper_for<'c, C: Curve>(
    context: &'c LlzkContext,
) -> Result<FuncDefOp<'c>, Error> {
    emit_two_in_one_out_helper(context, C::MUL_MOD_P_NAME, C::append_mul_mod_p_inline)
}

fn emit_inv_mod_helper_for<'c>(
    context: &'c LlzkContext,
    helper_name: &str,
    modulus: &[u64; LIMBS],
) -> Result<FuncDefOp<'c>, Error> {
    emit_one_in_one_out_helper(context, helper_name, |block, ctx, loc, a| {
        append_inv_mod_n_barrett(block, ctx, loc, a, modulus)
    })
}

fn emit_two_in_one_out_helper<'c, F>(
    context: &'c LlzkContext,
    helper_name: &str,
    body: F,
) -> Result<FuncDefOp<'c>, Error>
where
    F: for<'a> FnOnce(
        &'a Block<'c>,
        &'c LlzkContext,
        Location<'c>,
        &[Value<'c, 'a>; LIMBS],
        &[Value<'c, 'a>; LIMBS],
    ) -> Result<[Value<'c, 'a>; LIMBS], Error>,
{
    let location = Location::unknown(context);
    let felt = felt_type(context);
    let inputs = vec![(felt, location); 2 * LIMBS];
    let input_types = vec![felt; 2 * LIMBS];
    let output_types = vec![felt; LIMBS];
    let function_type = FunctionType::new(context, &input_types, &output_types);
    let function = dialect::function::def(location, helper_name, function_type, &[], None)?;
    function.set_allow_non_native_field_ops_attr(true);

    let block = Block::new(&inputs);
    let lhs: [Value; LIMBS] = block_args::<LIMBS>(&block, 0)?;
    let rhs: [Value; LIMBS] = block_args::<LIMBS>(&block, LIMBS)?;
    let result = body(&block, context, location, &lhs, &rhs)?;
    block.append_operation(dialect::function::r#return(location, &result));
    function.region(0)?.append_block(block);
    Ok(function)
}

fn emit_one_in_one_out_helper<'c, F>(
    context: &'c LlzkContext,
    helper_name: &str,
    body: F,
) -> Result<FuncDefOp<'c>, Error>
where
    F: for<'a> FnOnce(
        &'a Block<'c>,
        &'c LlzkContext,
        Location<'c>,
        &[Value<'c, 'a>; LIMBS],
    ) -> Result<[Value<'c, 'a>; LIMBS], Error>,
{
    let location = Location::unknown(context);
    let felt = felt_type(context);
    let inputs = vec![(felt, location); LIMBS];
    let input_types = vec![felt; LIMBS];
    let output_types = vec![felt; LIMBS];
    let function_type = FunctionType::new(context, &input_types, &output_types);
    let function = dialect::function::def(location, helper_name, function_type, &[], None)?;
    function.set_allow_non_native_field_ops_attr(true);

    let block = Block::new(&inputs);
    let a: [Value; LIMBS] = block_args::<LIMBS>(&block, 0)?;
    let result = body(&block, context, location, &a)?;
    block.append_operation(dialect::function::r#return(location, &result));
    function.region(0)?.append_block(block);
    Ok(function)
}

// ── Public wrappers used by the blackbox registry ────────────────────────

pub(crate) fn emit_secp256k1_mul_mod_n_helper<'c>(
    context: &'c LlzkContext,
) -> Result<FuncDefOp<'c>, Error> {
    emit_mul_mod_n_helper_for::<Secp256k1>(context)
}

pub(crate) fn emit_secp256r1_mul_mod_n_helper<'c>(
    context: &'c LlzkContext,
) -> Result<FuncDefOp<'c>, Error> {
    emit_mul_mod_n_helper_for::<Secp256r1>(context)
}

pub(crate) fn emit_secp256k1_mul_mod_p_helper<'c>(
    context: &'c LlzkContext,
) -> Result<FuncDefOp<'c>, Error> {
    emit_mul_mod_p_helper_for::<Secp256k1>(context)
}

pub(crate) fn emit_secp256r1_mul_mod_p_helper<'c>(
    context: &'c LlzkContext,
) -> Result<FuncDefOp<'c>, Error> {
    emit_mul_mod_p_helper_for::<Secp256r1>(context)
}

pub(crate) fn emit_secp256k1_inv_mod_n_helper<'c>(
    context: &'c LlzkContext,
) -> Result<FuncDefOp<'c>, Error> {
    emit_inv_mod_helper_for(context, ECDSA_SECP256K1_INV_MOD_N_HELPER_NAME, &SECP256K1_N)
}

pub(crate) fn emit_secp256r1_inv_mod_n_helper<'c>(
    context: &'c LlzkContext,
) -> Result<FuncDefOp<'c>, Error> {
    emit_inv_mod_helper_for(context, ECDSA_SECP256R1_INV_MOD_N_HELPER_NAME, &SECP256R1_N)
}

pub(crate) fn emit_secp256k1_inv_mod_p_helper<'c>(
    context: &'c LlzkContext,
) -> Result<FuncDefOp<'c>, Error> {
    emit_inv_mod_helper_for(context, ECDSA_SECP256K1_INV_MOD_P_HELPER_NAME, &SECP256K1_P)
}

pub(crate) fn emit_secp256r1_inv_mod_p_helper<'c>(
    context: &'c LlzkContext,
) -> Result<FuncDefOp<'c>, Error> {
    emit_inv_mod_helper_for(context, ECDSA_SECP256R1_INV_MOD_P_HELPER_NAME, &SECP256R1_P)
}

fn append_call_inv_mod_helper<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c LlzkContext,
    location: Location<'c>,
    helper_name: &str,
    a: &[Value<'c, 'a>; LIMBS],
) -> Result<[Value<'c, 'a>; LIMBS], Error> {
    let felt = felt_type(context);
    let args = [a[0], a[1], a[2], a[3]];
    let call = block.append_operation(
        dialect::function::call(
            &OpBuilder::new(context, block.at_end()),
            location,
            FlatSymbolRefAttribute::new(context, helper_name),
            &args,
            &[felt; LIMBS],
        )?
        .into(),
    );
    Ok([
        call.result(0)?.into(),
        call.result(1)?.into(),
        call.result(2)?.into(),
        call.result(3)?.into(),
    ])
}

/// Inputs and output are in `[0, n)`.
pub(super) fn append_add_mod_n<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    a: &[Value<'c, 'a>; LIMBS],
    b: &[Value<'c, 'a>; LIMBS],
    n: &[u64; LIMBS],
) -> Result<[Value<'c, 'a>; LIMBS], Error> {
    let zero = append_felt_constant(block, context, location, &FieldElement::zero())?;
    let n_limbs = pack_const_limbs(block, context, location, n)?;
    let (sum, carry) = append_limbs_add_with_carry(block, context, location, a, b, zero)?;
    let sum_5: [Value<'c, 'a>; LIMBS + 1] = [sum[0], sum[1], sum[2], sum[3], carry];
    // sum < 2n, so a single conditional subtract suffices.
    let r = append_conditional_sub_n_5(block, context, location, &sum_5, &n_limbs)?;
    Ok([r[0], r[1], r[2], r[3]])
}

/// Inputs and output are in `[0, n)`.
pub(super) fn append_sub_mod_n<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    a: &[Value<'c, 'a>; LIMBS],
    b: &[Value<'c, 'a>; LIMBS],
    n: &[u64; LIMBS],
) -> Result<[Value<'c, 'a>; LIMBS], Error> {
    let zero = append_felt_constant(block, context, location, &FieldElement::zero())?;
    let n_limbs = pack_const_limbs(block, context, location, n)?;
    // borrow == 1 means a - b wrapped; add n back.
    let (diff, borrow) = append_limbs_sub_with_borrow(block, context, location, a, b, zero)?;
    let (diff_plus_n, _) =
        append_limbs_add_with_carry(block, context, location, &diff, &n_limbs, zero)?;
    append_select_limbs(block, context, location, borrow, &diff_plus_n, &diff)
}

pub(super) fn append_mul_p<'c, 'a, C: Curve>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    a: &[Value<'c, 'a>; LIMBS],
    b: &[Value<'c, 'a>; LIMBS],
) -> Result<[Value<'c, 'a>; LIMBS], Error> {
    append_call_mul_mod_helper(block, context, location, C::MUL_MOD_P_NAME, a, b)
}

pub(super) fn append_mul_n<'c, 'a, C: Curve>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    a: &[Value<'c, 'a>; LIMBS],
    b: &[Value<'c, 'a>; LIMBS],
) -> Result<[Value<'c, 'a>; LIMBS], Error> {
    append_call_mul_mod_helper(block, context, location, C::MUL_MOD_N_NAME, a, b)
}

pub(super) fn append_inv_p<'c, 'a, C: Curve>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    a: &[Value<'c, 'a>; LIMBS],
) -> Result<[Value<'c, 'a>; LIMBS], Error> {
    append_call_inv_mod_helper(block, context, location, C::INV_MOD_P_NAME, a)
}

pub(super) fn append_inv_n<'c, 'a, C: Curve>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    a: &[Value<'c, 'a>; LIMBS],
) -> Result<[Value<'c, 'a>; LIMBS], Error> {
    append_call_inv_mod_helper(block, context, location, C::INV_MOD_N_NAME, a)
}

pub(super) fn append_add_p<'c, 'a, C: Curve>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    a: &[Value<'c, 'a>; LIMBS],
    b: &[Value<'c, 'a>; LIMBS],
) -> Result<[Value<'c, 'a>; LIMBS], Error> {
    append_add_mod_n(block, context, location, a, b, &C::P)
}

pub(super) fn append_sub_p<'c, 'a, C: Curve>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    a: &[Value<'c, 'a>; LIMBS],
    b: &[Value<'c, 'a>; LIMBS],
) -> Result<[Value<'c, 'a>; LIMBS], Error> {
    append_sub_mod_n(block, context, location, a, b, &C::P)
}

pub(super) fn append_dbl_p<'c, 'a, C: Curve>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    a: &[Value<'c, 'a>; LIMBS],
) -> Result<[Value<'c, 'a>; LIMBS], Error> {
    append_add_mod_n(block, context, location, a, a, &C::P)
}

/// Deterministic `a^(n-2) mod n` for a generic 256-bit modulus `n` via
/// Fermat's little theorem and square-and-multiply (binary exponent, MSB
/// first). Uses Barrett `mul_mod_n` internally.
pub(super) fn append_inv_mod_n_barrett<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    a: &[Value<'c, 'a>; LIMBS],
    n: &[u64; LIMBS],
) -> Result<[Value<'c, 'a>; LIMBS], Error> {
    use num_bigint::BigUint;
    let n_big: BigUint = (0..LIMBS).fold(BigUint::from(0u32), |acc, i| {
        acc | (BigUint::from(n[i]) << (64 * i))
    });
    let exponent = &n_big - 2u32;
    let high_bit = exponent.bits().saturating_sub(1) as u32;

    let mut result = pack_const_limbs(block, context, location, &[1, 0, 0, 0])?;

    // Square-and-multiply MSB-first. Each mul goes through the helper dispatch
    // so known curves emit a `function.call` instead of inlining Barrett.
    for bit_idx in (0..=high_bit).rev() {
        result = append_mul_mod_n_helper_call(block, context, location, &result, &result, n)?;
        if exponent.bit(bit_idx as u64) {
            result = append_mul_mod_n_helper_call(block, context, location, &result, a, n)?;
        }
    }
    Ok(result)
}

/// `r >= n ? r - n : r`, where `r` is 5-limb and `n` is 4-limb (implicit zero
/// top limb). Returns the 5-limb result; the caller is responsible for
/// dropping the now-known-zero top limb after enough iterations.
fn append_conditional_sub_n_5<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    r: &[Value<'c, 'a>; LIMBS + 1],
    n_limbs: &[Value<'c, 'a>; LIMBS],
) -> Result<[Value<'c, 'a>; LIMBS + 1], Error> {
    let one = append_felt_constant(block, context, location, &FieldElement::one())?;
    let zero = append_felt_constant(block, context, location, &FieldElement::zero())?;

    let r4_is_zero_i1 = append_op_with_result(block, dialect::bool::eq(location, r[4], zero)?)?;
    let felt_ty = FeltType::with_field(context, FIELD_NAME);
    let r4_is_zero = append_op_with_result(
        block,
        dialect::cast::tofelt(location, r4_is_zero_i1, Some(felt_ty)),
    )?;
    let r4_is_nonzero = append_not_bit(block, context, location, r4_is_zero)?;

    let r_low: [Value<'c, 'a>; LIMBS] = [r[0], r[1], r[2], r[3]];
    let r_low_lt_n = append_limbs_lt_bool(block, context, location, &r_low, n_limbs)?;
    let r_low_ge_n = append_not_bit(block, context, location, r_low_lt_n)?;

    // need_sub = r4_is_nonzero OR r_low_ge_n = a + b - a*b (both are 0/1).
    let prod = append_op_with_result(
        block,
        dialect::felt::mul(location, r4_is_nonzero, r_low_ge_n)?,
    )?;
    let sum = append_op_with_result(
        block,
        dialect::felt::add(location, r4_is_nonzero, r_low_ge_n)?,
    )?;
    let neg_prod = append_op_with_result(block, dialect::felt::neg(location, prod)?)?;
    let need_sub = append_op_with_result(block, dialect::felt::add(location, sum, neg_prod)?)?;

    let (sub_low, borrow) =
        append_limbs_sub_with_borrow(block, context, location, &r_low, n_limbs, zero)?;
    let neg_borrow = append_op_with_result(block, dialect::felt::neg(location, borrow)?)?;
    let sub_high = append_op_with_result(block, dialect::felt::add(location, r[4], neg_borrow)?)?;

    let r_low_orig: [Value<'c, 'a>; LIMBS] = [r[0], r[1], r[2], r[3]];
    let low_result =
        append_select_limbs(block, context, location, need_sub, &sub_low, &r_low_orig)?;
    let neg_need = append_op_with_result(block, dialect::felt::neg(location, need_sub)?)?;
    let one_minus_need =
        append_op_with_result(block, dialect::felt::add(location, one, neg_need)?)?;
    let from_sub_high =
        append_op_with_result(block, dialect::felt::mul(location, need_sub, sub_high)?)?;
    let from_orig_high =
        append_op_with_result(block, dialect::felt::mul(location, one_minus_need, r[4])?)?;
    let high_result = append_op_with_result(
        block,
        dialect::felt::add(location, from_sub_high, from_orig_high)?,
    )?;
    Ok([
        low_result[0],
        low_result[1],
        low_result[2],
        low_result[3],
        high_result,
    ])
}
