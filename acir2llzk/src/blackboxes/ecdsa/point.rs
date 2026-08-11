use acir::{AcirField, FieldElement};
use llzk::{
    builder::{OpBuilder, OpBuilderLike as _},
    dialect::llzk::LoopBoundsAttribute,
    prelude::{
        Block, BlockLike, LlzkContext, Location, OperationMutLike, OperationRef, Region,
        RegionLike, Type, Value,
        dialect::{bool, felt},
        melior_dialects::scf,
    },
};

use crate::{common::as_value, error::Error, multiprec::LIMBS};

use super::{
    curve::Curve,
    limbs::{append_felt_constant, append_limbs_eq_bool, append_not_bit, append_select_limbs},
    modular::{
        append_add_p, append_dbl_p, append_inv_p, append_mul_p, append_sub_p, pack_const_limbs,
    },
};

/// secp256k1 point in Jacobian coordinates: `(X, Y, Z)` where the affine
/// equivalent is `(X / Z^2, Y / Z^3)`. The identity (point at infinity) is
/// represented as `Z == 0`.
pub(super) type JacobianPoint<'c, 'a> = (
    [Value<'c, 'a>; LIMBS],
    [Value<'c, 'a>; LIMBS],
    [Value<'c, 'a>; LIMBS],
);

/// Jacobian point doubling for curves with `a = 0` (secp256k1):
///
/// ```text
/// A  = Y1^2
/// B  = 4 * X1 * A
/// C  = 8 * A^2
/// D  = 3 * X1^2          (uses a = 0)
/// X3 = D^2 - 2B
/// Y3 = D*(B - X3) - C
/// Z3 = 2*Y1*Z1
/// ```
///
/// `Z1 = 0` propagates: `Z3 = 2*Y*0 = 0`, so the identity stays the identity.
pub(super) fn append_point_double_a_zero<'c: 'a, 'a, C: Curve>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    p: &JacobianPoint<'c, 'a>,
) -> Result<JacobianPoint<'c, 'a>, Error> {
    let (x1, y1, z1) = p;
    let a_val = append_mul_p::<C>(builder, context, location, y1, y1)?;
    let x_a = append_mul_p::<C>(builder, context, location, x1, &a_val)?;
    let x_a2 = append_dbl_p::<C>(builder, context, location, &x_a)?;
    let b_val = append_dbl_p::<C>(builder, context, location, &x_a2)?;
    let a_sq = append_mul_p::<C>(builder, context, location, &a_val, &a_val)?;
    let a_sq_2 = append_dbl_p::<C>(builder, context, location, &a_sq)?;
    let a_sq_4 = append_dbl_p::<C>(builder, context, location, &a_sq_2)?;
    let c_val = append_dbl_p::<C>(builder, context, location, &a_sq_4)?;
    let x1_sq = append_mul_p::<C>(builder, context, location, x1, x1)?;
    let x1_sq_2 = append_dbl_p::<C>(builder, context, location, &x1_sq)?;
    let d_val = append_add_p::<C>(builder, context, location, &x1_sq_2, &x1_sq)?;
    let d_sq = append_mul_p::<C>(builder, context, location, &d_val, &d_val)?;
    let two_b = append_dbl_p::<C>(builder, context, location, &b_val)?;
    let x3 = append_sub_p::<C>(builder, context, location, &d_sq, &two_b)?;
    let b_minus_x3 = append_sub_p::<C>(builder, context, location, &b_val, &x3)?;
    let d_times_diff = append_mul_p::<C>(builder, context, location, &d_val, &b_minus_x3)?;
    let y3 = append_sub_p::<C>(builder, context, location, &d_times_diff, &c_val)?;
    let y_z = append_mul_p::<C>(builder, context, location, y1, z1)?;
    let z3 = append_dbl_p::<C>(builder, context, location, &y_z)?;
    Ok((x3, y3, z3))
}

/// Jacobian point doubling for curves with `a = -3` (secp256r1):
///
/// ```text
/// delta = Z1^2
/// gamma = Y1^2
/// beta  = X1 * gamma
/// alpha = 3 * (X1 - delta) * (X1 + delta)   (uses a = -3)
/// X3    = alpha^2 - 8*beta
/// Z3    = (Y1 + Z1)^2 - gamma - delta       (= 2*Y1*Z1)
/// Y3    = alpha*(4*beta - X3) - 8*gamma^2
/// ```
pub(super) fn append_point_double_a_neg_3<'c: 'a, 'a, C: Curve>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    p: &JacobianPoint<'c, 'a>,
) -> Result<JacobianPoint<'c, 'a>, Error> {
    let (x1, y1, z1) = p;
    let delta = append_mul_p::<C>(builder, context, location, z1, z1)?;
    let gamma = append_mul_p::<C>(builder, context, location, y1, y1)?;
    let beta = append_mul_p::<C>(builder, context, location, x1, &gamma)?;
    let x_minus_delta = append_sub_p::<C>(builder, context, location, x1, &delta)?;
    let x_plus_delta = append_add_p::<C>(builder, context, location, x1, &delta)?;
    let diff_prod = append_mul_p::<C>(builder, context, location, &x_minus_delta, &x_plus_delta)?;
    let two_diff = append_dbl_p::<C>(builder, context, location, &diff_prod)?;
    let alpha = append_add_p::<C>(builder, context, location, &two_diff, &diff_prod)?;
    let alpha_sq = append_mul_p::<C>(builder, context, location, &alpha, &alpha)?;
    let beta_2 = append_dbl_p::<C>(builder, context, location, &beta)?;
    let beta_4 = append_dbl_p::<C>(builder, context, location, &beta_2)?;
    let beta_8 = append_dbl_p::<C>(builder, context, location, &beta_4)?;
    let x3 = append_sub_p::<C>(builder, context, location, &alpha_sq, &beta_8)?;
    let y_plus_z = append_add_p::<C>(builder, context, location, y1, z1)?;
    let yz_sq = append_mul_p::<C>(builder, context, location, &y_plus_z, &y_plus_z)?;
    let yz_minus_gamma = append_sub_p::<C>(builder, context, location, &yz_sq, &gamma)?;
    let z3 = append_sub_p::<C>(builder, context, location, &yz_minus_gamma, &delta)?;
    let gamma_sq = append_mul_p::<C>(builder, context, location, &gamma, &gamma)?;
    let gamma_sq_2 = append_dbl_p::<C>(builder, context, location, &gamma_sq)?;
    let gamma_sq_4 = append_dbl_p::<C>(builder, context, location, &gamma_sq_2)?;
    let gamma_sq_8 = append_dbl_p::<C>(builder, context, location, &gamma_sq_4)?;
    let four_beta_minus_x3 = append_sub_p::<C>(builder, context, location, &beta_4, &x3)?;
    let alpha_times = append_mul_p::<C>(builder, context, location, &alpha, &four_beta_minus_x3)?;
    let y3 = append_sub_p::<C>(builder, context, location, &alpha_times, &gamma_sq_8)?;
    Ok((x3, y3, z3))
}

/// Returns the regular-formula result plus `same_x = X1 == x2·Z1²` and
/// `same_y = Y1 == y2·Z1³`, which the complete wrapper uses to dispatch
/// the degenerate cases.
fn append_point_add_mixed_regular_with_flags<'c: 'a, 'a, C: Curve>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    p1: &JacobianPoint<'c, 'a>,
    q: &([Value<'c, 'a>; LIMBS], [Value<'c, 'a>; LIMBS]),
) -> Result<(JacobianPoint<'c, 'a>, Value<'c, 'a>, Value<'c, 'a>), Error> {
    let (x1, y1, z1) = p1;
    let (x2, y2) = q;
    let zero_limbs = pack_const_limbs(builder, context, location, &[0, 0, 0, 0])?;
    let z1z1 = append_mul_p::<C>(builder, context, location, z1, z1)?;
    let u2 = append_mul_p::<C>(builder, context, location, x2, &z1z1)?;
    let y2_z1 = append_mul_p::<C>(builder, context, location, y2, z1)?;
    let s2 = append_mul_p::<C>(builder, context, location, &y2_z1, &z1z1)?;
    let h = append_sub_p::<C>(builder, context, location, &u2, x1)?;
    let same_x = append_limbs_eq_bool(builder, context, location, &h, &zero_limbs)?;
    let hh = append_mul_p::<C>(builder, context, location, &h, &h)?;
    let hh2 = append_dbl_p::<C>(builder, context, location, &hh)?;
    let i = append_dbl_p::<C>(builder, context, location, &hh2)?;
    let j = append_mul_p::<C>(builder, context, location, &h, &i)?;
    let s2_minus_y1 = append_sub_p::<C>(builder, context, location, &s2, y1)?;
    let same_y = append_limbs_eq_bool(builder, context, location, &s2_minus_y1, &zero_limbs)?;
    let r = append_dbl_p::<C>(builder, context, location, &s2_minus_y1)?;
    let v = append_mul_p::<C>(builder, context, location, x1, &i)?;
    let r_sq = append_mul_p::<C>(builder, context, location, &r, &r)?;
    let two_v = append_dbl_p::<C>(builder, context, location, &v)?;
    let r_sq_minus_j = append_sub_p::<C>(builder, context, location, &r_sq, &j)?;
    let x3 = append_sub_p::<C>(builder, context, location, &r_sq_minus_j, &two_v)?;
    let v_minus_x3 = append_sub_p::<C>(builder, context, location, &v, &x3)?;
    let r_times_diff = append_mul_p::<C>(builder, context, location, &r, &v_minus_x3)?;
    let y1_j = append_mul_p::<C>(builder, context, location, y1, &j)?;
    let two_y1_j = append_dbl_p::<C>(builder, context, location, &y1_j)?;
    let y3 = append_sub_p::<C>(builder, context, location, &r_times_diff, &two_y1_j)?;
    let z1_plus_h = append_add_p::<C>(builder, context, location, z1, &h)?;
    let z1ph_sq = append_mul_p::<C>(builder, context, location, &z1_plus_h, &z1_plus_h)?;
    let z1ph_sq_minus_z1z1 = append_sub_p::<C>(builder, context, location, &z1ph_sq, &z1z1)?;
    let z3 = append_sub_p::<C>(builder, context, location, &z1ph_sq_minus_z1z1, &hh)?;
    Ok(((x3, y3, z3), same_x, same_y))
}

/// Complete mixed Jacobian + affine addition. Handles:
/// - `p1 = O`
/// - `q = O` (communicated separately because affine points have no infinity bit)
/// - `p1 = q`
/// - `p1 = -q`
pub(super) fn append_point_add_mixed_complete<'c: 'a, 'a, C: Curve>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    p1: &JacobianPoint<'c, 'a>,
    q: &([Value<'c, 'a>; LIMBS], [Value<'c, 'a>; LIMBS]),
    q_is_infinity: Value<'c, 'a>,
) -> Result<JacobianPoint<'c, 'a>, Error> {
    let zero_limbs = pack_const_limbs(builder, context, location, &[0, 0, 0, 0])?;
    let one_limbs = pack_const_limbs(builder, context, location, &[1, 0, 0, 0])?;
    let infinity: JacobianPoint<'c, 'a> = (zero_limbs, zero_limbs, zero_limbs);

    let (regular, same_x, same_y) =
        append_point_add_mixed_regular_with_flags::<C>(builder, context, location, p1, q)?;
    let doubled = C::append_point_double(builder, context, location, p1)?;

    let p1_is_infinity = append_limbs_eq_bool(builder, context, location, &p1.2, &zero_limbs)?;
    let same_point = as_value(felt::mul(builder, location, same_x, same_y)?)?;
    let not_same_y = append_not_bit(builder, context, location, same_y)?;
    let inverse_point = as_value(felt::mul(builder, location, same_x, not_same_y)?)?;

    let after_inverse = append_select_jacobian(
        builder,
        context,
        location,
        inverse_point,
        &infinity,
        &regular,
    )?;
    let after_double = append_select_jacobian(
        builder,
        context,
        location,
        same_point,
        &doubled,
        &after_inverse,
    )?;
    let after_q_infinity =
        append_select_jacobian(builder, context, location, q_is_infinity, p1, &after_double)?;

    let q_as_jac: JacobianPoint<'c, 'a> = (q.0, q.1, one_limbs);
    let q_or_infinity = append_select_jacobian(
        builder,
        context,
        location,
        q_is_infinity,
        &infinity,
        &q_as_jac,
    )?;
    append_select_jacobian(
        builder,
        context,
        location,
        p1_is_infinity,
        &q_or_infinity,
        &after_q_infinity,
    )
}

fn append_select_jacobian<'c: 'a, 'a>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    bit: Value<'c, 'a>,
    if_one: &JacobianPoint<'c, 'a>,
    if_zero: &JacobianPoint<'c, 'a>,
) -> Result<JacobianPoint<'c, 'a>, Error> {
    Ok((
        append_select_limbs(builder, context, location, bit, &if_one.0, &if_zero.0)?,
        append_select_limbs(builder, context, location, bit, &if_one.1, &if_zero.1)?,
        append_select_limbs(builder, context, location, bit, &if_one.2, &if_zero.2)?,
    ))
}

/// `mask` is a runtime power-of-two; the surrounding loop guarantees `mask != 0`.
fn append_extract_masked_bit<'c: 'a, 'a>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    limb: Value<'c, 'a>,
    mask: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    let shifted = as_value(felt::uintdiv(builder, location, limb, mask)?)?;
    let two = append_felt_constant(builder, context, location, &FieldElement::from(2u128))?;
    as_value(felt::umod(builder, location, shifted, two)?)
}

/// The `(0, 0)` slot can be a don't-care if the caller knows it's unused —
/// the joint scalar mul exploits this by skipping the add when both bits are 0.
#[allow(clippy::too_many_arguments)]
fn append_select_affine_2x2<'c: 'a, 'a>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    b1: Value<'c, 'a>,
    b2: Value<'c, 'a>,
    t_00: &([Value<'c, 'a>; LIMBS], [Value<'c, 'a>; LIMBS]),
    t_10: &([Value<'c, 'a>; LIMBS], [Value<'c, 'a>; LIMBS]),
    t_01: &([Value<'c, 'a>; LIMBS], [Value<'c, 'a>; LIMBS]),
    t_11: &([Value<'c, 'a>; LIMBS], [Value<'c, 'a>; LIMBS]),
) -> Result<([Value<'c, 'a>; LIMBS], [Value<'c, 'a>; LIMBS]), Error> {
    // First collapse the b1 axis: pick {t_00, t_10} → row0, {t_01, t_11} → row1.
    let row0_x = append_select_limbs(builder, context, location, b1, &t_10.0, &t_00.0)?;
    let row0_y = append_select_limbs(builder, context, location, b1, &t_10.1, &t_00.1)?;
    let row1_x = append_select_limbs(builder, context, location, b1, &t_11.0, &t_01.0)?;
    let row1_y = append_select_limbs(builder, context, location, b1, &t_11.1, &t_01.1)?;
    // Then collapse the b2 axis.
    let x = append_select_limbs(builder, context, location, b2, &row1_x, &row0_x)?;
    let y = append_select_limbs(builder, context, location, b2, &row1_y, &row0_y)?;
    Ok((x, y))
}

fn append_loop_values<'c, 'a>(
    mask: Value<'c, 'a>,
    acc: &JacobianPoint<'c, 'a>,
) -> Vec<Value<'c, 'a>> {
    let mut values = Vec::with_capacity(1 + 3 * LIMBS);
    values.push(mask);
    values.extend(acc.0);
    values.extend(acc.1);
    values.extend(acc.2);
    values
}

fn read_loop_limbs<'c, 'a>(
    block: &'a Block<'c>,
    offset: usize,
) -> Result<[Value<'c, 'a>; LIMBS], Error> {
    Ok([
        block.argument(offset)?.into(),
        block.argument(offset + 1)?.into(),
        block.argument(offset + 2)?.into(),
        block.argument(offset + 3)?.into(),
    ])
}

fn read_loop_jacobian<'c, 'a>(
    block: &'a Block<'c>,
    offset: usize,
) -> Result<JacobianPoint<'c, 'a>, Error> {
    Ok((
        read_loop_limbs(block, offset)?,
        read_loop_limbs(block, offset + LIMBS)?,
        read_loop_limbs(block, offset + 2 * LIMBS)?,
    ))
}

fn collect_loop_jacobian<'c, 'a>(op: OperationRef<'c, 'a>) -> Result<JacobianPoint<'c, 'a>, Error> {
    let read = |offset: usize| -> Result<[Value<'c, 'a>; LIMBS], Error> {
        Ok([
            op.result(offset)?.into(),
            op.result(offset + 1)?.into(),
            op.result(offset + 2)?.into(),
            op.result(offset + 3)?.into(),
        ])
    };
    Ok((read(1)?, read(1 + LIMBS)?, read(1 + 2 * LIMBS)?))
}

#[allow(clippy::too_many_arguments)]
fn append_joint_scalar_mul_limb_loop<'c: 'a, 'a, C: Curve>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    acc: &JacobianPoint<'c, 'a>,
    g: &([Value<'c, 'a>; LIMBS], [Value<'c, 'a>; LIMBS]),
    p: &([Value<'c, 'a>; LIMBS], [Value<'c, 'a>; LIMBS]),
    g_plus_p: &([Value<'c, 'a>; LIMBS], [Value<'c, 'a>; LIMBS]),
    g_plus_p_is_infinity: Value<'c, 'a>,
    u1_limb: Value<'c, 'a>,
    u2_limb: Value<'c, 'a>,
) -> Result<JacobianPoint<'c, 'a>, Error> {
    let felt_ty = Type::from(context.felt_type());
    let loop_arg_types = vec![(felt_ty, location); 1 + 3 * LIMBS];
    let loop_result_types = vec![felt_ty; 1 + 3 * LIMBS];

    let before_region = {
        let before_region = Region::new();
        let before_block = before_region.append_block(Block::new(&loop_arg_types));
        let builder = OpBuilder::at_block_end(context, before_block);
        let mask_before: Value = before_block.argument(0)?.into();
        let acc_before = read_loop_jacobian(&before_block, 1)?;
        let zero = append_felt_constant(&builder, context, location, &FieldElement::zero())?;
        let keep_going = as_value(bool::gt(&builder, location, mask_before, zero)?)?;
        let before_values = append_loop_values(mask_before, &acc_before);
        before_block.append_operation(scf::condition(keep_going, &before_values, location));
        before_region
    };

    let after_region = {
        let after_region = Region::new();
        let after_block = after_region.append_block(Block::new(&loop_arg_types));
        let builder = OpBuilder::at_block_end(context, after_block);
        let mask_after: Value = after_block.argument(0)?.into();
        let acc_after = read_loop_jacobian(&after_block, 1)?;

        let zero_limbs = pack_const_limbs(&builder, context, location, &[0, 0, 0, 0])?;
        let one_limbs = pack_const_limbs(&builder, context, location, &[1, 0, 0, 0])?;
        let one = append_felt_constant(&builder, context, location, &FieldElement::one())?;
        let two = append_felt_constant(&builder, context, location, &FieldElement::from(2u128))?;

        let acc_doubled = C::append_point_double(&builder, context, location, &acc_after)?;

        let b1 = append_extract_masked_bit(&builder, context, location, u1_limb, mask_after)?;
        let b2 = append_extract_masked_bit(&builder, context, location, u2_limb, mask_after)?;

        let t_selected =
            append_select_affine_2x2(&builder, context, location, b1, b2, g, g, p, g_plus_p)?;

        let both_bits = as_value(felt::mul(&builder, location, b1, b2)?)?;
        let selected_is_infinity = as_value(felt::mul(
            &builder,
            location,
            both_bits,
            g_plus_p_is_infinity,
        )?)?;

        let add_result = append_point_add_mixed_complete::<C>(
            &builder,
            context,
            location,
            &acc_doubled,
            &t_selected,
            selected_is_infinity,
        )?;

        let acc_z_eq_zero =
            append_limbs_eq_bool(&builder, context, location, &acc_doubled.2, &zero_limbs)?;
        let t_as_jac: JacobianPoint = (t_selected.0, t_selected.1, one_limbs);
        let post_add = append_select_jacobian(
            &builder,
            context,
            location,
            acc_z_eq_zero,
            &t_as_jac,
            &add_result,
        )?;

        // skip_add = (1-b1) * (1-b2).
        let neg_b1 = as_value(felt::neg(&builder, location, b1)?)?;
        let neg_b2 = as_value(felt::neg(&builder, location, b2)?)?;
        let one_minus_b1 = as_value(felt::add(&builder, location, one, neg_b1)?)?;
        let one_minus_b2 = as_value(felt::add(&builder, location, one, neg_b2)?)?;
        let skip_add = as_value(felt::mul(&builder, location, one_minus_b1, one_minus_b2)?)?;
        let next_acc = append_select_jacobian(
            &builder,
            context,
            location,
            skip_add,
            &acc_doubled,
            &post_add,
        )?;
        let next_mask = as_value(felt::uintdiv(&builder, location, mask_after, two)?)?;
        let after_values = append_loop_values(next_mask, &next_acc);
        after_block.append_operation(scf::r#yield(&after_values, location));
        after_region
    };

    let mask = append_felt_constant(builder, context, location, &FieldElement::from(1u128 << 63))?;
    let initial_values = append_loop_values(mask, acc);
    let loop_op = builder.insert(location, |_, location| {
        let mut while_op = scf::r#while(
            &initial_values,
            &loop_result_types,
            before_region,
            after_region,
            location,
        );
        while_op.set_attribute(
            "llzk.loopbounds",
            LoopBoundsAttribute::new(context, 0, 64, 1).into(),
        );
        while_op
    });
    let result = collect_loop_jacobian(loop_op)?;

    Ok(result)
}

/// Joint scalar mul `u1·G + u2·P` via Shamir's trick, returning affine
/// `(R_x, R_y, is_infinity)`.
///
/// `g_plus_p` is precomputed by the caller because building it inline would
/// cost another inversion; `g_plus_p_is_infinity` flags the `G = -P` case.
#[allow(clippy::too_many_arguments)]
pub(super) fn append_joint_scalar_mul<'c: 'a, 'a, C: Curve>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    g: &([Value<'c, 'a>; LIMBS], [Value<'c, 'a>; LIMBS]),
    p: &([Value<'c, 'a>; LIMBS], [Value<'c, 'a>; LIMBS]),
    g_plus_p: &([Value<'c, 'a>; LIMBS], [Value<'c, 'a>; LIMBS]),
    g_plus_p_is_infinity: Value<'c, 'a>,
    u1: &[Value<'c, 'a>; LIMBS],
    u2: &[Value<'c, 'a>; LIMBS],
) -> Result<
    (
        [Value<'c, 'a>; LIMBS],
        [Value<'c, 'a>; LIMBS],
        Value<'c, 'a>,
    ),
    Error,
> {
    let zero_limbs = pack_const_limbs(builder, context, location, &[0, 0, 0, 0])?;
    let one_limbs = pack_const_limbs(builder, context, location, &[1, 0, 0, 0])?;
    let mut acc: JacobianPoint<'c, 'a> = (zero_limbs, zero_limbs, zero_limbs);

    for limb_idx in (0..LIMBS).rev() {
        acc = append_joint_scalar_mul_limb_loop::<C>(
            builder,
            context,
            location,
            &acc,
            g,
            p,
            g_plus_p,
            g_plus_p_is_infinity,
            u1[limb_idx],
            u2[limb_idx],
        )?;
    }

    // Guard the inverse against Z = 0 (caller checks `is_infinity`).
    let acc_z_is_zero = append_limbs_eq_bool(builder, context, location, &acc.2, &zero_limbs)?;
    let safe_z = append_select_limbs(
        builder,
        context,
        location,
        acc_z_is_zero,
        &one_limbs,
        &acc.2,
    )?;
    let (rx, ry) =
        append_jacobian_to_affine::<C>(builder, context, location, &(acc.0, acc.1, safe_z))?;

    Ok((rx, ry, acc_z_is_zero))
}

/// `(X, Y, Z)` Jacobian → `(x, y)` affine over curve `C`. Panics on `Z = 0`;
/// callers must guard with a separate check.
pub(super) fn append_jacobian_to_affine<'c: 'a, 'a, C: Curve>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    p: &JacobianPoint<'c, 'a>,
) -> Result<([Value<'c, 'a>; LIMBS], [Value<'c, 'a>; LIMBS]), Error> {
    let (x, y, z) = p;
    let z_inv = append_inv_p::<C>(builder, context, location, z)?;
    let z_inv_sq = append_mul_p::<C>(builder, context, location, &z_inv, &z_inv)?;
    let z_inv_cu = append_mul_p::<C>(builder, context, location, &z_inv_sq, &z_inv)?;
    let x_affine = append_mul_p::<C>(builder, context, location, x, &z_inv_sq)?;
    let y_affine = append_mul_p::<C>(builder, context, location, y, &z_inv_cu)?;
    Ok((x_affine, y_affine))
}
