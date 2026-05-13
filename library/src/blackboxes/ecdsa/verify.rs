use acir::{AcirField, FieldElement};
use llzk::prelude::{
    Block, BlockLike, FuncDefOp, FuncDefOpLike, FunctionType, LlzkContext, Location, OperationLike,
    RegionLike, Value, dialect,
};

use crate::{blackboxes::common::felt_type, error::Error, multiprec::LIMBS};

use super::{
    constants::{
        ECDSA_HELPER_INPUTS, ECDSA_PK_BYTES, ECDSA_SECP256K1_COMPUTE_HELPER_NAME,
        ECDSA_SECP256R1_COMPUTE_HELPER_NAME, ECDSA_SIG_BYTES,
    },
    curve::{Curve, Secp256k1, Secp256r1},
    limbs::{
        append_felt_constant, append_limbs_eq_bool, append_limbs_lt_bool, append_not_bit,
        append_op_with_result, append_select_limbs,
    },
    modular::{append_inv_n, append_mul_n, append_mul_p, pack_const_limbs},
    point::{
        JacobianPoint, append_jacobian_to_affine, append_joint_scalar_mul,
        append_point_add_mixed_complete,
    },
};

fn append_pack_args_be_to_le_limbs<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    byte_offset: usize,
) -> Result<[Value<'c, 'a>; LIMBS], Error> {
    let zero = append_felt_constant(block, context, location, &FieldElement::zero())?;
    let mut limbs = [zero; LIMBS];
    for (limb_idx, limb) in limbs.iter_mut().enumerate() {
        let byte_start = byte_offset + (3 - limb_idx) * 8;
        let mut acc = zero;
        for i in 0..8 {
            let byte_value = block.argument(byte_start + i)?.into();
            let shift = 8u32 * (7 - i) as u32;
            let coeff = append_felt_constant(
                block,
                context,
                location,
                &FieldElement::from(1u128 << shift),
            )?;
            let term =
                append_op_with_result(block, dialect::felt::mul(location, byte_value, coeff)?)?;
            acc = append_op_with_result(block, dialect::felt::add(location, acc, term)?)?;
        }
        *limb = acc;
    }
    Ok(limbs)
}

/// ECDSA verify result as a deterministic felt 0/1, generic over the curve.
///
/// Returns `1` iff all of these hold:
/// - `pk_x, pk_y < p`
/// - `(pk_x, pk_y)` lies on `y² = x³ + a·x + b (mod p)`
/// - `r ≠ 0`, `r < n`, `s < n`, `s < (n+1)/2` (low-s)
/// - `R = u1·G + u2·P` is not the point at infinity, where
///   `s_inv = s^(n-2) mod n`, `u1 = z·s_inv mod n`, `u2 = r·s_inv mod n`
/// - `R.x < n` and `R.x == r`
#[allow(clippy::too_many_arguments)]
fn append_verify_result<'c, 'a, C: Curve>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    pk_x: &[Value<'c, 'a>; LIMBS],
    pk_y: &[Value<'c, 'a>; LIMBS],
    sig_r: &[Value<'c, 'a>; LIMBS],
    sig_s: &[Value<'c, 'a>; LIMBS],
    z: &[Value<'c, 'a>; LIMBS],
) -> Result<Value<'c, 'a>, Error> {
    let zero_limbs = pack_const_limbs(block, context, location, &[0, 0, 0, 0])?;
    let one_limbs = pack_const_limbs(block, context, location, &[1, 0, 0, 0])?;
    let p_limbs = pack_const_limbs(block, context, location, &C::P)?;
    let n_limbs = pack_const_limbs(block, context, location, &C::N)?;
    let half_n_plus_one_limbs = pack_const_limbs(block, context, location, &C::HALF_N_PLUS_ONE)?;
    let g_x_limbs = pack_const_limbs(block, context, location, &C::GX)?;
    let g_y_limbs = pack_const_limbs(block, context, location, &C::GY)?;

    let pkx_lt_p = append_limbs_lt_bool(block, context, location, pk_x, &p_limbs)?;
    let pky_lt_p = append_limbs_lt_bool(block, context, location, pk_y, &p_limbs)?;
    let r_lt_n = append_limbs_lt_bool(block, context, location, sig_r, &n_limbs)?;
    let s_lt_n = append_limbs_lt_bool(block, context, location, sig_s, &n_limbs)?;
    let s_is_low = append_limbs_lt_bool(block, context, location, sig_s, &half_n_plus_one_limbs)?;
    let r_is_zero = append_limbs_eq_bool(block, context, location, sig_r, &zero_limbs)?;
    let r_is_nonzero = append_not_bit(block, context, location, r_is_zero)?;

    // pk_y² == x³ + a·x + b (mod p)
    let py_sq = append_mul_p::<C>(block, context, location, pk_y, pk_y)?;
    let rhs = C::append_curve_rhs(block, context, location, pk_x)?;
    let on_curve = append_limbs_eq_bool(block, context, location, &py_sq, &rhs)?;

    let s_inv = append_inv_n::<C>(block, context, location, sig_s)?;
    let u1 = append_mul_n::<C>(block, context, location, z, &s_inv)?;
    let u2 = append_mul_n::<C>(block, context, location, sig_r, &s_inv)?;

    // Precompute G + P in affine so the joint scalar mul's table is ready.
    let g_as_jac: JacobianPoint<'c, 'a> = (g_x_limbs, g_y_limbs, one_limbs);
    let gp_q_is_inf = append_felt_constant(block, context, location, &FieldElement::zero())?;
    let gp_jac = append_point_add_mixed_complete::<C>(
        block,
        context,
        location,
        &g_as_jac,
        &(*pk_x, *pk_y),
        gp_q_is_inf,
    )?;
    let gp_is_inf = append_limbs_eq_bool(block, context, location, &gp_jac.2, &zero_limbs)?;
    let safe_gp_z =
        append_select_limbs(block, context, location, gp_is_inf, &one_limbs, &gp_jac.2)?;
    let (gp_x, gp_y) =
        append_jacobian_to_affine::<C>(block, context, location, &(gp_jac.0, gp_jac.1, safe_gp_z))?;

    let (rx, _ry, r_is_inf) = append_joint_scalar_mul::<C>(
        block,
        context,
        location,
        &(g_x_limbs, g_y_limbs),
        &(*pk_x, *pk_y),
        &(gp_x, gp_y),
        gp_is_inf,
        &u1,
        &u2,
    )?;
    let r_is_finite = append_not_bit(block, context, location, r_is_inf)?;

    // ACVM converts R.x into a scalar and rejects if that conversion fails
    // (`R.x >= n`). It does not reduce R.x modulo n before comparing to r.
    let rx_lt_n = append_limbs_lt_bool(block, context, location, &rx, &n_limbs)?;
    let r_match = append_limbs_eq_bool(block, context, location, &rx, sig_r)?;

    let flags = [
        pkx_lt_p,
        pky_lt_p,
        r_lt_n,
        s_lt_n,
        s_is_low,
        r_is_nonzero,
        on_curve,
        r_is_finite,
        rx_lt_n,
        r_match,
    ];
    let mut valid = flags[0];
    for &f in &flags[1..] {
        valid = append_op_with_result(block, dialect::felt::mul(location, valid, f)?)?;
    }
    Ok(valid)
}

/// Output: `1` if `predicate == 0` (matches `1 - predicate`); otherwise `1`
/// iff the signature verifies, else `0`.
fn emit_compute_helper_deterministic<'c, C: Curve>(
    context: &'c LlzkContext,
    helper_name: &str,
) -> Result<FuncDefOp<'c>, Error> {
    let location = Location::unknown(context);
    let felt = felt_type(context);
    let inputs = vec![(felt, location); ECDSA_HELPER_INPUTS];
    let input_types = vec![felt; ECDSA_HELPER_INPUTS];
    let function_type = FunctionType::new(context, &input_types, &[felt]);
    let function = dialect::function::def(location, helper_name, function_type, &[], None)?;
    function.set_allow_non_native_field_ops_attr(true);

    let block = Block::new(&inputs);

    let pk_y_off = ECDSA_PK_BYTES;
    let sig_off = pk_y_off + ECDSA_PK_BYTES;
    let sig_s_off = sig_off + ECDSA_SIG_BYTES / 2;
    let hash_off = sig_off + ECDSA_SIG_BYTES;
    let pk_x = append_pack_args_be_to_le_limbs(&block, context, location, 0)?;
    let pk_y = append_pack_args_be_to_le_limbs(&block, context, location, pk_y_off)?;
    let sig_r = append_pack_args_be_to_le_limbs(&block, context, location, sig_off)?;
    let sig_s = append_pack_args_be_to_le_limbs(&block, context, location, sig_s_off)?;
    let z = append_pack_args_be_to_le_limbs(&block, context, location, hash_off)?;
    let predicate: Value<'_, '_> = block.argument(ECDSA_HELPER_INPUTS - 1)?.into();

    // Predicate short-circuit: predicate==0 returns 1 directly (matches the
    // constrain side's `1 - predicate`); the full verify runs only when active.
    let one_felt = append_felt_constant(&block, context, location, &FieldElement::one())?;
    let predicate_is_true: Value<'_, '_> = block
        .append_operation(dialect::bool::eq(location, predicate, one_felt)?)
        .result(0)?
        .into();

    let [result] = crate::common::append_if_with_results(
        &block,
        location,
        predicate_is_true,
        &[felt],
        |then_block| {
            let valid = append_verify_result::<C>(
                then_block, context, location, &pk_x, &pk_y, &sig_r, &sig_s, &z,
            )?;
            Ok([valid])
        },
        |else_block| {
            let one = append_felt_constant(else_block, context, location, &FieldElement::one())?;
            Ok([one])
        },
    )?;

    block.append_operation(dialect::function::r#return(location, &[result]));
    function.region(0)?.append_block(block);
    Ok(function)
}

pub(crate) fn emit_secp256k1_compute_helper<'c>(
    context: &'c LlzkContext,
) -> Result<FuncDefOp<'c>, Error> {
    emit_compute_helper_deterministic::<Secp256k1>(context, ECDSA_SECP256K1_COMPUTE_HELPER_NAME)
}

pub(crate) fn emit_secp256r1_compute_helper<'c>(
    context: &'c LlzkContext,
) -> Result<FuncDefOp<'c>, Error> {
    emit_compute_helper_deterministic::<Secp256r1>(context, ECDSA_SECP256R1_COMPUTE_HELPER_NAME)
}
