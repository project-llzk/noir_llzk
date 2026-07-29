use llzk::prelude::{Block, LlzkContext, Location, Value};

use crate::{error::Error, multiprec::LIMBS};

use super::{
    constants::*,
    modular::{
        append_add_p, append_mul_mod_n_barrett, append_mul_mod_p_secp256k1, append_mul_p,
        append_sub_p, pack_const_limbs,
    },
    point::{JacobianPoint, append_point_double_a_neg_3, append_point_double_a_zero},
};

/// Short-Weierstrass curve over a ~256-bit prime.
pub(super) trait Curve {
    const P: [u64; LIMBS];
    const N: [u64; LIMBS];
    /// `floor(n/2) + 1` — low-S threshold.
    const HALF_N_PLUS_ONE: [u64; LIMBS];
    /// Curve coefficient `b` in `y² = x³ + a·x + b`.
    const B: [u64; LIMBS];
    const GX: [u64; LIMBS];
    const GY: [u64; LIMBS];

    const MUL_MOD_P_NAME: &'static str;
    const MUL_MOD_N_NAME: &'static str;
    const INV_MOD_P_NAME: &'static str;
    const INV_MOD_N_NAME: &'static str;

    fn append_mul_mod_p_inline<'c, 'a>(
        block: &'a Block<'c>,
        context: &'c LlzkContext,
        location: Location<'c>,
        a: &[Value<'c, 'a>; LIMBS],
        b: &[Value<'c, 'a>; LIMBS],
    ) -> Result<[Value<'c, 'a>; LIMBS], Error>;

    fn append_point_double<'c, 'a>(
        block: &'a Block<'c>,
        context: &'c LlzkContext,
        location: Location<'c>,
        p: &JacobianPoint<'c, 'a>,
    ) -> Result<JacobianPoint<'c, 'a>, Error>;

    /// `x³ + a·x + b (mod p)`.
    fn append_curve_rhs<'c, 'a>(
        block: &'a Block<'c>,
        context: &'c LlzkContext,
        location: Location<'c>,
        x: &[Value<'c, 'a>; LIMBS],
    ) -> Result<[Value<'c, 'a>; LIMBS], Error>;
}

pub(super) struct Secp256k1;
pub(super) struct Secp256r1;

impl Curve for Secp256k1 {
    const P: [u64; LIMBS] = SECP256K1_P;
    const N: [u64; LIMBS] = SECP256K1_N;
    const HALF_N_PLUS_ONE: [u64; LIMBS] = SECP256K1_HALF_N_PLUS_ONE;
    const B: [u64; LIMBS] = SECP256K1_B;
    const GX: [u64; LIMBS] = SECP256K1_GX;
    const GY: [u64; LIMBS] = SECP256K1_GY;

    const MUL_MOD_P_NAME: &'static str = ECDSA_SECP256K1_MUL_MOD_P_HELPER_NAME;
    const MUL_MOD_N_NAME: &'static str = ECDSA_SECP256K1_MUL_MOD_N_HELPER_NAME;
    const INV_MOD_P_NAME: &'static str = ECDSA_SECP256K1_INV_MOD_P_HELPER_NAME;
    const INV_MOD_N_NAME: &'static str = ECDSA_SECP256K1_INV_MOD_N_HELPER_NAME;

    fn append_mul_mod_p_inline<'c, 'a>(
        block: &'a Block<'c>,
        context: &'c LlzkContext,
        location: Location<'c>,
        a: &[Value<'c, 'a>; LIMBS],
        b: &[Value<'c, 'a>; LIMBS],
    ) -> Result<[Value<'c, 'a>; LIMBS], Error> {
        append_mul_mod_p_secp256k1(block, context, location, a, b)
    }

    fn append_point_double<'c, 'a>(
        block: &'a Block<'c>,
        context: &'c LlzkContext,
        location: Location<'c>,
        p: &JacobianPoint<'c, 'a>,
    ) -> Result<JacobianPoint<'c, 'a>, Error> {
        append_point_double_a_zero::<Self>(block, context, location, p)
    }

    fn append_curve_rhs<'c, 'a>(
        block: &'a Block<'c>,
        context: &'c LlzkContext,
        location: Location<'c>,
        x: &[Value<'c, 'a>; LIMBS],
    ) -> Result<[Value<'c, 'a>; LIMBS], Error> {
        // y² = x³ + 7 (a = 0).
        let x_sq = append_mul_p::<Self>(block, context, location, x, x)?;
        let x_cu = append_mul_p::<Self>(block, context, location, &x_sq, x)?;
        let b_limbs = pack_const_limbs(block, context, location, &Self::B)?;
        append_add_p::<Self>(block, context, location, &x_cu, &b_limbs)
    }
}

impl Curve for Secp256r1 {
    const P: [u64; LIMBS] = SECP256R1_P;
    const N: [u64; LIMBS] = SECP256R1_N;
    const HALF_N_PLUS_ONE: [u64; LIMBS] = SECP256R1_HALF_N_PLUS_ONE;
    const B: [u64; LIMBS] = SECP256R1_B;
    const GX: [u64; LIMBS] = SECP256R1_GX;
    const GY: [u64; LIMBS] = SECP256R1_GY;

    const MUL_MOD_P_NAME: &'static str = ECDSA_SECP256R1_MUL_MOD_P_HELPER_NAME;
    const MUL_MOD_N_NAME: &'static str = ECDSA_SECP256R1_MUL_MOD_N_HELPER_NAME;
    const INV_MOD_P_NAME: &'static str = ECDSA_SECP256R1_INV_MOD_P_HELPER_NAME;
    const INV_MOD_N_NAME: &'static str = ECDSA_SECP256R1_INV_MOD_N_HELPER_NAME;

    fn append_mul_mod_p_inline<'c, 'a>(
        block: &'a Block<'c>,
        context: &'c LlzkContext,
        location: Location<'c>,
        a: &[Value<'c, 'a>; LIMBS],
        b: &[Value<'c, 'a>; LIMBS],
    ) -> Result<[Value<'c, 'a>; LIMBS], Error> {
        append_mul_mod_n_barrett(block, context, location, a, b, &Self::P)
    }

    fn append_point_double<'c, 'a>(
        block: &'a Block<'c>,
        context: &'c LlzkContext,
        location: Location<'c>,
        p: &JacobianPoint<'c, 'a>,
    ) -> Result<JacobianPoint<'c, 'a>, Error> {
        append_point_double_a_neg_3::<Self>(block, context, location, p)
    }

    fn append_curve_rhs<'c, 'a>(
        block: &'a Block<'c>,
        context: &'c LlzkContext,
        location: Location<'c>,
        x: &[Value<'c, 'a>; LIMBS],
    ) -> Result<[Value<'c, 'a>; LIMBS], Error> {
        // y² = x³ − 3·x + b.
        let x_sq = append_mul_p::<Self>(block, context, location, x, x)?;
        let x_cu = append_mul_p::<Self>(block, context, location, &x_sq, x)?;
        let three_limbs = pack_const_limbs(block, context, location, &[3, 0, 0, 0])?;
        let three_x = append_mul_p::<Self>(block, context, location, &three_limbs, x)?;
        let cu_minus_3x = append_sub_p::<Self>(block, context, location, &x_cu, &three_x)?;
        let b_limbs = pack_const_limbs(block, context, location, &Self::B)?;
        append_add_p::<Self>(block, context, location, &cu_minus_3x, &b_limbs)
    }
}
