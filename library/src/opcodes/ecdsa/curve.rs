//! Secp256k1 affine point arithmetic over the base field Fp.
//!
//! Points are represented as `(x, y)`, each a 4-limb little-endian
//! non-native integer < p. Infinity is *not* representable here — these
//! primitives assume finite, non-special inputs. Edge cases (P + (-P),
//! doubling at y=0, infinity handling) will be layered on top later.

use acir::FieldElement;
use llzk::prelude::Value;

use crate::{
    block_writer::BlockWriter,
    error::Error,
    multiprec::{
        LIMBS, Limbs256, emit_add_mod_p, emit_limbs_eq_boolean, emit_mul_mod_p,
        emit_safe_div_mod_p, emit_sub_mod_p,
    },
};

use super::secp256k1::SECP256K1_P;

/// Affine point on secp256k1. Neither coordinate represents infinity.
pub(super) type AffinePoint<'c, 'a> = (Limbs256<'c, 'a>, Limbs256<'c, 'a>);

/// Point on secp256k1 with an explicit infinity flag.
/// `is_infinity ∈ {0, 1}`; when 1, the x and y components are ignored.
pub(super) type CompletePoint<'c, 'a> = (Limbs256<'c, 'a>, Limbs256<'c, 'a>, Value<'c, 'a>);

/// Emits `P1 + P2` on secp256k1 as a fully complete addition:
///   - P1 = O: returns P2
///   - P2 = O: returns P1
///   - x1 = x2 ∧ y1 = y2: doubling (P1 = P2)
///   - x1 = x2 ∧ y1 ≠ y2: returns O (P1 = -P2)
///   - otherwise: regular add formula
///
/// Everything is computed unconditionally and the cases are resolved by a
/// chain of selects on infinity / x_eq / y_eq flags. Safe division tolerates
/// x1 = x2 (garbage lambda discarded by the select).
pub(super) fn emit_point_add_complete<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    p1: CompletePoint<'c, 'a>,
    p2: CompletePoint<'c, 'a>,
) -> Result<CompletePoint<'c, 'a>, Error> {
    let (x1, y1, inf1) = p1;
    let (x2, y2, inf2) = p2;
    let zero = writer.emit_constant(&FieldElement::from(0u128))?;
    let one = writer.emit_constant(&FieldElement::from(1u128))?;

    // Regular add via safe_div so we don't fail when x1 = x2.
    let dy = emit_sub_mod_p(writer, &y2, &y1, &SECP256K1_P)?;
    let dx = emit_sub_mod_p(writer, &x2, &x1, &SECP256K1_P)?;
    let (lambda, _) = emit_safe_div_mod_p(writer, &dy, &dx, &SECP256K1_P)?;
    let lambda_sq = emit_mul_mod_p(writer, &lambda, &lambda, &SECP256K1_P)?;
    let x_sum = emit_add_mod_p(writer, &x1, &x2, &SECP256K1_P)?;
    let x3_reg = emit_sub_mod_p(writer, &lambda_sq, &x_sum, &SECP256K1_P)?;
    let x1_minus_x3 = emit_sub_mod_p(writer, &x1, &x3_reg, &SECP256K1_P)?;
    let lambda_dx3 = emit_mul_mod_p(writer, &lambda, &x1_minus_x3, &SECP256K1_P)?;
    let y3_reg = emit_sub_mod_p(writer, &lambda_dx3, &y1, &SECP256K1_P)?;
    let reg: CompletePoint = (x3_reg, y3_reg, zero);

    // x1 == x2 cases: either doubling (y1 == y2) or infinity (y1 ≠ y2).
    let doubled = emit_point_double_complete(writer, p1)?;
    let zero_limbs: Limbs256 = [zero; LIMBS];
    let inf_pt: CompletePoint = (zero_limbs, zero_limbs, one);
    let x_eq = emit_limbs_eq_boolean(writer, &x1, &x2)?;
    let y_eq = emit_limbs_eq_boolean(writer, &y1, &y2)?;

    // when_x_eq = y_eq ? doubled : O
    let when_x_eq = emit_select_complete(writer, y_eq, doubled, inf_pt)?;
    // both_finite = x_eq ? when_x_eq : reg
    let both_finite = emit_select_complete(writer, x_eq, when_x_eq, reg)?;

    // Infinity handling: if_inf2 = inf2 ? P1 : both_finite
    let if_inf2 = emit_select_complete(writer, inf2, p1, both_finite)?;
    // result = inf1 ? P2 : if_inf2
    emit_select_complete(writer, inf1, p2, if_inf2)
}

/// Emits `2·P` on secp256k1 handling P = infinity via select. For finite P
/// with y ≠ 0 this reduces to the regular doubling formula. When y = 0 the
/// safe_div returns garbage that gets discarded iff P is also flagged as
/// infinity (order-2 case — doesn't happen for secp256k1-G-derived points).
pub(super) fn emit_point_double_complete<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    p_pt: CompletePoint<'c, 'a>,
) -> Result<CompletePoint<'c, 'a>, Error> {
    let (x, y, inf) = p_pt;
    let zero = writer.emit_constant(&FieldElement::from(0u128))?;
    let one = writer.emit_constant(&FieldElement::from(1u128))?;

    // Regular doubling via safe_div so y = 0 doesn't fail.
    let x_sq = emit_mul_mod_p(writer, &x, &x, &SECP256K1_P)?;
    let two_x_sq = emit_add_mod_p(writer, &x_sq, &x_sq, &SECP256K1_P)?;
    let three_x_sq = emit_add_mod_p(writer, &two_x_sq, &x_sq, &SECP256K1_P)?;
    let two_y = emit_add_mod_p(writer, &y, &y, &SECP256K1_P)?;
    let (lambda, _) = emit_safe_div_mod_p(writer, &three_x_sq, &two_y, &SECP256K1_P)?;
    let lambda_sq = emit_mul_mod_p(writer, &lambda, &lambda, &SECP256K1_P)?;
    let two_x = emit_add_mod_p(writer, &x, &x, &SECP256K1_P)?;
    let x3_reg = emit_sub_mod_p(writer, &lambda_sq, &two_x, &SECP256K1_P)?;
    let x_minus_x3 = emit_sub_mod_p(writer, &x, &x3_reg, &SECP256K1_P)?;
    let lambda_dx3 = emit_mul_mod_p(writer, &lambda, &x_minus_x3, &SECP256K1_P)?;
    let y3_reg = emit_sub_mod_p(writer, &lambda_dx3, &y, &SECP256K1_P)?;
    let reg: CompletePoint = (x3_reg, y3_reg, zero);

    // If P infinite, result = infinity placeholder.
    let zero_limbs: Limbs256 = [zero; LIMBS];
    let inf_pt: CompletePoint = (zero_limbs, zero_limbs, one);
    emit_select_complete(writer, inf, inf_pt, reg)
}

/// General double-and-add scalar multiplication `k · P` for any 256-bit
/// scalar. Accumulator starts at infinity; each iteration doubles then
/// conditionally adds, using `emit_point_double_complete` and
/// `emit_point_add_complete` for infinity-aware ops.
///
/// Returns the result as a `CompletePoint`. If it's infinity, downstream
/// code must treat the signature as invalid.
pub(super) fn emit_scalar_mul_general<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    point: AffinePoint<'c, 'a>,
    scalar_bits_lsb_first: &[Value<'c, 'a>],
) -> Result<CompletePoint<'c, 'a>, Error> {
    let zero = writer.emit_constant(&FieldElement::from(0u128))?;
    let one = writer.emit_constant(&FieldElement::from(1u128))?;
    let zero_limbs: Limbs256 = [zero; LIMBS];

    let mut acc: CompletePoint = (zero_limbs, zero_limbs, one);
    let point_pt: CompletePoint = (point.0, point.1, zero);

    for bit in scalar_bits_lsb_first.iter().rev().copied() {
        let doubled = emit_point_double_complete(writer, acc)?;
        let added = emit_point_add_complete(writer, doubled, point_pt)?;
        acc = emit_select_complete(writer, bit, added, doubled)?;
    }
    Ok(acc)
}

/// Selects between two `CompletePoint`s based on `bit ∈ {0, 1}`.
fn emit_select_complete<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    bit: Value<'c, 'a>,
    if_one: CompletePoint<'c, 'a>,
    if_zero: CompletePoint<'c, 'a>,
) -> Result<CompletePoint<'c, 'a>, Error> {
    let (x, y) = emit_point_select(writer, bit, (if_one.0, if_one.1), (if_zero.0, if_zero.1))?;
    let one = writer.emit_constant(&FieldElement::from(1u128))?;
    let neg_bit = writer.insert_neg(bit)?;
    let one_minus_bit = writer.insert_add(one, neg_bit)?;
    let from_one = writer.insert_mul(bit, if_one.2)?;
    let from_zero = writer.insert_mul(one_minus_bit, if_zero.2)?;
    let inf = writer.insert_add(from_one, from_zero)?;
    Ok((x, y, inf))
}

/// Computes `P1 + P2` for two distinct finite points with `x1 ≠ x2`.
///
/// Selects `if_one` when `bit = 1`, `if_zero` when `bit = 0`.
/// Per limb: `out = bit · if_one + (1 - bit) · if_zero`.
/// Caller must have constrained `bit ∈ {0, 1}`.
pub(super) fn emit_point_select<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    bit: Value<'c, 'a>,
    if_one: AffinePoint<'c, 'a>,
    if_zero: AffinePoint<'c, 'a>,
) -> Result<AffinePoint<'c, 'a>, Error> {
    let one = writer.emit_constant(&FieldElement::from(1u128))?;
    let neg_bit = writer.insert_neg(bit)?;
    let one_minus_bit = writer.insert_add(one, neg_bit)?;
    let x = select_limbs(writer, bit, one_minus_bit, &if_one.0, &if_zero.0)?;
    let y = select_limbs(writer, bit, one_minus_bit, &if_one.1, &if_zero.1)?;
    Ok((x, y))
}

fn select_limbs<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    bit: Value<'c, 'a>,
    one_minus_bit: Value<'c, 'a>,
    if_one: &Limbs256<'c, 'a>,
    if_zero: &Limbs256<'c, 'a>,
) -> Result<Limbs256<'c, 'a>, Error> {
    let mut out: [Option<Value<'c, 'a>>; LIMBS] = [None; LIMBS];
    for (i, slot) in out.iter_mut().enumerate() {
        let from_one = writer.insert_mul(bit, if_one[i])?;
        let from_zero = writer.insert_mul(one_minus_bit, if_zero[i])?;
        *slot = Some(writer.insert_add(from_one, from_zero)?);
    }
    Ok(out.map(|s| s.expect("all slots filled")))
}
