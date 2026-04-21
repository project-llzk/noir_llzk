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
    multiprec::{LIMBS, Limbs256, emit_add_mod_p, emit_div_mod_p, emit_mul_mod_p, emit_sub_mod_p},
};

use super::secp256k1::SECP256K1_P;

/// Affine point on secp256k1. Neither coordinate represents infinity.
pub(super) type AffinePoint<'c, 'a> = (Limbs256<'c, 'a>, Limbs256<'c, 'a>);

/// Computes `P1 + P2` for two distinct finite points with `x1 ≠ x2`.
///
/// Formula (short Weierstrass, a=0):
///   λ  = (y2 - y1) / (x2 - x1)
///   x3 = λ² - x1 - x2
///   y3 = λ·(x1 - x3) - y1
pub(super) fn emit_point_add_affine<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    p1: AffinePoint<'c, 'a>,
    p2: AffinePoint<'c, 'a>,
) -> Result<AffinePoint<'c, 'a>, Error> {
    let (x1, y1) = p1;
    let (x2, y2) = p2;
    let dy = emit_sub_mod_p(writer, &y2, &y1, &SECP256K1_P)?;
    let dx = emit_sub_mod_p(writer, &x2, &x1, &SECP256K1_P)?;
    let lambda = emit_div_mod_p(writer, &dy, &dx, &SECP256K1_P)?;
    let lambda_sq = emit_mul_mod_p(writer, &lambda, &lambda, &SECP256K1_P)?;
    let x_sum = emit_add_mod_p(writer, &x1, &x2, &SECP256K1_P)?;
    let x3 = emit_sub_mod_p(writer, &lambda_sq, &x_sum, &SECP256K1_P)?;
    let x1_minus_x3 = emit_sub_mod_p(writer, &x1, &x3, &SECP256K1_P)?;
    let lambda_dx3 = emit_mul_mod_p(writer, &lambda, &x1_minus_x3, &SECP256K1_P)?;
    let y3 = emit_sub_mod_p(writer, &lambda_dx3, &y1, &SECP256K1_P)?;
    Ok((x3, y3))
}

/// Computes `2·P` for a finite affine point `P = (x, y)` with `y ≠ 0`.
///
/// Formula (short Weierstrass, a=0):
///   λ  = 3·x² / (2·y)
///   x3 = λ² - 2·x
///   y3 = λ·(x - x3) - y
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

/// Fixed-width scalar multiplication `k · P` assuming `k`'s MSB is 1 and the
/// running accumulator never hits the point at infinity or `±P` during the
/// double-and-add loop. Bits are given **LSB-first**; the MSB is the
/// initialisation bit for `acc = P`, and subsequent iterations walk from the
/// bit below the MSB down to bit 0.
///
/// Per iteration: one double (`~123` nondets) + one add (`~100`) + one select
/// (deterministic, no nondets).
pub(super) fn emit_scalar_mul_known_msb<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    point: AffinePoint<'c, 'a>,
    scalar_bits_lsb_first: &[Value<'c, 'a>],
) -> Result<AffinePoint<'c, 'a>, Error> {
    let mut acc = point;
    for bit in scalar_bits_lsb_first.iter().rev().skip(1).copied() {
        let doubled = emit_point_double(writer, acc)?;
        let added = emit_point_add_affine(writer, doubled, point)?;
        acc = emit_point_select(writer, bit, added, doubled)?;
    }
    Ok(acc)
}

pub(super) fn emit_point_double<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    p: AffinePoint<'c, 'a>,
) -> Result<AffinePoint<'c, 'a>, Error> {
    let (x, y) = p;
    let x_sq = emit_mul_mod_p(writer, &x, &x, &SECP256K1_P)?;
    let two_x_sq = emit_add_mod_p(writer, &x_sq, &x_sq, &SECP256K1_P)?;
    let three_x_sq = emit_add_mod_p(writer, &two_x_sq, &x_sq, &SECP256K1_P)?;
    let two_y = emit_add_mod_p(writer, &y, &y, &SECP256K1_P)?;
    let lambda = emit_div_mod_p(writer, &three_x_sq, &two_y, &SECP256K1_P)?;
    let lambda_sq = emit_mul_mod_p(writer, &lambda, &lambda, &SECP256K1_P)?;
    let two_x = emit_add_mod_p(writer, &x, &x, &SECP256K1_P)?;
    let x3 = emit_sub_mod_p(writer, &lambda_sq, &two_x, &SECP256K1_P)?;
    let x_minus_x3 = emit_sub_mod_p(writer, &x, &x3, &SECP256K1_P)?;
    let lambda_dx3 = emit_mul_mod_p(writer, &lambda, &x_minus_x3, &SECP256K1_P)?;
    let y3 = emit_sub_mod_p(writer, &lambda_dx3, &y, &SECP256K1_P)?;
    Ok((x3, y3))
}
