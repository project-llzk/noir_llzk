//! Short-Weierstrass point arithmetic over `y² = x³ + a·x + b (mod p)`.

use acir::FieldElement;
use llzk::prelude::Value;

use crate::{
    block_writer::BlockWriter,
    error::Error,
    multiprec::{
        LIMBS, Limbs256, emit_add_mod_p, emit_limbs_eq_boolean, emit_mul_mod_p,
        emit_safe_div_mod_p, emit_sub_mod_p, emit_zero_limbs, try_init_limbs,
    },
};

pub(super) struct CurveParams {
    pub(super) p: [u64; LIMBS],
    pub(super) a: [u64; LIMBS],
    pub(super) b: [u64; LIMBS],
}

pub(super) fn assert_on_curve<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    x: &Limbs256<'c, 'b>,
    y: &Limbs256<'c, 'b>,
    curve: &CurveParams,
) -> Result<(), Error> {
    let a_limbs =
        try_init_limbs(|i| writer.emit_constant(&FieldElement::from(curve.a[i] as u128)))?;
    let b_limbs =
        try_init_limbs(|i| writer.emit_constant(&FieldElement::from(curve.b[i] as u128)))?;
    let x_sq = emit_mul_mod_p(writer, x, x, &curve.p)?;
    let x_cubed = emit_mul_mod_p(writer, &x_sq, x, &curve.p)?;
    let a_x = emit_mul_mod_p(writer, &a_limbs, x, &curve.p)?;
    let x_cubed_plus_ax = emit_add_mod_p(writer, &x_cubed, &a_x, &curve.p)?;
    let rhs = emit_add_mod_p(writer, &x_cubed_plus_ax, &b_limbs, &curve.p)?;
    let y_sq = emit_mul_mod_p(writer, y, y, &curve.p)?;
    for (a, b) in y_sq.iter().zip(rhs.iter()) {
        writer.insert_constrain_eq(*a, *b);
    }
    Ok(())
}

pub(super) type AffinePoint<'c, 'a> = (Limbs256<'c, 'a>, Limbs256<'c, 'a>);

/// `(x, y, is_infinity)` — when `is_infinity = 1`, x and y are ignored.
pub(super) type CompletePoint<'c, 'a> = (Limbs256<'c, 'a>, Limbs256<'c, 'a>, Value<'c, 'a>);

const JOINT_WINDOW_BITS: usize = 2;
const JOINT_WINDOW_SIZE: usize = 1 << JOINT_WINDOW_BITS;

struct JointWindowTable<'c, 'a> {
    x: Limbs256<'c, 'a>,
    y: Limbs256<'c, 'a>,
    inf: Value<'c, 'a>,
}

/// Complete addition: handles O + P, P + O, P ± Q, and the regular formula.
/// All branches emit unconditionally; case dispatch is done with selects.
pub(super) fn emit_point_add_complete<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    p1: CompletePoint<'c, 'a>,
    p2: CompletePoint<'c, 'a>,
    curve: &CurveParams,
) -> Result<CompletePoint<'c, 'a>, Error> {
    let (x1, y1, inf1) = p1;
    let (x2, y2, inf2) = p2;
    let zero = writer.emit_constant(&FieldElement::from(0u128))?;
    let one = writer.emit_constant(&FieldElement::from(1u128))?;

    // safe_div tolerates x1 = x2; garbage lambda discarded by the case selects below.
    let dy = emit_sub_mod_p(writer, &y2, &y1, &curve.p)?;
    let dx = emit_sub_mod_p(writer, &x2, &x1, &curve.p)?;
    let (lambda, _) = emit_safe_div_mod_p(writer, &dy, &dx, &curve.p)?;
    let lambda_sq = emit_mul_mod_p(writer, &lambda, &lambda, &curve.p)?;
    let x_sum = emit_add_mod_p(writer, &x1, &x2, &curve.p)?;
    let x3_reg = emit_sub_mod_p(writer, &lambda_sq, &x_sum, &curve.p)?;
    let x1_minus_x3 = emit_sub_mod_p(writer, &x1, &x3_reg, &curve.p)?;
    let lambda_dx3 = emit_mul_mod_p(writer, &lambda, &x1_minus_x3, &curve.p)?;
    let y3_reg = emit_sub_mod_p(writer, &lambda_dx3, &y1, &curve.p)?;
    let reg: CompletePoint = (x3_reg, y3_reg, zero);

    let doubled = emit_point_double_complete(writer, p1, curve)?;
    let zero_limbs = emit_zero_limbs(writer)?;
    let inf_pt: CompletePoint = (zero_limbs, zero_limbs, one);
    let x_eq = emit_limbs_eq_boolean(writer, &x1, &x2)?;
    let y_eq = emit_limbs_eq_boolean(writer, &y1, &y2)?;

    let when_x_eq = emit_select_complete(writer, y_eq, doubled, inf_pt)?;
    let both_finite = emit_select_complete(writer, x_eq, when_x_eq, reg)?;
    let if_inf2 = emit_select_complete(writer, inf2, p1, both_finite)?;
    emit_select_complete(writer, inf1, p2, if_inf2)
}

/// `2·P` with the infinity case selected in. safe_div tolerates y = 0;
/// the resulting garbage is unreachable for secp-G-derived points (no order-2 elements).
pub(super) fn emit_point_double_complete<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    p_pt: CompletePoint<'c, 'a>,
    curve: &CurveParams,
) -> Result<CompletePoint<'c, 'a>, Error> {
    let (x, y, inf) = p_pt;
    let zero = writer.emit_constant(&FieldElement::from(0u128))?;
    let one = writer.emit_constant(&FieldElement::from(1u128))?;

    // Slope = (3·x² + a) / (2·y).
    let x_sq = emit_mul_mod_p(writer, &x, &x, &curve.p)?;
    let two_x_sq = emit_add_mod_p(writer, &x_sq, &x_sq, &curve.p)?;
    let three_x_sq = emit_add_mod_p(writer, &two_x_sq, &x_sq, &curve.p)?;
    let a_limbs =
        try_init_limbs(|i| writer.emit_constant(&FieldElement::from(curve.a[i] as u128)))?;
    let numerator = emit_add_mod_p(writer, &three_x_sq, &a_limbs, &curve.p)?;
    let two_y = emit_add_mod_p(writer, &y, &y, &curve.p)?;
    let (lambda, _) = emit_safe_div_mod_p(writer, &numerator, &two_y, &curve.p)?;
    let lambda_sq = emit_mul_mod_p(writer, &lambda, &lambda, &curve.p)?;
    let two_x = emit_add_mod_p(writer, &x, &x, &curve.p)?;
    let x3_reg = emit_sub_mod_p(writer, &lambda_sq, &two_x, &curve.p)?;
    let x_minus_x3 = emit_sub_mod_p(writer, &x, &x3_reg, &curve.p)?;
    let lambda_dx3 = emit_mul_mod_p(writer, &lambda, &x_minus_x3, &curve.p)?;
    let y3_reg = emit_sub_mod_p(writer, &lambda_dx3, &y, &curve.p)?;
    let reg: CompletePoint = (x3_reg, y3_reg, zero);

    let zero_limbs = emit_zero_limbs(writer)?;
    let inf_pt: CompletePoint = (zero_limbs, zero_limbs, one);
    emit_select_complete(writer, inf, inf_pt, reg)
}

/// `k1·P1 + k2·P2` via windowed Shamir: 2 bits per step, 16-entry table
/// `{i·P1 + j·P2 | i, j ∈ [0, 3]}`.
pub(super) fn emit_joint_scalar_mul<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    p1: AffinePoint<'c, 'a>,
    p1_bits_lsb_first: &[Value<'c, 'a>],
    p2: AffinePoint<'c, 'a>,
    p2_bits_lsb_first: &[Value<'c, 'a>],
    curve: &CurveParams,
) -> Result<CompletePoint<'c, 'a>, Error> {
    debug_assert_eq!(p1_bits_lsb_first.len(), p2_bits_lsb_first.len());
    debug_assert_eq!(p1_bits_lsb_first.len() % JOINT_WINDOW_BITS, 0);

    let zero = writer.emit_constant(&FieldElement::from(0u128))?;
    let one = writer.emit_constant(&FieldElement::from(1u128))?;
    let zero_limbs = emit_zero_limbs(writer)?;
    let infinity: CompletePoint = (zero_limbs, zero_limbs, one);
    let p1_pt: CompletePoint = (p1.0, p1.1, zero);
    let p2_pt: CompletePoint = (p2.0, p2.1, zero);
    let table = emit_joint_window_table(writer, infinity, p1_pt, p2_pt, curve)?;

    let mut acc = infinity;
    for window in (0..p1_bits_lsb_first.len() / JOINT_WINDOW_BITS).rev() {
        for _ in 0..JOINT_WINDOW_BITS {
            acc = emit_point_double_complete(writer, acc, curve)?;
        }

        let start = window * JOINT_WINDOW_BITS;
        let addend = emit_select_joint_window_addend(
            writer,
            p1_bits_lsb_first[start],
            p1_bits_lsb_first[start + 1],
            p2_bits_lsb_first[start],
            p2_bits_lsb_first[start + 1],
            &table,
        )?;
        acc = emit_point_add_complete(writer, acc, addend, curve)?;
    }
    Ok(acc)
}

fn emit_joint_window_table<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    infinity: CompletePoint<'c, 'a>,
    p1: CompletePoint<'c, 'a>,
    p2: CompletePoint<'c, 'a>,
    curve: &CurveParams,
) -> Result<JointWindowTable<'c, 'a>, Error> {
    let p1_multiples = emit_window_multiples(writer, infinity, p1, curve)?;
    let p2_multiples = emit_window_multiples(writer, infinity, p2, curve)?;

    let mut table = Vec::with_capacity(JOINT_WINDOW_SIZE * JOINT_WINDOW_SIZE);
    for (i, p1_multiple) in p1_multiples.iter().copied().enumerate() {
        for (j, p2_multiple) in p2_multiples.iter().copied().enumerate() {
            let entry = if i == 0 {
                p2_multiple
            } else if j == 0 {
                p1_multiple
            } else {
                emit_point_add_complete(writer, p1_multiple, p2_multiple, curve)?
            };
            table.push(entry);
        }
    }
    emit_joint_window_arrays(writer, &table)
}

fn emit_joint_window_arrays<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    table: &[CompletePoint<'c, 'a>],
) -> Result<JointWindowTable<'c, 'a>, Error> {
    debug_assert_eq!(table.len(), JOINT_WINDOW_SIZE * JOINT_WINDOW_SIZE);

    let table_len = JOINT_WINDOW_SIZE * JOINT_WINDOW_SIZE;
    let x = try_init_limbs(|_| writer.insert_new_array(table_len))?;
    let y = try_init_limbs(|_| writer.insert_new_array(table_len))?;
    let inf = writer.insert_new_array(table_len)?;

    for (table_idx, point) in table.iter().enumerate() {
        let idx = writer.insert_integer(table_idx)?;
        for limb in 0..LIMBS {
            writer.insert_array_write(x[limb], &[idx], point.0[limb]);
            writer.insert_array_write(y[limb], &[idx], point.1[limb]);
        }
        writer.insert_array_write(inf, &[idx], point.2);
    }

    Ok(JointWindowTable { x, y, inf })
}

fn emit_window_multiples<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    infinity: CompletePoint<'c, 'a>,
    point: CompletePoint<'c, 'a>,
    curve: &CurveParams,
) -> Result<[CompletePoint<'c, 'a>; JOINT_WINDOW_SIZE], Error> {
    // Hard-coded for size 4; larger windows need a new addition chain.
    const _: () = assert!(JOINT_WINDOW_SIZE == 4);
    let double = emit_point_double_complete(writer, point, curve)?;
    let triple = emit_point_add_complete(writer, double, point, curve)?;
    Ok([infinity, point, double, triple])
}

fn emit_select_joint_window_addend<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    p1_bit0: Value<'c, 'a>,
    p1_bit1: Value<'c, 'a>,
    p2_bit0: Value<'c, 'a>,
    p2_bit1: Value<'c, 'a>,
    table: &JointWindowTable<'c, 'a>,
) -> Result<CompletePoint<'c, 'a>, Error> {
    let two = writer.emit_constant(&FieldElement::from(2u128))?;
    let four = writer.emit_constant(&FieldElement::from(4u128))?;

    let p1_high = writer.insert_mul(p1_bit1, two)?;
    let p1_window = writer.insert_add(p1_bit0, p1_high)?;
    let p2_high = writer.insert_mul(p2_bit1, two)?;
    let p2_window = writer.insert_add(p2_bit0, p2_high)?;
    let p1_scaled = writer.insert_mul(p1_window, four)?;
    let idx_felt = writer.insert_add(p1_scaled, p2_window)?;
    let idx = writer.insert_cast_to_index(idx_felt)?;

    let x = try_init_limbs(|i| writer.insert_array_read(table.x[i], idx))?;
    let y = try_init_limbs(|i| writer.insert_array_read(table.y[i], idx))?;
    let inf = writer.insert_array_read(table.inf, idx)?;
    Ok((x, y, inf))
}

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

/// `bit ? if_one : if_zero`. Caller must have constrained `bit ∈ {0, 1}`.
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
    try_init_limbs(|i| {
        let from_one = writer.insert_mul(bit, if_one[i])?;
        let from_zero = writer.insert_mul(one_minus_bit, if_zero[i])?;
        writer.insert_add(from_one, from_zero)
    })
}
