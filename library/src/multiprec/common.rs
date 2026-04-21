use acir::{AcirField, FieldElement};
use llzk::prelude::Value;

use crate::{block_writer::BlockWriter, error::Error};

use super::{LIMB_BITS, LIMBS, Limbs256};

/// Witnesses a nondet `k` and constrains `k·(1-k) = 0`, i.e. `k ∈ {0, 1}`.
pub(super) fn witness_bool<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    let felt_ty = writer.felt_type();
    let zero = writer.emit_constant(&FieldElement::zero())?;
    let one = writer.emit_constant(&FieldElement::one())?;
    let k = writer.insert_nondet(felt_ty)?;
    let neg_k = writer.insert_neg(k)?;
    let one_minus_k = writer.insert_add(one, neg_k)?;
    let k_times_one_minus_k = writer.insert_mul(k, one_minus_k)?;
    writer.insert_constrain_eq(k_times_one_minus_k, zero);
    Ok(k)
}

/// Witnesses 4 nondet limbs each range-checked to 64 bits.
pub(super) fn witness_result_limbs<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
) -> Result<Limbs256<'c, 'a>, Error> {
    let felt_ty = writer.felt_type();
    let bound = writer
        .emit_constant(&FieldElement::from(2u128).pow(&FieldElement::from(LIMB_BITS as u128)))?;
    let mut limbs: [Option<Value<'c, 'a>>; LIMBS] = [None; LIMBS];
    for slot in &mut limbs {
        let limb = writer.insert_nondet(felt_ty)?;
        let ok = writer.insert_bool_lt(limb, bound)?;
        writer.insert_bool_assert(ok)?;
        *slot = Some(limb);
    }
    Ok(limbs.map(|slot| slot.expect("all slots filled")))
}

/// Enforces `c ∈ {-1, 0, 1}` via `c·(c+1)·(c-1) = 0`.
pub(super) fn constrain_signed_trit<'c, 'a>(
    writer: &mut BlockWriter<'c, 'a>,
    c: Value<'c, 'a>,
) -> Result<(), Error> {
    let zero = writer.emit_constant(&FieldElement::zero())?;
    let one = writer.emit_constant(&FieldElement::one())?;
    let neg_one = writer.insert_neg(one)?;
    let c_plus_one = writer.insert_add(c, one)?;
    let c_minus_one = writer.insert_add(c, neg_one)?;
    let t = writer.insert_mul(c, c_plus_one)?;
    let t = writer.insert_mul(t, c_minus_one)?;
    writer.insert_constrain_eq(t, zero);
    Ok(())
}

/// Emits `2^64` as a cached felt constant.
pub(super) fn two_pow_64<'c, 'a>(writer: &mut BlockWriter<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
    writer.emit_constant(&FieldElement::from(2u128).pow(&FieldElement::from(LIMB_BITS as u128)))
}
