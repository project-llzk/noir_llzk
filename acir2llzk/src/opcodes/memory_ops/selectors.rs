//! Dynamic-index gadget for memory ops.
//!
//! - `@compute`: selectors are computed via `bool.cmp eq(idx, i)` wrapped in
//!   an `scf.if` that yields `felt 1` or `felt 0`.
//! - `@constrain`: selectors are introduced as `llzk.nondet` and pinned by
//!   three field-native constraints (booleanness, match, unique). This is
//!   the gadget the backends actually consume.

use acir::{AcirField, FieldElement};
use llzk::prelude::{Block, BlockLike, LlzkContext, Location, Value, dialect};

use crate::block_writer::BlockWriter;
use crate::common::{field_to_felt_const, insert_if_with_results};
use crate::error::Error;
use crate::writer::Writer;

/// Phase-specific strategy for materialising the one-hot selector vector over `idx_felt`.
pub(super) type EmitSelectors<'c, 'b> = fn(
    writer: &mut BlockWriter<'c, 'b>,
    idx_felt: Value<'c, 'b>,
    len: usize,
) -> Result<Vec<Value<'c, 'b>>, Error>;

/// `@compute`: selectors are computed from `idx_felt` directly.
pub(super) fn emit_selectors_compute<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    idx_felt: Value<'c, 'b>,
    len: usize,
) -> Result<Vec<Value<'c, 'b>>, Error> {
    let context = writer.context();
    let location = writer.location();
    let felt_ty = writer.felt_type();
    let mut selectors = Vec::with_capacity(len);
    for i in 0..len {
        let i_const = writer.emit_constant(&FieldElement::from(i as u128))?;
        let cond = writer.insert_bool_eq(idx_felt, i_const)?;
        let [s_i] = insert_if_with_results(
            writer,
            cond,
            &[felt_ty],
            |then_block| {
                Ok([append_felt_const(
                    then_block,
                    context,
                    location,
                    &FieldElement::one(),
                )?])
            },
            |else_block| {
                Ok([append_felt_const(
                    else_block,
                    context,
                    location,
                    &FieldElement::zero(),
                )?])
            },
        )?;
        selectors.push(s_i);
    }
    Ok(selectors)
}

/// `@constrain`: selectors are nondet witnesses pinned by 3 constraints.
pub(super) fn emit_selectors_constrain<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    idx_felt: Value<'c, 'b>,
    len: usize,
) -> Result<Vec<Value<'c, 'b>>, Error> {
    let felt_ty = writer.felt_type();
    let zero = writer.emit_constant(&FieldElement::zero())?;
    let one = writer.emit_constant(&FieldElement::one())?;
    let neg_one = writer.insert_neg(one)?;

    let mut selectors = Vec::with_capacity(len);
    let mut sum: Option<Value<'c, 'b>> = None;
    for i in 0..len {
        let s_i = writer.insert_nondet(felt_ty)?;

        // s_i * (s_i - 1) == 0
        let s_minus_one = writer.insert_add(s_i, neg_one)?;
        let bool_check = writer.insert_mul(s_i, s_minus_one)?;
        writer.insert_constrain_eq(bool_check, zero);

        // s_i * (idx_felt - i) == 0
        let i_const = writer.emit_constant(&FieldElement::from(i as u128))?;
        let neg_i = writer.insert_neg(i_const)?;
        let idx_minus_i = writer.insert_add(idx_felt, neg_i)?;
        let match_check = writer.insert_mul(s_i, idx_minus_i)?;
        writer.insert_constrain_eq(match_check, zero);

        sum = Some(match sum {
            None => s_i,
            Some(prev) => writer.insert_add(prev, s_i)?,
        });
        selectors.push(s_i);
    }

    // Σ s_i == 1
    if let Some(s) = sum {
        writer.insert_constrain_eq(s, one);
    }
    Ok(selectors)
}

/// Appends `felt.const value` to an inner `scf.if` branch block and returns the result.
fn append_felt_const<'c, 'b>(
    block: &'b Block<'c>,
    context: &'c LlzkContext,
    location: Location<'c>,
    value: &FieldElement,
) -> Result<Value<'c, 'b>, Error> {
    let attr = field_to_felt_const(context, value);
    Ok(block
        .append_operation(dialect::felt::constant(location, attr)?)
        .result(0)?
        .into())
}
