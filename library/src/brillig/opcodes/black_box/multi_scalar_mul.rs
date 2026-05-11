//! `BlackBoxOp::MultiScalarMul` lowering.
use acir::brillig::HeapArray;
use acir::{AcirField, FieldElement};
use llzk::prelude::Value;

use crate::blackboxes::grumpkin::multi_scalar_mul::{
    SCALAR_HIGH_BITS, SCALAR_LOW_BITS, SCALAR_TOTAL_BITS,
};
use crate::blackboxes::registry::BlackboxFunction;
use crate::brillig::translator::TranslationCtx;
use crate::error::Error;

use super::to_radix::emit_limb_decomp;
use super::{collect_results, read_heap_array, write_heap_array};
use crate::writer::Writer;

const POINT_FELTS: usize = 3;
const SCALAR_LIMBS: usize = 2;
const OUTPUT_FELTS: usize = 3;

pub(super) fn emit_multi_scalar_mul(
    ctx: &mut TranslationCtx<'_, '_, '_>,
    points: &HeapArray,
    scalars: &HeapArray,
    outputs: &HeapArray,
) -> Result<(), Error> {
    let points_size = points.size.0 as usize;
    let scalars_size = scalars.size.0 as usize;
    let outputs_size = outputs.size.0 as usize;

    if !points_size.is_multiple_of(POINT_FELTS) {
        return Err(Error::UnsupportedBrillig {
            reason: format!(
                "BlackBox::MultiScalarMul points HeapArray size must be a multiple of \
                 {POINT_FELTS} (got {points_size})"
            ),
        });
    }
    let num_points = points_size / POINT_FELTS;
    let expected_scalars = num_points * SCALAR_LIMBS;
    if scalars_size != expected_scalars {
        return Err(Error::UnsupportedBrillig {
            reason: format!(
                "BlackBox::MultiScalarMul expects scalars HeapArray size {expected_scalars} \
                 ({SCALAR_LIMBS} per point × {num_points} points), got {scalars_size}"
            ),
        });
    }
    if outputs_size != OUTPUT_FELTS {
        return Err(Error::UnsupportedBrillig {
            reason: format!(
                "BlackBox::MultiScalarMul requires outputs HeapArray size {OUTPUT_FELTS} \
                 (got {outputs_size})"
            ),
        });
    }

    let point_felts = read_heap_array(ctx, points.pointer, points_size)?;
    let scalar_felts = read_heap_array(ctx, scalars.pointer, scalars_size)?;

    let two = ctx.writer.emit_constant(&FieldElement::from(2u128))?;
    let mut bits: Vec<Value<'_, '_>> = Vec::with_capacity(num_points * SCALAR_TOTAL_BITS);
    for chunk in scalar_felts.chunks_exact(SCALAR_LIMBS) {
        let lo = chunk[0];
        let hi = chunk[1];
        bits.extend(emit_limb_decomp(ctx.writer, lo, two, SCALAR_LOW_BITS)?);
        bits.extend(emit_limb_decomp(ctx.writer, hi, two, SCALAR_HIGH_BITS)?);
    }

    let predicate = ctx.writer.emit_constant(&FieldElement::one())?;
    let mut args = Vec::with_capacity(num_points * POINT_FELTS + bits.len() + 1);
    args.extend_from_slice(&point_felts);
    args.extend(bits);
    args.push(predicate);

    let call = ctx
        .writer
        .call_blackbox_function(BlackboxFunction::MultiScalarMul { num_points }, &args)?;
    let results = collect_results(call, OUTPUT_FELTS)?;

    write_heap_array(ctx, outputs.pointer, OUTPUT_FELTS, &results)
}
