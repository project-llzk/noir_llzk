//! `BlackBoxOp::EmbeddedCurveAdd` lowering.
//!
//! Reads the six register-held inputs (`input1` and `input2` each as
//! `(x, y, infinite)`) plus a constant `predicate = 1` (the Brillig
//! VM has no predicate gate — passing `1` matches the
//! always-execute semantics), calls `@embedded_curve_add`, and
//! writes the resulting `(x, y, infinite)` triple to `result`.

use acir::brillig::{HeapArray, MemoryAddress};
use acir::{AcirField, FieldElement};
use llzk::prelude::Value;

use crate::blackboxes::registry::BlackboxFunction;
use crate::brillig::translator::TranslationCtx;
use crate::error::Error;

use super::{collect_results, write_heap_array};
use crate::writer::Writer;

const EMBEDDED_POINT_FELTS: usize = 3;

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_embedded_curve_add(
    ctx: &mut TranslationCtx<'_, '_, '_>,
    input1_x: MemoryAddress,
    input1_y: MemoryAddress,
    input1_infinite: MemoryAddress,
    input2_x: MemoryAddress,
    input2_y: MemoryAddress,
    input2_infinite: MemoryAddress,
    result: &HeapArray,
) -> Result<(), Error> {
    if result.size.0 as usize != EMBEDDED_POINT_FELTS {
        return Err(Error::UnsupportedBrillig {
            reason: format!(
                "BlackBox::EmbeddedCurveAdd requires \
                 result of size {EMBEDDED_POINT_FELTS} (got {})",
                result.size.0,
            ),
        });
    }

    let predicate = ctx.writer.emit_constant(&FieldElement::one())?;
    let args: [Value<'_, '_>; 7] = [
        ctx.memory.read(ctx.writer, input1_x)?,
        ctx.memory.read(ctx.writer, input1_y)?,
        ctx.memory.read(ctx.writer, input1_infinite)?,
        ctx.memory.read(ctx.writer, input2_x)?,
        ctx.memory.read(ctx.writer, input2_y)?,
        ctx.memory.read(ctx.writer, input2_infinite)?,
        predicate,
    ];

    let call = ctx
        .writer
        .call_blackbox_function(BlackboxFunction::EmbeddedCurveAdd, &args)?;
    let results: Vec<Value<'_, '_>> = collect_results(call, EMBEDDED_POINT_FELTS)?;

    write_heap_array(ctx, result.pointer, EMBEDDED_POINT_FELTS, &results)
}
