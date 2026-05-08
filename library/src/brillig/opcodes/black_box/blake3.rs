//! `BlackBoxOp::Blake3` lowering.
//!
//! Mirrors [`super::blake2s`]: reads `message.size` bytes, pads to
//! `num_blocks * 64` with felt-zero, appends the real length's lo/hi
//! 32-bit halves, calls `@blake3_<num_blocks>`, and writes
//! `BLAKE3_DIGEST_BYTES` digest felts to the output HeapArray.

use acir::brillig::HeapArray;
use acir::{AcirField, FieldElement};
use llzk::prelude::Value;

use crate::blackboxes::{
    hash::blake3::{BLAKE3_DIGEST_BYTES, blake3_num_blocks_for_len},
    registry::BlackboxFunction,
};
use crate::brillig::{memory::Memory, translator::TranslationCtx};
use crate::error::Error;

use super::{collect_results, read_heap_array, write_heap_array};

const BLAKE3_BLOCK_BYTES: usize = 64;

pub(super) fn emit_blake3<M: Memory>(
    ctx: &mut TranslationCtx<'_, '_, '_, M>,
    message: &HeapArray,
    output: &HeapArray,
    opcode_index: usize,
) -> Result<(), Error> {
    if output.size.0 as usize != BLAKE3_DIGEST_BYTES {
        return Err(Error::UnsupportedBrillig {
            reason: format!(
                "BlackBox at bytecode index {opcode_index}: Blake3 requires \
                 output of size {BLAKE3_DIGEST_BYTES} (got {})",
                output.size.0,
            ),
        });
    }

    let real_len = message.size.0 as usize;
    let num_blocks = blake3_num_blocks_for_len(real_len);
    let padded_len = num_blocks * BLAKE3_BLOCK_BYTES;

    let mut args = read_heap_array(ctx, message.pointer, real_len)?;
    let zero = ctx.writer.emit_constant(&FieldElement::zero())?;
    args.resize(padded_len, zero);

    let len = real_len as u64;
    let real_length_lo = ctx
        .writer
        .emit_constant(&FieldElement::from((len & 0xFFFF_FFFF) as u128))?;
    let real_length_hi = ctx
        .writer
        .emit_constant(&FieldElement::from((len >> 32) as u128))?;
    args.push(real_length_lo);
    args.push(real_length_hi);

    let call = ctx
        .writer
        .call_blackbox_function(BlackboxFunction::Blake3 { num_blocks }, &args)?;
    let results: Vec<Value<'_, '_>> = collect_results(call, BLAKE3_DIGEST_BYTES)?;

    write_heap_array(ctx, output.pointer, BLAKE3_DIGEST_BYTES, &results)
}
