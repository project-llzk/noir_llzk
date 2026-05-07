//! `BlackBoxOp::Blake2s` lowering.
//!
//! Reads `message.size` bytes from the message HeapArray, pads with
//! felt-zero up to `num_blocks * 64`, appends the lo/hi 32-bit halves
//! of the real length as felt constants (matching the helper's
//! signature), calls `@blake2s_<num_blocks>`, and writes the
//! `BLAKE2S_DIGEST_BYTES` digest felts to the output HeapArray.

use acir::brillig::HeapArray;
use acir::{AcirField, FieldElement};
use llzk::prelude::Value;

use crate::blackboxes::{
    hash::blake2s::{BLAKE2S_DIGEST_BYTES, blake2s_num_blocks_for_len},
    registry::BlackboxFunction,
};
use crate::error::Error;
use crate::opcodes::brillig::{memory::Memory, translator::TranslationCtx};

use super::{collect_results, read_heap_array, write_heap_array};

const BLAKE2S_BLOCK_BYTES: usize = 64;

pub(super) fn emit_blake2s<M: Memory>(
    ctx: &mut TranslationCtx<'_, '_, '_, M>,
    message: &HeapArray,
    output: &HeapArray,
    opcode_index: usize,
) -> Result<(), Error> {
    if output.size.0 as usize != BLAKE2S_DIGEST_BYTES {
        return Err(Error::UnsupportedBrillig {
            reason: format!(
                "BlackBox at bytecode index {opcode_index}: Blake2s requires \
                 output of size {BLAKE2S_DIGEST_BYTES} (got {})",
                output.size.0,
            ),
        });
    }

    let real_len = message.size.0 as usize;
    let num_blocks = blake2s_num_blocks_for_len(real_len);
    let padded_len = num_blocks * BLAKE2S_BLOCK_BYTES;

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
        .call_blackbox_function(BlackboxFunction::Blake2s { num_blocks }, &args)?;
    let results: Vec<Value<'_, '_>> = collect_results(call, BLAKE2S_DIGEST_BYTES)?;

    write_heap_array(ctx, output.pointer, BLAKE2S_DIGEST_BYTES, &results)
}
