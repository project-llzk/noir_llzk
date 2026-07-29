//! `BlackBoxOp::Sha256Compression` lowering.
//!
//! Reads the 16-felt block + 8-felt previous-state HeapArrays, calls
//! the shared `@sha256_compression` helper, and writes the 8-felt new
//! state to the output HeapArray.

use acir::brillig::HeapArray;
use llzk::prelude::Value;

use crate::blackboxes::{hash::sha256::SHA256_STATE_WORDS, registry::BlackboxFunction};
use crate::brillig::translator::TranslationCtx;
use crate::error::Error;

use super::{collect_results, read_heap_array, write_heap_array};
use crate::writer::Writer;

const SHA256_BLOCK_WORDS: usize = 16;

pub(super) fn emit_sha256_compression(
    ctx: &mut TranslationCtx<'_, '_, '_>,
    input: &HeapArray,
    hash_values: &HeapArray,
    output: &HeapArray,
    opcode_index: usize,
) -> Result<(), Error> {
    if input.size.0 as usize != SHA256_BLOCK_WORDS
        || hash_values.size.0 as usize != SHA256_STATE_WORDS
        || output.size.0 as usize != SHA256_STATE_WORDS
    {
        return Err(Error::UnsupportedBrillig {
            reason: format!(
                "BlackBox at bytecode index {opcode_index}: Sha256Compression requires \
                 input of size {SHA256_BLOCK_WORDS}, hash_values and output of size \
                 {SHA256_STATE_WORDS} (got {} / {} / {})",
                input.size.0, hash_values.size.0, output.size.0,
            ),
        });
    }

    let mut args = read_heap_array(ctx, input.pointer, SHA256_BLOCK_WORDS)?;
    args.extend(read_heap_array(
        ctx,
        hash_values.pointer,
        SHA256_STATE_WORDS,
    )?);

    let call = ctx
        .writer
        .call_blackbox_function(BlackboxFunction::Sha256Compression, &args)?;
    let results: Vec<Value<'_, '_>> = collect_results(call, SHA256_STATE_WORDS)?;

    write_heap_array(ctx, output.pointer, SHA256_STATE_WORDS, &results)
}
