//! `BlackBoxOp::Keccakf1600` lowering.
//!
//! Reads the 25-word state HeapArray, calls the shared
//! `@keccakf1600` helper, and writes the 25-word permuted state back
//! to the output HeapArray.

use acir::brillig::HeapArray;
use llzk::prelude::Value;

use crate::blackboxes::{hash::keccak::KECCAK_STATE_WORDS, registry::BlackboxFunction};
use crate::brillig::{memory::Memory, translator::TranslationCtx};
use crate::error::Error;

use super::{collect_results, read_heap_array, write_heap_array};
use crate::writer::Writer;

pub(super) fn emit_keccakf1600<M: Memory>(
    ctx: &mut TranslationCtx<'_, '_, '_, M>,
    input: &HeapArray,
    output: &HeapArray,
    opcode_index: usize,
) -> Result<(), Error> {
    if input.size.0 as usize != KECCAK_STATE_WORDS || output.size.0 as usize != KECCAK_STATE_WORDS {
        return Err(Error::UnsupportedBrillig {
            reason: format!(
                "BlackBox at bytecode index {opcode_index}: Keccakf1600 requires \
                 input and output of size {KECCAK_STATE_WORDS} (got {} / {})",
                input.size.0, output.size.0,
            ),
        });
    }

    let inputs = read_heap_array(ctx, input.pointer, KECCAK_STATE_WORDS)?;

    let call = ctx
        .writer
        .call_blackbox_function(BlackboxFunction::Keccakf1600, &inputs)?;
    let results: Vec<Value<'_, '_>> = collect_results(call, KECCAK_STATE_WORDS)?;

    write_heap_array(ctx, output.pointer, KECCAK_STATE_WORDS, &results)
}
