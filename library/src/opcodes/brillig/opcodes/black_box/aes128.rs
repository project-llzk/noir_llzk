//! `BlackBoxOp::AES128Encrypt` lowering.
//!
//! Reads the inputs, IV (16 felts), and key (16 felts) HeapArrays in
//! that order — matching the helper's `inputs ++ iv ++ key` argument
//! layout — calls `@aes128_encrypt_<num_inputs>`, and writes the
//! `num_inputs` ciphertext felts to the outputs HeapArray. `inputs`
//! must be a non-zero multiple of `AES_BLOCK_SIZE` (16) and `outputs`
//! must match its length.

use acir::brillig::HeapArray;
use llzk::prelude::Value;

use crate::blackboxes::{cipher::aes128::AES_BLOCK_SIZE, registry::BlackboxFunction};
use crate::error::Error;
use crate::opcodes::brillig::{memory::Memory, translator::TranslationCtx};

use super::{collect_results, read_heap_array, write_heap_array};

pub(super) fn emit_aes128<M: Memory>(
    ctx: &mut TranslationCtx<'_, '_, '_, M>,
    inputs: &HeapArray,
    iv: &HeapArray,
    key: &HeapArray,
    outputs: &HeapArray,
    opcode_index: usize,
) -> Result<(), Error> {
    let num_inputs = inputs.size.0 as usize;
    if num_inputs == 0 || !num_inputs.is_multiple_of(AES_BLOCK_SIZE) {
        return Err(Error::UnsupportedBrillig {
            reason: format!(
                "BlackBox at bytecode index {opcode_index}: AES128Encrypt input length {num_inputs} \
                 must be a non-zero multiple of {AES_BLOCK_SIZE}"
            ),
        });
    }
    if iv.size.0 as usize != AES_BLOCK_SIZE || key.size.0 as usize != AES_BLOCK_SIZE {
        return Err(Error::UnsupportedBrillig {
            reason: format!(
                "BlackBox at bytecode index {opcode_index}: AES128Encrypt IV and key must be of \
                 size {AES_BLOCK_SIZE} (got iv={} key={})",
                iv.size.0, key.size.0,
            ),
        });
    }
    if outputs.size.0 as usize != num_inputs {
        return Err(Error::UnsupportedBrillig {
            reason: format!(
                "BlackBox at bytecode index {opcode_index}: AES128Encrypt output length {} \
                 must match input length {num_inputs}",
                outputs.size.0,
            ),
        });
    }

    let mut args = read_heap_array(ctx, inputs.pointer, num_inputs)?;
    args.extend(read_heap_array(ctx, iv.pointer, AES_BLOCK_SIZE)?);
    args.extend(read_heap_array(ctx, key.pointer, AES_BLOCK_SIZE)?);

    let call = ctx
        .writer
        .call_blackbox_function(BlackboxFunction::Aes128Encrypt { num_inputs }, &args)?;
    let results: Vec<Value<'_, '_>> = collect_results(call, num_inputs)?;

    write_heap_array(ctx, outputs.pointer, num_inputs, &results)
}
