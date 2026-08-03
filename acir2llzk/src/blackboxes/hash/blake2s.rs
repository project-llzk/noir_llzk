use llzk::{
    builder::OpBuilder,
    dialect::empty_region,
    prelude::{
        dialect::{self, function},
        Block, BlockLike, FuncDefOp, FuncDefOpLike, FunctionType, LlzkContext, Location,
        OperationLike, RegionLike, Value,
    },
};

use crate::{
    blackboxes::common::{
        block_args, block_args_slice, create_helper_function, ConstantCache, WordArithEmitter,
    },
    error::Error,
};

use super::common::{emit_round, iv_values, IV};

pub(crate) const BLAKE2S_DIGEST_BYTES: usize = 32;
const BLAKE2S_BLOCK_BYTES: usize = 64;
const BLAKE2S_STATE_WORDS: usize = 8;
const BLAKE2S_ROUNDS: usize = 10;
// Blake2s parameter block word 0: 0x01 (depth) | 0x01 (fanout) | 0x00 (key length) | digest size.
const BLAKE2S_PARAM_BLOCK_0: u32 = 0x0101_0000 | BLAKE2S_DIGEST_BYTES as u32;

const SIGMA: [[usize; 16]; BLAKE2S_ROUNDS] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

pub(crate) fn blake2s_num_blocks_for_len(num_inputs: usize) -> usize {
    num_inputs.max(1).div_ceil(BLAKE2S_BLOCK_BYTES)
}

pub(in crate::blackboxes) fn blake2s_helper_name(num_blocks: usize) -> String {
    format!("blake2s_blocks_{num_blocks}")
}

pub(in crate::blackboxes) fn emit_blake2s_helper<'c>(
    context: &'c LlzkContext,
    block: BlockRef<'c, '_>,
    num_blocks: usize,
) -> Result<(), Error> {
    let location = Location::unknown(context);
    let num_inputs = num_blocks * BLAKE2S_BLOCK_BYTES;
    let (function, block) = create_helper_function(
        context,
        block,
        location,
        &blake2s_helper_name(num_blocks),
        num_inputs + 2,
        BLAKE2S_DIGEST_BYTES,
    )?;
    function.set_allow_non_native_field_ops_attr(true);

    let input_values = block_args_slice(block, 0..num_inputs)?;
    let real_length_lo = block.argument(num_inputs)?.into();
    let real_length_hi = block.argument(num_inputs + 1)?.into();
    let outputs = emit_blake2s_hash(
        &mut WordArithEmitter::new(block, context, location),
        &input_values,
        real_length_lo,
        real_length_hi,
    )?;
    function::r#return(&OpBuilder::at_block_end(context, block), location, &outputs);
    Ok(())
}

fn emit_blake2s_hash<'c: 'a, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
    inputs: &[Value<'c, 'a>],
    real_length_lo: Value<'c, 'a>,
    real_length_hi: Value<'c, 'a>,
) -> Result<Vec<Value<'c, 'a>>, Error> {
    let zero = emitter.u32(0)?;
    let mut h = iv_values(emitter)?;
    let param = emitter.u32(BLAKE2S_PARAM_BLOCK_0)?;
    h[0] = emitter.emit_xor(h[0], param)?;

    let num_blocks = inputs.len() / BLAKE2S_BLOCK_BYTES;
    for block_index in 0..num_blocks {
        let start = block_index * BLAKE2S_BLOCK_BYTES;
        let end = start + BLAKE2S_BLOCK_BYTES;
        let mut block_bytes = [zero; BLAKE2S_BLOCK_BYTES];
        block_bytes[..end - start].copy_from_slice(&inputs[start..end]);
        let message_vec = emitter.emit_message_words(&block_bytes)?;
        let message: [Value<'c, 'a>; 16] = message_vec
            .try_into()
            .expect("exactly sixteen message words");
        let last_block = block_index + 1 == num_blocks;
        let (t0, t1) = if last_block {
            (real_length_lo, real_length_hi)
        } else {
            let total_bytes = end as u64;
            (
                emitter.u32(total_bytes as u32)?,
                emitter.u32((total_bytes >> 32) as u32)?,
            )
        };
        h = emit_compress(emitter, h, message, t0, t1, last_block)?;
    }

    let mut digest = Vec::with_capacity(BLAKE2S_DIGEST_BYTES);
    for word in h {
        digest.extend(emitter.emit_word_to_bytes(word)?);
    }
    Ok(digest)
}

fn emit_compress<'c: 'a, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
    h: [Value<'c, 'a>; BLAKE2S_STATE_WORDS],
    m: [Value<'c, 'a>; 16],
    t0: Value<'c, 'a>,
    t1: Value<'c, 'a>,
    last_block: bool,
) -> Result<[Value<'c, 'a>; BLAKE2S_STATE_WORDS], Error> {
    let mut v = [emitter.u32(0)?; 16];
    v[..BLAKE2S_STATE_WORDS].copy_from_slice(&h);
    for (dst, word) in v[BLAKE2S_STATE_WORDS..].iter_mut().zip(IV) {
        *dst = emitter.u32(word)?;
    }

    v[12] = emitter.emit_xor(v[12], t0)?;
    v[13] = emitter.emit_xor(v[13], t1)?;
    if last_block {
        let final_mask = emitter.word_mask()?;
        v[14] = emitter.emit_xor(v[14], final_mask)?;
    }

    for sigma in SIGMA {
        emit_round(emitter, &mut v, &m, &sigma)?;
    }

    let mut next_h = Vec::with_capacity(BLAKE2S_STATE_WORDS);
    for i in 0..BLAKE2S_STATE_WORDS {
        next_h.push(emitter.emit_xor(emitter.emit_xor(h[i], v[i])?, v[i + BLAKE2S_STATE_WORDS])?);
    }
    Ok(next_h.try_into().expect("exactly eight state words"))
}
