use llzk::prelude::{
    Block, BlockLike, FuncDefOp, FuncDefOpLike, FunctionType, Location, OperationLike, RegionLike,
    Value, dialect,
};

use crate::{blackboxes::common::felt_type, error::Error};

use super::common::{ConstantCache, IV, emit_round, emit_word_to_bytes, emit_xor, iv_values};

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

fn blake2s_capacity_bytes(num_blocks: usize) -> usize {
    num_blocks * BLAKE2S_BLOCK_BYTES
}

pub(in crate::blackboxes) fn blake2s_helper_name(num_blocks: usize) -> String {
    format!("blake2s_blocks_{num_blocks}")
}

pub(in crate::blackboxes) fn emit_blake2s_helper<'c>(
    context: &'c llzk::prelude::LlzkContext,
    num_blocks: usize,
) -> Result<FuncDefOp<'c>, Error> {
    let location = Location::unknown(context);
    let felt = felt_type(context);
    let num_inputs = blake2s_capacity_bytes(num_blocks);
    let inputs = vec![(felt, location); num_inputs + 2];
    let input_types = vec![felt; num_inputs + 2];
    let output_types = vec![felt; BLAKE2S_DIGEST_BYTES];
    let function_type = FunctionType::new(context, &input_types, &output_types);
    let function = dialect::function::def(
        location,
        &blake2s_helper_name(num_blocks),
        function_type,
        &[],
        None,
    )?;
    function.set_allow_non_native_field_ops_attr(true);

    let block = Block::new(&inputs);
    let input_values = (0..num_inputs)
        .map(|i| block.argument(i).map(Into::into))
        .collect::<Result<Vec<Value<'c, '_>>, _>>()?;
    let real_length_lo = block.argument(num_inputs)?.into();
    let real_length_hi = block.argument(num_inputs + 1)?.into();
    let outputs = emit_blake2s_hash(
        &block,
        context,
        location,
        &input_values,
        real_length_lo,
        real_length_hi,
    )?;
    block.append_operation(dialect::function::r#return(location, &outputs));
    function.region(0)?.append_block(block);
    Ok(function)
}

fn emit_blake2s_hash<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    inputs: &[Value<'c, 'a>],
    real_length_lo: Value<'c, 'a>,
    real_length_hi: Value<'c, 'a>,
) -> Result<Vec<Value<'c, 'a>>, Error> {
    let mut cache = ConstantCache::new(block, context, location);
    let zero = cache.u32(0)?;
    let mut h = iv_values(&mut cache)?;
    let param = cache.u32(BLAKE2S_PARAM_BLOCK_0)?;
    h[0] = emit_xor(block, location, h[0], param)?;

    let num_blocks = inputs.len() / BLAKE2S_BLOCK_BYTES;
    for block_index in 0..num_blocks {
        let start = block_index * BLAKE2S_BLOCK_BYTES;
        let end = start + BLAKE2S_BLOCK_BYTES;
        let mut block_bytes = [zero; BLAKE2S_BLOCK_BYTES];
        block_bytes[..end - start].copy_from_slice(&inputs[start..end]);
        let message_vec = super::common::emit_message_words(&mut cache, &block_bytes)?;
        let message: [Value<'c, 'a>; 16] = message_vec
            .try_into()
            .expect("exactly sixteen message words");
        let last_block = block_index + 1 == num_blocks;
        let (t0, t1) = if last_block {
            (real_length_lo, real_length_hi)
        } else {
            let total_bytes = end as u64;
            (
                cache.u32(total_bytes as u32)?,
                cache.u32((total_bytes >> 32) as u32)?,
            )
        };
        h = emit_compress(&mut cache, h, message, t0, t1, last_block)?;
    }

    let mut digest = Vec::with_capacity(BLAKE2S_DIGEST_BYTES);
    for word in h {
        digest.extend(emit_word_to_bytes(&mut cache, word)?);
    }
    Ok(digest)
}

fn emit_compress<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    h: [Value<'c, 'a>; BLAKE2S_STATE_WORDS],
    m: [Value<'c, 'a>; 16],
    t0: Value<'c, 'a>,
    t1: Value<'c, 'a>,
    last_block: bool,
) -> Result<[Value<'c, 'a>; BLAKE2S_STATE_WORDS], Error> {
    let mut v = [cache.u32(0)?; 16];
    v[..BLAKE2S_STATE_WORDS].copy_from_slice(&h);
    for (dst, word) in v[BLAKE2S_STATE_WORDS..].iter_mut().zip(IV) {
        *dst = cache.u32(word)?;
    }

    v[12] = emit_xor(cache.block, cache.location, v[12], t0)?;
    v[13] = emit_xor(cache.block, cache.location, v[13], t1)?;
    if last_block {
        let final_mask = cache.word_mask()?;
        v[14] = emit_xor(cache.block, cache.location, v[14], final_mask)?;
    }

    for sigma in SIGMA {
        emit_round(cache, &mut v, &m, &sigma)?;
    }

    let mut next_h = Vec::with_capacity(BLAKE2S_STATE_WORDS);
    for i in 0..BLAKE2S_STATE_WORDS {
        next_h.push(emit_xor(
            cache.block,
            cache.location,
            emit_xor(cache.block, cache.location, h[i], v[i])?,
            v[i + BLAKE2S_STATE_WORDS],
        )?);
    }
    Ok(next_h.try_into().expect("exactly eight state words"))
}

#[cfg(test)]
mod tests {
    use super::{IV, SIGMA};

    #[test]
    fn empty_input_matches_known_vector() {
        assert_eq!(
            eval_blake2s(&[]),
            [
                0x69, 0x21, 0x7a, 0x30, 0x79, 0x90, 0x80, 0x94, 0xe1, 0x11, 0x21, 0xd0, 0x42, 0x35,
                0x4a, 0x7c, 0x1f, 0x55, 0xb6, 0x48, 0x2c, 0xa1, 0xa5, 0x1e, 0x1b, 0x25, 0x0d, 0xfd,
                0x1e, 0xd0, 0xee, 0xf9,
            ]
        );
    }

    #[test]
    fn abc_matches_known_vector() {
        assert_eq!(
            eval_blake2s(b"abc"),
            [
                0x50, 0x8c, 0x5e, 0x8c, 0x32, 0x7c, 0x14, 0xe2, 0xe1, 0xa7, 0x2b, 0xa3, 0x4e, 0xeb,
                0x45, 0x2f, 0x37, 0x45, 0x8b, 0x20, 0x9e, 0xd6, 0x3a, 0x29, 0x4d, 0x99, 0x9b, 0x4c,
                0x86, 0x67, 0x59, 0x82,
            ]
        );
    }

    #[test]
    fn eighty_bytes_match_known_vector() {
        let input: Vec<u8> = (0..80).collect();
        assert_eq!(
            eval_blake2s(&input),
            [
                0xaf, 0xf3, 0xb7, 0x5f, 0x3f, 0x58, 0x12, 0x64, 0xd7, 0x66, 0x16, 0x62, 0xb9, 0x2f,
                0x5a, 0xd3, 0x7c, 0x1d, 0x32, 0xbd, 0x45, 0xff, 0x81, 0xa4, 0xed, 0x8a, 0xdc, 0x9e,
                0xf3, 0x0d, 0xd9, 0x89,
            ]
        );
    }

    fn eval_blake2s(input: &[u8]) -> [u8; 32] {
        let mut h = IV;
        h[0] ^= super::BLAKE2S_PARAM_BLOCK_0;

        let num_blocks = input.len().max(1).div_ceil(64);
        for block_index in 0..num_blocks {
            let start = block_index * 64;
            let end = (start + 64).min(input.len());
            let mut block = [0u8; 64];
            block[..end - start].copy_from_slice(&input[start..end]);

            let mut m = [0u32; 16];
            for (word, chunk) in m.iter_mut().zip(block.chunks_exact(4)) {
                *word = u32::from_le_bytes(chunk.try_into().expect("four bytes"));
            }

            h = compress(
                h,
                m,
                end as u32,
                ((end as u64) >> 32) as u32,
                block_index + 1 == num_blocks,
            );
        }

        let mut digest = [0u8; 32];
        for (chunk, word) in digest.chunks_exact_mut(4).zip(h) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        digest
    }

    fn compress(mut h: [u32; 8], m: [u32; 16], t0: u32, t1: u32, last_block: bool) -> [u32; 8] {
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= t0;
        v[13] ^= t1;
        if last_block {
            v[14] ^= u32::MAX;
        }

        for sigma in SIGMA {
            g(&mut v, &m, sigma, (0, 4, 8, 12), 0, 1);
            g(&mut v, &m, sigma, (1, 5, 9, 13), 2, 3);
            g(&mut v, &m, sigma, (2, 6, 10, 14), 4, 5);
            g(&mut v, &m, sigma, (3, 7, 11, 15), 6, 7);
            g(&mut v, &m, sigma, (0, 5, 10, 15), 8, 9);
            g(&mut v, &m, sigma, (1, 6, 11, 12), 10, 11);
            g(&mut v, &m, sigma, (2, 7, 8, 13), 12, 13);
            g(&mut v, &m, sigma, (3, 4, 9, 14), 14, 15);
        }

        for i in 0..8 {
            h[i] ^= v[i] ^ v[i + 8];
        }
        h
    }

    fn g(
        v: &mut [u32; 16],
        m: &[u32; 16],
        sigma: [usize; 16],
        (a, b, c, d): (usize, usize, usize, usize),
        x_index: usize,
        y_index: usize,
    ) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[sigma[x_index]]);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(12);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[sigma[y_index]]);
        v[d] = (v[d] ^ v[a]).rotate_right(8);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(7);
    }
}
