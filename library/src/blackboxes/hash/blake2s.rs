use std::collections::HashMap;

use acir::FieldElement;
use llzk::prelude::{
    Block, BlockLike, FuncDefOp, FuncDefOpLike, FunctionType, Location, OperationLike, RegionLike,
    Value, dialect,
};

use crate::{
    blackboxes::common::{append_felt_constant, append_op_with_result, felt_type},
    error::Error,
};

pub(crate) const BLAKE2S_DIGEST_BYTES: usize = 32;
const BLAKE2S_BLOCK_BYTES: usize = 64;
const BLAKE2S_STATE_WORDS: usize = 8;
const BLAKE2S_WORK_VECTOR_WORDS: usize = 16;
const BLAKE2S_ROUNDS: usize = 10;

const IV: [u32; BLAKE2S_STATE_WORDS] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

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

pub(in crate::blackboxes) fn blake2s_helper_name(num_inputs: usize) -> String {
    format!("blake2s_{num_inputs}")
}

pub(in crate::blackboxes) fn emit_blake2s_helper<'c>(
    context: &'c llzk::prelude::LlzkContext,
    num_inputs: usize,
) -> Result<FuncDefOp<'c>, Error> {
    let location = Location::unknown(context);
    let felt = felt_type(context);
    let inputs = vec![(felt, location); num_inputs];
    let input_types = vec![felt; num_inputs];
    let output_types = vec![felt; BLAKE2S_DIGEST_BYTES];
    let function_type = FunctionType::new(context, &input_types, &output_types);
    let function = dialect::function::def(
        location,
        &blake2s_helper_name(num_inputs),
        function_type,
        &[],
        None,
    )?;
    function.set_allow_non_native_field_ops_attr(true);

    let block = Block::new(&inputs);
    let input_values = (0..num_inputs)
        .map(|i| block.argument(i).map(Into::into))
        .collect::<Result<Vec<Value<'c, '_>>, _>>()?;
    let outputs = emit_blake2s_hash(&block, context, location, &input_values)?;
    block.append_operation(dialect::function::r#return(location, &outputs));
    function.region(0)?.append_block(block);
    Ok(function)
}

fn emit_blake2s_hash<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    inputs: &[Value<'c, 'a>],
) -> Result<Vec<Value<'c, 'a>>, Error> {
    let mut cache = ConstantCache::new(block, context, location);
    let zero = cache.u32(0)?;
    let mut h = iv_values(&mut cache)?;
    let param = cache.u32(0x0101_0020)?;
    h[0] = emit_xor(block, location, h[0], param)?;

    let num_blocks = inputs.len().max(1).div_ceil(BLAKE2S_BLOCK_BYTES);
    for block_index in 0..num_blocks {
        let start = block_index * BLAKE2S_BLOCK_BYTES;
        let end = (start + BLAKE2S_BLOCK_BYTES).min(inputs.len());
        let mut block_bytes = [zero; BLAKE2S_BLOCK_BYTES];
        for (slot, value) in block_bytes
            .iter_mut()
            .zip(inputs[start..end].iter().copied())
        {
            *slot = value;
        }
        let message = emit_message_words(&mut cache, &block_bytes)?;
        let total_bytes = end as u64;
        let last_block = block_index + 1 == num_blocks;
        h = emit_compress(
            &mut cache,
            h,
            message,
            total_bytes as u32,
            (total_bytes >> 32) as u32,
            last_block,
        )?;
    }

    let mut digest = Vec::with_capacity(BLAKE2S_DIGEST_BYTES);
    for word in h {
        digest.extend(emit_word_to_bytes(&mut cache, word)?);
    }
    Ok(digest)
}

fn emit_message_words<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    bytes: &[Value<'c, 'a>; BLAKE2S_BLOCK_BYTES],
) -> Result<[Value<'c, 'a>; 16], Error> {
    let mut words = Vec::with_capacity(16);
    for chunk in bytes.chunks_exact(4) {
        let b0 = chunk[0];
        let b1 = emit_shl(cache, chunk[1], 8)?;
        let b2 = emit_shl(cache, chunk[2], 16)?;
        let b3 = emit_shl(cache, chunk[3], 24)?;
        let word = emit_or(
            cache.block,
            cache.location,
            emit_or(
                cache.block,
                cache.location,
                b0,
                emit_or(cache.block, cache.location, b1, b2)?,
            )?,
            b3,
        )?;
        words.push(word);
    }
    Ok(words.try_into().expect("exactly sixteen message words"))
}

fn emit_compress<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    h: [Value<'c, 'a>; BLAKE2S_STATE_WORDS],
    m: [Value<'c, 'a>; 16],
    t0: u32,
    t1: u32,
    last_block: bool,
) -> Result<[Value<'c, 'a>; BLAKE2S_STATE_WORDS], Error> {
    let mut v = [cache.u32(0)?; BLAKE2S_WORK_VECTOR_WORDS];
    v[..BLAKE2S_STATE_WORDS].copy_from_slice(&h);
    for (dst, word) in v[BLAKE2S_STATE_WORDS..].iter_mut().zip(IV) {
        *dst = cache.u32(word)?;
    }

    let t0_value = cache.u32(t0)?;
    let t1_value = cache.u32(t1)?;
    v[12] = emit_xor(cache.block, cache.location, v[12], t0_value)?;
    v[13] = emit_xor(cache.block, cache.location, v[13], t1_value)?;
    if last_block {
        let final_mask = cache.word_mask()?;
        v[14] = emit_xor(cache.block, cache.location, v[14], final_mask)?;
    }

    for sigma in SIGMA {
        emit_g(cache, &mut v, &m, sigma, (0, 4, 8, 12), 0, 1)?;
        emit_g(cache, &mut v, &m, sigma, (1, 5, 9, 13), 2, 3)?;
        emit_g(cache, &mut v, &m, sigma, (2, 6, 10, 14), 4, 5)?;
        emit_g(cache, &mut v, &m, sigma, (3, 7, 11, 15), 6, 7)?;
        emit_g(cache, &mut v, &m, sigma, (0, 5, 10, 15), 8, 9)?;
        emit_g(cache, &mut v, &m, sigma, (1, 6, 11, 12), 10, 11)?;
        emit_g(cache, &mut v, &m, sigma, (2, 7, 8, 13), 12, 13)?;
        emit_g(cache, &mut v, &m, sigma, (3, 4, 9, 14), 14, 15)?;
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

fn emit_g<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    v: &mut [Value<'c, 'a>; BLAKE2S_WORK_VECTOR_WORDS],
    m: &[Value<'c, 'a>; 16],
    sigma: [usize; 16],
    (a, b, c, d): (usize, usize, usize, usize),
    x_index: usize,
    y_index: usize,
) -> Result<(), Error> {
    v[a] = emit_wrapping_add3(cache, v[a], v[b], m[sigma[x_index]])?;
    v[d] = emit_rotr(
        cache,
        emit_xor(cache.block, cache.location, v[d], v[a])?,
        16,
    )?;
    v[c] = emit_wrapping_add(cache, v[c], v[d])?;
    v[b] = emit_rotr(
        cache,
        emit_xor(cache.block, cache.location, v[b], v[c])?,
        12,
    )?;
    v[a] = emit_wrapping_add3(cache, v[a], v[b], m[sigma[y_index]])?;
    v[d] = emit_rotr(cache, emit_xor(cache.block, cache.location, v[d], v[a])?, 8)?;
    v[c] = emit_wrapping_add(cache, v[c], v[d])?;
    v[b] = emit_rotr(cache, emit_xor(cache.block, cache.location, v[b], v[c])?, 7)?;
    Ok(())
}

fn emit_wrapping_add<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    lhs: Value<'c, 'a>,
    rhs: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    let sum = append_op_with_result(cache.block, dialect::felt::add(cache.location, lhs, rhs)?)?;
    let mask = cache.word_mask()?;
    emit_and(cache.block, cache.location, sum, mask)
}

fn emit_wrapping_add3<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    a: Value<'c, 'a>,
    b: Value<'c, 'a>,
    c: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    let sum = append_op_with_result(cache.block, dialect::felt::add(cache.location, a, b)?)?;
    let sum = append_op_with_result(cache.block, dialect::felt::add(cache.location, sum, c)?)?;
    let mask = cache.word_mask()?;
    emit_and(cache.block, cache.location, sum, mask)
}

fn emit_rotr<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    value: Value<'c, 'a>,
    amount: u32,
) -> Result<Value<'c, 'a>, Error> {
    let right = emit_shr(cache, value, amount)?;
    let left = emit_shl(cache, value, 32 - amount)?;
    let combined = emit_or(cache.block, cache.location, right, left)?;
    let mask = cache.word_mask()?;
    emit_and(cache.block, cache.location, combined, mask)
}

fn emit_word_to_bytes<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    word: Value<'c, 'a>,
) -> Result<[Value<'c, 'a>; 4], Error> {
    let mask = cache.u32(0xff)?;
    let byte0 = emit_and(cache.block, cache.location, word, mask)?;
    let shifted1 = emit_shr(cache, word, 8)?;
    let byte1 = emit_and(cache.block, cache.location, shifted1, mask)?;
    let shifted2 = emit_shr(cache, word, 16)?;
    let byte2 = emit_and(cache.block, cache.location, shifted2, mask)?;
    let shifted3 = emit_shr(cache, word, 24)?;
    let byte3 = emit_and(cache.block, cache.location, shifted3, mask)?;
    Ok([byte0, byte1, byte2, byte3])
}

fn emit_shl<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    value: Value<'c, 'a>,
    amount: u32,
) -> Result<Value<'c, 'a>, Error> {
    let amount = cache.u32(amount)?;
    append_op_with_result(
        cache.block,
        dialect::felt::shl(cache.location, value, amount)?,
    )
}

fn emit_shr<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    value: Value<'c, 'a>,
    amount: u32,
) -> Result<Value<'c, 'a>, Error> {
    let amount = cache.u32(amount)?;
    append_op_with_result(
        cache.block,
        dialect::felt::shr(cache.location, value, amount)?,
    )
}

fn emit_and<'c, 'a>(
    block: &'a Block<'c>,
    location: Location<'c>,
    lhs: Value<'c, 'a>,
    rhs: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    append_op_with_result(block, dialect::felt::bit_and(location, lhs, rhs)?)
}

fn emit_or<'c, 'a>(
    block: &'a Block<'c>,
    location: Location<'c>,
    lhs: Value<'c, 'a>,
    rhs: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    append_op_with_result(block, dialect::felt::bit_or(location, lhs, rhs)?)
}

fn emit_xor<'c, 'a>(
    block: &'a Block<'c>,
    location: Location<'c>,
    lhs: Value<'c, 'a>,
    rhs: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    append_op_with_result(block, dialect::felt::bit_xor(location, lhs, rhs)?)
}

fn iv_values<'c, 'a>(cache: &mut ConstantCache<'c, 'a>) -> Result<[Value<'c, 'a>; 8], Error> {
    let mut values = Vec::with_capacity(BLAKE2S_STATE_WORDS);
    for word in IV {
        values.push(cache.u32(word)?);
    }
    Ok(values.try_into().expect("exactly eight IV words"))
}

struct ConstantCache<'c, 'a> {
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    values: HashMap<FieldElement, Value<'c, 'a>>,
}

impl<'c, 'a> ConstantCache<'c, 'a> {
    fn new(
        block: &'a Block<'c>,
        context: &'c llzk::prelude::LlzkContext,
        location: Location<'c>,
    ) -> Self {
        Self {
            block,
            context,
            location,
            values: HashMap::new(),
        }
    }

    fn u32(&mut self, value: u32) -> Result<Value<'c, 'a>, Error> {
        self.field(FieldElement::from(u128::from(value)))
    }

    fn word_mask(&mut self) -> Result<Value<'c, 'a>, Error> {
        self.u32(u32::MAX)
    }

    fn field(&mut self, value: FieldElement) -> Result<Value<'c, 'a>, Error> {
        if let Some(&cached) = self.values.get(&value) {
            return Ok(cached);
        }
        let emitted = append_felt_constant(self.block, self.context, self.location, &value)?;
        self.values.insert(value, emitted);
        Ok(emitted)
    }
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

    fn eval_blake2s(input: &[u8]) -> [u8; 32] {
        let mut h = IV;
        h[0] ^= 0x0101_0020;

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
