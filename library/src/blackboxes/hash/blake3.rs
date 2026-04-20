use llzk::prelude::{
    Block, BlockLike, FuncDefOp, FuncDefOpLike, FunctionType, Location, OperationLike, RegionLike,
    Value, dialect,
};

use crate::{
    blackboxes::common::{
        ConstantCache, emit_message_words, emit_word_to_bytes, emit_xor, felt_type,
    },
    error::Error,
};

use super::common::{IV, emit_g, iv_values};

pub(crate) const BLAKE3_DIGEST_BYTES: usize = 32;
const BLOCK_BYTES: usize = 64;
const CHUNK_BYTES: usize = 1024;
const BLAKE3_ROUNDS: usize = 7;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

pub(crate) fn blake3_num_blocks_for_len(num_inputs: usize) -> usize {
    num_inputs.max(1).div_ceil(BLOCK_BYTES)
}

fn blake3_capacity_bytes(num_blocks: usize) -> usize {
    num_blocks * BLOCK_BYTES
}

pub(in crate::blackboxes) fn blake3_helper_name(num_blocks: usize) -> String {
    format!("blake3_blocks_{num_blocks}")
}

pub(in crate::blackboxes) fn emit_blake3_helper<'c>(
    context: &'c llzk::prelude::LlzkContext,
    num_blocks: usize,
) -> Result<FuncDefOp<'c>, Error> {
    let location = Location::unknown(context);
    let felt = felt_type(context);
    let num_inputs = blake3_capacity_bytes(num_blocks);
    let inputs = vec![(felt, location); num_inputs + 1];
    let input_types = vec![felt; num_inputs + 1];
    let output_types = vec![felt; BLAKE3_DIGEST_BYTES];
    let function_type = FunctionType::new(context, &input_types, &output_types);
    let function = dialect::function::def(
        location,
        &blake3_helper_name(num_blocks),
        function_type,
        &[],
        None,
    )?;
    function.set_allow_non_native_field_ops_attr(true);

    let block = Block::new(&inputs);
    let input_values = (0..num_inputs)
        .map(|i| block.argument(i).map(Into::into))
        .collect::<Result<Vec<Value<'c, '_>>, _>>()?;
    let final_block_len = block.argument(num_inputs)?.into();
    let outputs = emit_blake3_hash(&block, context, location, &input_values, final_block_len)?;
    block.append_operation(dialect::function::r#return(location, &outputs));
    function.region(0)?.append_block(block);
    Ok(function)
}

struct EmitOutput<'c, 'a> {
    input_cv: [Value<'c, 'a>; 8],
    block_words: [Value<'c, 'a>; 16],
    counter: u64,
    block_len: Value<'c, 'a>,
    flags: u32,
}

fn emit_blake3_hash<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    inputs: &[Value<'c, 'a>],
    final_block_len: Value<'c, 'a>,
) -> Result<Vec<Value<'c, 'a>>, Error> {
    let mut cache = ConstantCache::new(block, context, location);
    let key_words = iv_values(&mut cache)?;

    let num_blocks = inputs.len() / BLOCK_BYTES;
    let num_chunks = num_blocks.div_ceil(CHUNK_BYTES / BLOCK_BYTES);
    let mut cv_stack: Vec<[Value<'c, 'a>; 8]> = Vec::new();

    for chunk_index in 0..num_chunks - 1 {
        let chunk_start = chunk_index * CHUNK_BYTES;
        let chunk_end = chunk_start + CHUNK_BYTES;
        let chunk_data = &inputs[chunk_start..chunk_end];

        let output =
            emit_chunk_output(&mut cache, &key_words, chunk_data, chunk_index as u64, None)?;
        let mut new_cv = emit_output_cv(&mut cache, &output)?;
        let mut total = chunk_index + 1;
        while total & 1 == 0 {
            let left = cv_stack.pop().expect("stack should have a value");
            new_cv = emit_parent_cv(&mut cache, &key_words, &left, &new_cv)?;
            total >>= 1;
        }
        cv_stack.push(new_cv);
    }

    let last_chunk_index = num_chunks - 1;
    let last_chunk_start = last_chunk_index * CHUNK_BYTES;
    let last_chunk_data = &inputs[last_chunk_start..];
    let mut output = emit_chunk_output(
        &mut cache,
        &key_words,
        last_chunk_data,
        last_chunk_index as u64,
        Some(final_block_len),
    )?;

    if num_chunks == 1 {
        return emit_root_output_bytes(&mut cache, output);
    }

    for i in (0..cv_stack.len()).rev() {
        let cv = emit_output_cv(&mut cache, &output)?;
        output = emit_parent_output(&mut cache, &key_words, &cv_stack[i], &cv)?;
    }
    emit_root_output_bytes(&mut cache, output)
}

fn emit_output_cv<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    output: &EmitOutput<'c, 'a>,
) -> Result<[Value<'c, 'a>; 8], Error> {
    emit_compress(
        cache,
        &output.input_cv,
        &output.block_words,
        output.counter,
        output.block_len,
        output.flags,
    )
}

fn emit_root_output_bytes<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    output: EmitOutput<'c, 'a>,
) -> Result<Vec<Value<'c, 'a>>, Error> {
    let full = emit_compress_full(
        cache,
        &output.input_cv,
        &output.block_words,
        0,
        output.block_len,
        output.flags | ROOT,
    )?;
    let mut digest = Vec::with_capacity(BLAKE3_DIGEST_BYTES);
    for word in full.iter().take(8) {
        digest.extend(emit_word_to_bytes(cache, *word)?);
    }
    Ok(digest)
}

fn emit_chunk_output<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    key_words: &[Value<'c, 'a>; 8],
    chunk_data: &[Value<'c, 'a>],
    chunk_counter: u64,
    final_block_len: Option<Value<'c, 'a>>,
) -> Result<EmitOutput<'c, 'a>, Error> {
    let zero = cache.u32(0)?;
    let num_blocks = chunk_data.len() / BLOCK_BYTES;
    let mut cv = *key_words;

    for block_index in 0..num_blocks {
        let block_start = block_index * BLOCK_BYTES;
        let block_end = block_start + BLOCK_BYTES;

        let mut padded_block = vec![zero; BLOCK_BYTES];
        padded_block[..block_end - block_start]
            .copy_from_slice(&chunk_data[block_start..block_end]);
        let words_vec = emit_message_words(cache, &padded_block)?;
        let block_words: [Value<'c, 'a>; 16] = words_vec.try_into().expect("exactly sixteen words");

        let mut flags = 0u32;
        if block_index == 0 {
            flags |= CHUNK_START;
        }
        let is_last = block_index == num_blocks - 1;
        let block_len = if is_last {
            final_block_len.unwrap_or(cache.u32(BLOCK_BYTES as u32)?)
        } else {
            cache.u32(BLOCK_BYTES as u32)?
        };
        if is_last {
            flags |= CHUNK_END;
            return Ok(EmitOutput {
                input_cv: cv,
                block_words,
                counter: chunk_counter,
                block_len,
                flags,
            });
        }

        cv = emit_compress(cache, &cv, &block_words, chunk_counter, block_len, flags)?;
    }
    unreachable!()
}

fn emit_parent_output<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    key_words: &[Value<'c, 'a>; 8],
    left: &[Value<'c, 'a>; 8],
    right: &[Value<'c, 'a>; 8],
) -> Result<EmitOutput<'c, 'a>, Error> {
    let zero = cache.u32(0)?;
    let mut block_words = [zero; 16];
    block_words[..8].copy_from_slice(left);
    block_words[8..].copy_from_slice(right);
    Ok(EmitOutput {
        input_cv: *key_words,
        block_words,
        counter: 0,
        block_len: cache.u32(BLOCK_BYTES as u32)?,
        flags: PARENT,
    })
}

fn emit_parent_cv<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    key_words: &[Value<'c, 'a>; 8],
    left: &[Value<'c, 'a>; 8],
    right: &[Value<'c, 'a>; 8],
) -> Result<[Value<'c, 'a>; 8], Error> {
    let mut block_words = [cache.u32(0)?; 16];
    block_words[..8].copy_from_slice(left);
    block_words[8..].copy_from_slice(right);
    let block_len = cache.u32(BLOCK_BYTES as u32)?;
    emit_compress(cache, key_words, &block_words, 0, block_len, PARENT)
}

fn emit_compress<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    h: &[Value<'c, 'a>; 8],
    m: &[Value<'c, 'a>; 16],
    counter: u64,
    block_len: Value<'c, 'a>,
    flags: u32,
) -> Result<[Value<'c, 'a>; 8], Error> {
    let v = emit_compress_raw(cache, h, m, counter, block_len, flags)?;
    let mut result = [v[0]; 8];
    for i in 0..8 {
        result[i] = emit_xor(cache.block, cache.location, v[i], v[i + 8])?;
    }
    Ok(result)
}

fn emit_compress_full<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    h: &[Value<'c, 'a>; 8],
    m: &[Value<'c, 'a>; 16],
    counter: u64,
    block_len: Value<'c, 'a>,
    flags: u32,
) -> Result<[Value<'c, 'a>; 16], Error> {
    let v = emit_compress_raw(cache, h, m, counter, block_len, flags)?;
    let mut out = [v[0]; 16];
    for i in 0..8 {
        out[i] = emit_xor(cache.block, cache.location, v[i], v[i + 8])?;
        out[i + 8] = emit_xor(cache.block, cache.location, v[i + 8], h[i])?;
    }
    Ok(out)
}

fn emit_compress_raw<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    h: &[Value<'c, 'a>; 8],
    m: &[Value<'c, 'a>; 16],
    counter: u64,
    block_len: Value<'c, 'a>,
    flags: u32,
) -> Result<[Value<'c, 'a>; 16], Error> {
    let mut v = [cache.u32(0)?; 16];
    v[..8].copy_from_slice(h);
    for i in 0..4 {
        v[8 + i] = cache.u32(IV[i])?;
    }
    let counter_lo = (counter & 0xFFFF_FFFF) as u32;
    let counter_hi = (counter >> 32) as u32;
    v[12] = cache.u32(counter_lo)?;
    v[13] = cache.u32(counter_hi)?;
    v[14] = block_len;
    v[15] = cache.u32(flags)?;

    let mut msg = *m;
    for round in 0..BLAKE3_ROUNDS {
        emit_g(cache, &mut v, (0, 4, 8, 12), msg[0], msg[1])?;
        emit_g(cache, &mut v, (1, 5, 9, 13), msg[2], msg[3])?;
        emit_g(cache, &mut v, (2, 6, 10, 14), msg[4], msg[5])?;
        emit_g(cache, &mut v, (3, 7, 11, 15), msg[6], msg[7])?;
        emit_g(cache, &mut v, (0, 5, 10, 15), msg[8], msg[9])?;
        emit_g(cache, &mut v, (1, 6, 11, 12), msg[10], msg[11])?;
        emit_g(cache, &mut v, (2, 7, 8, 13), msg[12], msg[13])?;
        emit_g(cache, &mut v, (3, 4, 9, 14), msg[14], msg[15])?;
        if round < BLAKE3_ROUNDS - 1 {
            msg = permute_message(&msg);
        }
    }

    Ok(v)
}

fn permute_message<'c, 'a>(m: &[Value<'c, 'a>; 16]) -> [Value<'c, 'a>; 16] {
    std::array::from_fn(|i| m[MSG_PERMUTATION[i]])
}

#[cfg(test)]
mod tests {
    use super::{
        BLAKE3_ROUNDS, BLOCK_BYTES, CHUNK_BYTES, CHUNK_END, CHUNK_START, IV, MSG_PERMUTATION,
        PARENT, ROOT,
    };

    #[test]
    fn empty_input_matches_known_vector() {
        let digest = eval_blake3(&[]);
        assert_eq!(
            digest,
            [
                0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc,
                0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca,
                0xe4, 0x1f, 0x32, 0x62,
            ]
        );
    }

    #[test]
    fn abc_matches_known_vector() {
        let digest = eval_blake3(b"abc");
        // Blake3 official test vector for "abc" (verified with blake3 crate)
        assert_eq!(
            digest,
            [
                0x64, 0x37, 0xb3, 0xac, 0x38, 0x46, 0x51, 0x33, 0xff, 0xb6, 0x3b, 0x75, 0x27, 0x3a,
                0x8d, 0xb5, 0x48, 0xc5, 0x58, 0x46, 0x5d, 0x79, 0xdb, 0x03, 0xfd, 0x35, 0x9c, 0x6c,
                0xd5, 0xbd, 0x9d, 0x85,
            ]
        );
    }

    #[test]
    fn eighty_bytes_match_known_vector() {
        let input: Vec<u8> = (0..80).collect();
        let digest = eval_blake3(&input);
        assert_eq!(
            digest,
            [
                0x4a, 0x68, 0x47, 0xef, 0x66, 0xbc, 0xe6, 0xc1, 0x4c, 0xa0, 0x5e, 0xc8, 0xf8, 0xad,
                0x73, 0x83, 0xbf, 0x29, 0x31, 0xf4, 0xbc, 0xfd, 0x03, 0x73, 0xc1, 0x8e, 0x05, 0x9e,
                0x93, 0xf9, 0xde, 0xf6,
            ]
        );
    }

    #[test]
    fn two_chunk_input_matches_known_vector() {
        // 1025 bytes = 2 chunks (power-of-two chunk count).
        let input: Vec<u8> = (0u8..=255).cycle().take(1025).collect();
        let digest = eval_blake3(&input);
        assert_eq!(
            digest,
            [
                0x3e, 0x85, 0xe5, 0xa7, 0xff, 0xcd, 0x07, 0xc2, 0x37, 0x94, 0xc0, 0x79, 0xd4, 0x3e,
                0xbb, 0x27, 0x37, 0x2d, 0x06, 0xbb, 0x1f, 0x75, 0xe4, 0xb4, 0x77, 0x32, 0xfc, 0xaa,
                0xf1, 0xa8, 0xcf, 0x3d,
            ]
        );
    }

    #[test]
    fn two_full_chunks_matches_known_vector() {
        // 2048 bytes = 2 full chunks (power-of-two, exactly fills both chunks).
        let input: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
        let digest = eval_blake3(&input);
        assert_eq!(
            digest,
            [
                0x1b, 0xdc, 0xcf, 0xde, 0x02, 0x10, 0xa8, 0xca, 0x17, 0x8b, 0xe1, 0x9c, 0x67, 0x77,
                0xcd, 0xb4, 0xb9, 0xa8, 0xfd, 0x24, 0xe7, 0xfe, 0x2b, 0x6b, 0x25, 0x9b, 0x98, 0xe7,
                0xaa, 0xaa, 0x0b, 0xb6,
            ]
        );
    }

    // Reference implementation matching the Blake3 spec.
    fn eval_blake3(input: &[u8]) -> [u8; 32] {
        let key_words = IV;
        let mut cv_stack: Vec<[u32; 8]> = Vec::new();

        let num_chunks = input.len().max(1).div_ceil(CHUNK_BYTES);

        // Process all chunks except the last, reducing CVs into the stack.
        for chunk_index in 0..num_chunks - 1 {
            let chunk_start = chunk_index * CHUNK_BYTES;
            let chunk_end = (chunk_start + CHUNK_BYTES).min(input.len());
            let chunk_data = &input[chunk_start..chunk_end];

            let output = chunk_output(&key_words, chunk_data, chunk_index as u64);
            let mut new_cv = output.chaining_value();
            let mut total = chunk_index + 1;
            while total & 1 == 0 {
                let left = cv_stack.pop().unwrap();
                new_cv = parent_cv(&key_words, &left, &new_cv);
                total >>= 1;
            }
            cv_stack.push(new_cv);
        }

        // Process last chunk, keeping its output node for ROOT finalization.
        let last_start = (num_chunks - 1) * CHUNK_BYTES;
        let last_end = (last_start + CHUNK_BYTES).min(input.len());
        let last_data = if last_start < input.len() {
            &input[last_start..last_end]
        } else {
            &[]
        };
        let mut output = chunk_output(&key_words, last_data, (num_chunks - 1) as u64);

        if num_chunks == 1 {
            return root_output_bytes(&output);
        }

        // Merge last chunk's output through the stack (top to bottom).
        for i in (0..cv_stack.len()).rev() {
            let cv = output.chaining_value();
            output = parent_output(&key_words, &cv_stack[i], &cv);
        }
        root_output_bytes(&output)
    }

    struct Output {
        input_cv: [u32; 8],
        block_words: [u32; 16],
        counter: u64,
        block_len: u32,
        flags: u32,
    }

    impl Output {
        fn chaining_value(&self) -> [u32; 8] {
            compress(
                &self.input_cv,
                &self.block_words,
                self.counter,
                self.block_len,
                self.flags,
            )
        }
    }

    fn root_output_bytes(output: &Output) -> [u8; 32] {
        let full = compress_full(
            &output.input_cv,
            &output.block_words,
            0,
            output.block_len,
            output.flags | ROOT,
        );
        words_to_bytes(&full[..8])
    }

    fn chunk_output(key_words: &[u32; 8], chunk_data: &[u8], chunk_counter: u64) -> Output {
        let mut cv = *key_words;
        let num_blocks = chunk_data.len().max(1).div_ceil(BLOCK_BYTES);

        for block_index in 0..num_blocks {
            let block_start = block_index * BLOCK_BYTES;
            let block_end = (block_start + BLOCK_BYTES).min(chunk_data.len());
            let mut block = [0u8; BLOCK_BYTES];
            if block_start < chunk_data.len() {
                block[..block_end - block_start]
                    .copy_from_slice(&chunk_data[block_start..block_end]);
            }
            let m = bytes_to_words(&block);
            let block_len = (block_end - block_start) as u32;

            let mut flags = 0u32;
            if block_index == 0 {
                flags |= CHUNK_START;
            }
            let is_last = block_index == num_blocks - 1;
            if is_last {
                flags |= CHUNK_END;
                return Output {
                    input_cv: cv,
                    block_words: m,
                    counter: chunk_counter,
                    block_len,
                    flags,
                };
            }

            cv = compress(&cv, &m, chunk_counter, block_len, flags);
        }
        unreachable!()
    }

    fn parent_output(key_words: &[u32; 8], left: &[u32; 8], right: &[u32; 8]) -> Output {
        let mut block_words = [0u32; 16];
        block_words[..8].copy_from_slice(left);
        block_words[8..].copy_from_slice(right);
        Output {
            input_cv: *key_words,
            block_words,
            counter: 0,
            block_len: BLOCK_BYTES as u32,
            flags: PARENT,
        }
    }

    fn parent_cv(key_words: &[u32; 8], left: &[u32; 8], right: &[u32; 8]) -> [u32; 8] {
        let mut block_words = [0u32; 16];
        block_words[..8].copy_from_slice(left);
        block_words[8..].copy_from_slice(right);
        compress(key_words, &block_words, 0, BLOCK_BYTES as u32, PARENT)
    }

    fn compress(h: &[u32; 8], m: &[u32; 16], counter: u64, block_len: u32, flags: u32) -> [u32; 8] {
        let v = compress_raw(h, m, counter, block_len, flags);
        let mut result = [0u32; 8];
        for i in 0..8 {
            result[i] = v[i] ^ v[i + 8];
        }
        result
    }

    fn compress_full(
        h: &[u32; 8],
        m: &[u32; 16],
        counter: u64,
        block_len: u32,
        flags: u32,
    ) -> [u32; 16] {
        let v = compress_raw(h, m, counter, block_len, flags);
        let mut out = [0u32; 16];
        for i in 0..8 {
            out[i] = v[i] ^ v[i + 8];
            out[i + 8] = v[i + 8] ^ h[i];
        }
        out
    }

    fn compress_raw(
        h: &[u32; 8],
        m: &[u32; 16],
        counter: u64,
        block_len: u32,
        flags: u32,
    ) -> [u32; 16] {
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(h);
        v[8] = IV[0];
        v[9] = IV[1];
        v[10] = IV[2];
        v[11] = IV[3];
        v[12] = (counter & 0xFFFF_FFFF) as u32;
        v[13] = (counter >> 32) as u32;
        v[14] = block_len;
        v[15] = flags;

        let mut msg = *m;
        for round in 0..BLAKE3_ROUNDS {
            g(&mut v, msg[0], msg[1], 0, 4, 8, 12);
            g(&mut v, msg[2], msg[3], 1, 5, 9, 13);
            g(&mut v, msg[4], msg[5], 2, 6, 10, 14);
            g(&mut v, msg[6], msg[7], 3, 7, 11, 15);
            g(&mut v, msg[8], msg[9], 0, 5, 10, 15);
            g(&mut v, msg[10], msg[11], 1, 6, 11, 12);
            g(&mut v, msg[12], msg[13], 2, 7, 8, 13);
            g(&mut v, msg[14], msg[15], 3, 4, 9, 14);
            if round < BLAKE3_ROUNDS - 1 {
                let mut permuted = [0u32; 16];
                for (i, &p) in MSG_PERMUTATION.iter().enumerate() {
                    permuted[i] = msg[p];
                }
                msg = permuted;
            }
        }
        v
    }

    fn g(v: &mut [u32; 16], x: u32, y: u32, a: usize, b: usize, c: usize, d: usize) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(12);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
        v[d] = (v[d] ^ v[a]).rotate_right(8);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(7);
    }

    fn bytes_to_words(bytes: &[u8; 64]) -> [u32; 16] {
        let mut words = [0u32; 16];
        for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(4)) {
            *word = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        words
    }

    fn words_to_bytes(words: &[u32]) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (chunk, word) in bytes.chunks_exact_mut(4).zip(words) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }
}
