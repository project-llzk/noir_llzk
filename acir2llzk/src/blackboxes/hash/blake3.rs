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
