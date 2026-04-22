use std::collections::HashMap;

use acir::FieldElement;
use llzk::prelude::{Block, Location, Value, dialect};

use crate::{
    blackboxes::common::{append_felt_constant, append_op_with_result},
    error::Error,
};

// ── Constant cache ──────────────────────────────────────────────────────

pub(super) struct ConstantCache<'c, 'a> {
    pub(super) block: &'a Block<'c>,
    pub(super) context: &'c llzk::prelude::LlzkContext,
    pub(super) location: Location<'c>,
    values: HashMap<FieldElement, Value<'c, 'a>>,
}

impl<'c, 'a> ConstantCache<'c, 'a> {
    pub(super) fn new(
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

    pub(super) fn u32(&mut self, value: u32) -> Result<Value<'c, 'a>, Error> {
        self.field(FieldElement::from(u128::from(value)))
    }

    pub(super) fn word_mask(&mut self) -> Result<Value<'c, 'a>, Error> {
        self.u32(u32::MAX)
    }

    pub(super) fn u64(&mut self, value: u64) -> Result<Value<'c, 'a>, Error> {
        self.field(FieldElement::from(u128::from(value)))
    }

    pub(super) fn u64_mask(&mut self) -> Result<Value<'c, 'a>, Error> {
        self.u64(u64::MAX)
    }

    pub(super) fn field(&mut self, value: FieldElement) -> Result<Value<'c, 'a>, Error> {
        if let Some(&cached) = self.values.get(&value) {
            return Ok(cached);
        }
        let emitted = append_felt_constant(self.block, self.context, self.location, &value)?;
        self.values.insert(value, emitted);
        Ok(emitted)
    }
}

// ── Bitwise primitives ──────────────────────────────────────────────────

pub(super) fn emit_and<'c, 'a>(
    block: &'a Block<'c>,
    location: Location<'c>,
    lhs: Value<'c, 'a>,
    rhs: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    append_op_with_result(block, dialect::felt::bit_and(location, lhs, rhs)?)
}

pub(super) fn emit_or<'c, 'a>(
    block: &'a Block<'c>,
    location: Location<'c>,
    lhs: Value<'c, 'a>,
    rhs: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    append_op_with_result(block, dialect::felt::bit_or(location, lhs, rhs)?)
}

pub(super) fn emit_xor<'c, 'a>(
    block: &'a Block<'c>,
    location: Location<'c>,
    lhs: Value<'c, 'a>,
    rhs: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    append_op_with_result(block, dialect::felt::bit_xor(location, lhs, rhs)?)
}

pub(super) fn emit_shl<'c, 'a>(
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

pub(super) fn emit_shr<'c, 'a>(
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

// ── Word-level arithmetic ───────────────────────────────────────────────

pub(super) fn emit_wrapping_add<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    lhs: Value<'c, 'a>,
    rhs: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    let sum = append_op_with_result(cache.block, dialect::felt::add(cache.location, lhs, rhs)?)?;
    let mask = cache.word_mask()?;
    emit_and(cache.block, cache.location, sum, mask)
}

// Sum of N u32-ranged operands stays under N * 2^32, well within BN254's ~2^254
// field, so the final `& word_mask` is the only truncation needed.
pub(super) fn emit_wrapping_sum<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    operands: &[Value<'c, 'a>],
) -> Result<Value<'c, 'a>, Error> {
    let (first, rest) = operands.split_first().expect("at least one operand");
    let mut sum = *first;
    for &op in rest {
        sum = append_op_with_result(cache.block, dialect::felt::add(cache.location, sum, op)?)?;
    }
    let mask = cache.word_mask()?;
    emit_and(cache.block, cache.location, sum, mask)
}

pub(super) fn emit_rotr<'c, 'a>(
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

pub(super) fn emit_rotl64<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    value: Value<'c, 'a>,
    amount: u32,
) -> Result<Value<'c, 'a>, Error> {
    let left = emit_shl(cache, value, amount)?;
    let right = emit_shr(cache, value, 64 - amount)?;
    let combined = emit_or(cache.block, cache.location, left, right)?;
    let mask = cache.u64_mask()?;
    emit_and(cache.block, cache.location, combined, mask)
}

// ── Byte/word conversion ────────────────────────────────────────────────

pub(super) fn emit_message_words<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    bytes: &[Value<'c, 'a>],
) -> Result<Vec<Value<'c, 'a>>, Error> {
    let mut words = Vec::with_capacity(bytes.len() / 4);
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
    Ok(words)
}

pub(super) fn emit_word_to_bytes<'c, 'a>(
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

// ── G mixing function (shared by Blake2s and Blake3) ────────────────────

pub(super) fn emit_g<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    v: &mut [Value<'c, 'a>; 16],
    (a, b, c, d): (usize, usize, usize, usize),
    x: Value<'c, 'a>,
    y: Value<'c, 'a>,
) -> Result<(), Error> {
    v[a] = emit_wrapping_sum(cache, &[v[a], v[b], x])?;
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
    v[a] = emit_wrapping_sum(cache, &[v[a], v[b], y])?;
    v[d] = emit_rotr(cache, emit_xor(cache.block, cache.location, v[d], v[a])?, 8)?;
    v[c] = emit_wrapping_add(cache, v[c], v[d])?;
    v[b] = emit_rotr(cache, emit_xor(cache.block, cache.location, v[b], v[c])?, 7)?;
    Ok(())
}

/// Runs one round of column + diagonal mixing on the work vector.
pub(super) fn emit_round<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    v: &mut [Value<'c, 'a>; 16],
    m: &[Value<'c, 'a>; 16],
    schedule: &[usize; 16],
) -> Result<(), Error> {
    emit_g(cache, v, (0, 4, 8, 12), m[schedule[0]], m[schedule[1]])?;
    emit_g(cache, v, (1, 5, 9, 13), m[schedule[2]], m[schedule[3]])?;
    emit_g(cache, v, (2, 6, 10, 14), m[schedule[4]], m[schedule[5]])?;
    emit_g(cache, v, (3, 7, 11, 15), m[schedule[6]], m[schedule[7]])?;
    emit_g(cache, v, (0, 5, 10, 15), m[schedule[8]], m[schedule[9]])?;
    emit_g(cache, v, (1, 6, 11, 12), m[schedule[10]], m[schedule[11]])?;
    emit_g(cache, v, (2, 7, 8, 13), m[schedule[12]], m[schedule[13]])?;
    emit_g(cache, v, (3, 4, 9, 14), m[schedule[14]], m[schedule[15]])?;
    Ok(())
}

// ── IV constants (shared by Blake2s and Blake3) ─────────────────────────

pub(super) const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

pub(super) fn iv_values<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
) -> Result<[Value<'c, 'a>; 8], Error> {
    let mut values = Vec::with_capacity(8);
    for word in IV {
        values.push(cache.u32(word)?);
    }
    Ok(values.try_into().expect("exactly eight IV words"))
}
