use std::collections::HashMap;

use acir::FieldElement;
use llzk::prelude::{Block, BlockLike, FeltType, Location, Operation, Type, Value, dialect};

use crate::{FIELD_NAME, error::Error};

pub(in crate::blackboxes) fn append_felt_constant<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    value: &FieldElement,
) -> Result<Value<'c, 'a>, Error> {
    let attr = crate::common::field_to_felt_const(context, value);
    append_op_with_result(block, dialect::felt::constant(location, attr)?)
}

pub(in crate::blackboxes) fn append_op_with_result<'c, 'a>(
    block: &'a Block<'c>,
    op: Operation<'c>,
) -> Result<Value<'c, 'a>, Error> {
    Ok(block.append_operation(op).result(0)?.into())
}

pub(in crate::blackboxes) fn felt_type<'c>(context: &'c llzk::prelude::LlzkContext) -> Type<'c> {
    FeltType::with_field(context, FIELD_NAME).into()
}

pub(in crate::blackboxes) fn block_args<'c, 'a, const N: usize>(
    block: &'a Block<'c>,
    offset: usize,
) -> Result<[Value<'c, 'a>; N], Error> {
    let vec: Vec<Value<'c, 'a>> = (0..N)
        .map(|i| {
            block
                .argument(offset + i)
                .map(Into::into)
                .map_err(Error::from)
        })
        .collect::<Result<_, _>>()?;
    Ok(vec.try_into().unwrap_or_else(|_: Vec<_>| unreachable!()))
}

// ── Constant cache ──────────────────────────────────────────────────────

pub(in crate::blackboxes) struct ConstantCache<'c, 'a> {
    pub(in crate::blackboxes) block: &'a Block<'c>,
    pub(in crate::blackboxes) context: &'c llzk::prelude::LlzkContext,
    pub(in crate::blackboxes) location: Location<'c>,
    values: HashMap<FieldElement, Value<'c, 'a>>,
}

impl<'c, 'a> ConstantCache<'c, 'a> {
    pub(in crate::blackboxes) fn new(
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

    pub(in crate::blackboxes) fn u32(&mut self, value: u32) -> Result<Value<'c, 'a>, Error> {
        self.field(FieldElement::from(u128::from(value)))
    }

    pub(in crate::blackboxes) fn word_mask(&mut self) -> Result<Value<'c, 'a>, Error> {
        self.u32(u32::MAX)
    }

    pub(in crate::blackboxes) fn u64(&mut self, value: u64) -> Result<Value<'c, 'a>, Error> {
        self.field(FieldElement::from(u128::from(value)))
    }

    pub(in crate::blackboxes) fn u64_mask(&mut self) -> Result<Value<'c, 'a>, Error> {
        self.u64(u64::MAX)
    }

    pub(in crate::blackboxes) fn field(
        &mut self,
        value: FieldElement,
    ) -> Result<Value<'c, 'a>, Error> {
        if let Some(&cached) = self.values.get(&value) {
            return Ok(cached);
        }
        let emitted = append_felt_constant(self.block, self.context, self.location, &value)?;
        self.values.insert(value, emitted);
        Ok(emitted)
    }
}

// ── Bitwise primitives ──────────────────────────────────────────────────

pub(in crate::blackboxes) fn emit_and<'c, 'a>(
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

pub(in crate::blackboxes) fn emit_xor<'c, 'a>(
    block: &'a Block<'c>,
    location: Location<'c>,
    lhs: Value<'c, 'a>,
    rhs: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    append_op_with_result(block, dialect::felt::bit_xor(location, lhs, rhs)?)
}

pub(in crate::blackboxes) fn emit_shl<'c, 'a>(
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

pub(in crate::blackboxes) fn emit_shr<'c, 'a>(
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

pub(in crate::blackboxes) fn emit_wrapping_add<'c, 'a>(
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
pub(in crate::blackboxes) fn emit_wrapping_sum<'c, 'a>(
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

pub(in crate::blackboxes) fn emit_rotr<'c, 'a>(
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

pub(in crate::blackboxes) fn emit_rotl64<'c, 'a>(
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

pub(in crate::blackboxes) fn emit_message_words<'c, 'a>(
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

pub(in crate::blackboxes) fn emit_word_to_bytes<'c, 'a>(
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
