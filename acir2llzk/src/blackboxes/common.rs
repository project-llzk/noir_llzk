use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
};

use acir::FieldElement;
use llzk::{
    builder::OpBuilder,
    dialect::{empty_region, function},
    prelude::{
        Block, BlockLike, BlockRef, FuncDefOpLike, FuncDefOpRef, FunctionType, LlzkContext,
        Location, OperationRef, RegionLike as _, Type, Value, dialect::felt,
    },
};

use crate::{
    common::{as_value, field_to_felt_const},
    error::Error,
};

pub(super) fn append_felt_constant<'c: 'a, 'a>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    value: &FieldElement,
) -> Result<Value<'c, 'a>, Error> {
    let attr = field_to_felt_const(context, value);
    as_value(felt::constant(builder, location, attr)?)
}

pub(super) fn block_args<'c, 'a, const N: usize>(
    block: BlockRef<'c, 'a>,
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

/// Creates an empty helper function that maps N felt inputs to M felt outputs.
pub(super) fn create_helper_function<'c: 'a, 'a: 'b, 'b>(
    context: &'c LlzkContext,
    block: BlockRef<'c, 'a>,
    location: Location<'c>,
    name: &str,
    inputs: usize,
    outputs: usize,
) -> Result<(FuncDefOpRef<'c, 'a>, BlockRef<'c, 'b>), Error> {
    let felt = Type::from(context.felt_type());
    let function = function::def(
        &OpBuilder::at_block_end(context, block),
        location,
        name,
        FunctionType::new(context, &vec![felt; inputs], &vec![felt; outputs]),
        &[],
        None,
        empty_region,
    )?;

    let region = function.body()?;
    let body = region
        .first_block()
        .unwrap_or_else(|| region.append_block(Block::new(&vec![(felt, location); inputs])));
    Ok((function, body))
}

/// Returns a vector of values representing the arguments of the block indicated by the given
/// indices.
#[inline]
pub(super) fn block_args_slice<'c, 'a>(
    block: BlockRef<'c, 'a>,
    args: impl IntoIterator<Item = usize>,
) -> Result<Vec<Value<'c, 'a>>, Error> {
    args.into_iter()
        .map(|i| Ok(block.argument(i).map(Into::into)?))
        .collect()
}

// ── Constant cache ──────────────────────────────────────────────────────

pub(super) struct ConstantCache<'c, 'a, 'l> {
    builder: OpBuilder<'c, 'l>,
    pub(in crate::blackboxes) context: &'c LlzkContext,
    pub(in crate::blackboxes) location: Location<'c>,
    values: HashMap<FieldElement, Value<'c, 'a>>,
}

impl<'c: 'a, 'a, 'l> ConstantCache<'c, 'a, 'l> {
    pub fn new(block: BlockRef<'c, 'a>, context: &'c LlzkContext, location: Location<'c>) -> Self {
        Self {
            builder: OpBuilder::at_block_end(context, block),
            context,
            location,
            values: HashMap::new(),
        }
    }

    pub fn builder(&self) -> &OpBuilder<'c, 'l> {
        &self.builder
    }

    pub fn u32(&mut self, value: u32) -> Result<Value<'c, 'a>, Error> {
        self.field(FieldElement::from(u128::from(value)))
    }

    pub fn u32s<T: Into<u32>>(
        &mut self,
        values: impl IntoIterator<Item = T>,
    ) -> Result<Vec<Value<'c, 'a>>, Error> {
        values
            .into_iter()
            .map(|value| self.u32(value.into()))
            .collect()
    }

    pub fn word_mask(&mut self) -> Result<Value<'c, 'a>, Error> {
        self.u32(u32::MAX)
    }

    pub fn u64(&mut self, value: u64) -> Result<Value<'c, 'a>, Error> {
        self.field(FieldElement::from(u128::from(value)))
    }

    pub fn u64_mask(&mut self) -> Result<Value<'c, 'a>, Error> {
        self.u64(u64::MAX)
    }

    pub fn field(&mut self, value: FieldElement) -> Result<Value<'c, 'a>, Error> {
        if let Some(&cached) = self.values.get(&value) {
            return Ok(cached);
        }
        let emitted = append_felt_constant(&self.builder, self.context, self.location, &value)?;
        self.values.insert(value, emitted);
        Ok(emitted)
    }
}

// ── Bitwise primitives ──────────────────────────────────────────────────

pub(super) struct BitwiseEmitter<'c, 'a, 'l> {
    cache: ConstantCache<'c, 'a, 'l>,
}

impl<'c: 'a, 'a, 'l> BitwiseEmitter<'c, 'a, 'l> {
    pub fn new(block: BlockRef<'c, 'a>, context: &'c LlzkContext, location: Location<'c>) -> Self {
        Self {
            cache: ConstantCache::new(block, context, location),
        }
    }

    #[inline]
    fn emit_binop(
        &self,
        op: impl Fn(
            &OpBuilder<'c, 'l>,
            Location<'c>,
            Value<'c, 'a>,
            Value<'c, 'a>,
        ) -> Result<OperationRef<'c, 'a>, llzk::error::Error>,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        as_value(op(&self.cache.builder, self.cache.location, lhs, rhs)?)
    }

    #[inline]
    pub fn emit_and(&self, lhs: Value<'c, 'a>, rhs: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        self.emit_binop(felt::bit_and, lhs, rhs)
    }

    #[inline]
    pub fn emit_or(&self, lhs: Value<'c, 'a>, rhs: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        self.emit_binop(felt::bit_or, lhs, rhs)
    }

    #[inline]
    pub fn emit_xor(&self, lhs: Value<'c, 'a>, rhs: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        self.emit_binop(felt::bit_xor, lhs, rhs)
    }

    #[inline]
    pub fn emit_shl(&mut self, value: Value<'c, 'a>, amount: u32) -> Result<Value<'c, 'a>, Error> {
        let amount = self.cache.u32(amount)?;
        self.emit_binop(felt::shl, value, amount)
    }

    #[inline]
    pub fn emit_shr(&mut self, value: Value<'c, 'a>, amount: u32) -> Result<Value<'c, 'a>, Error> {
        let amount = self.cache.u32(amount)?;
        self.emit_binop(felt::shr, value, amount)
    }
}

impl<'c, 'a, 'l> DerefMut for BitwiseEmitter<'c, 'a, 'l> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.cache
    }
}

impl<'c, 'a, 'l> Deref for BitwiseEmitter<'c, 'a, 'l> {
    type Target = ConstantCache<'c, 'a, 'l>;

    fn deref(&self) -> &Self::Target {
        &self.cache
    }
}

// ── Word-level arithmetic ───────────────────────────────────────────────

pub(super) struct WordArithEmitter<'c, 'a, 'l> {
    bitwise: BitwiseEmitter<'c, 'a, 'l>,
}

impl<'c: 'a, 'a, 'l> WordArithEmitter<'c, 'a, 'l> {
    pub fn new(block: BlockRef<'c, 'a>, context: &'c LlzkContext, location: Location<'c>) -> Self {
        Self {
            bitwise: BitwiseEmitter::new(block, context, location),
        }
    }

    #[inline]
    pub fn emit_wrapping_add(
        &mut self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        let sum = as_value(felt::add(
            &self.bitwise.cache.builder,
            self.bitwise.cache.location,
            lhs,
            rhs,
        )?)?;
        let mask = self.bitwise.cache.word_mask()?;
        self.bitwise.emit_and(sum, mask)
    }

    // Sum of N u32-ranged operands stays under N * 2^32, well within BN254's ~2^254
    // field, so the final `& word_mask` is the only truncation needed.
    pub fn emit_wrapping_sum(
        &mut self,
        operands: &[Value<'c, 'a>],
    ) -> Result<Value<'c, 'a>, Error> {
        let (first, rest) = operands.split_first().expect("at least one operand");
        let mut sum = *first;
        for &op in rest {
            sum = as_value(felt::add(
                &self.bitwise.cache.builder,
                self.bitwise.cache.location,
                sum,
                op,
            )?)?;
        }
        let mask = self.bitwise.cache.word_mask()?;
        self.bitwise.emit_and(sum, mask)
    }

    pub fn emit_rotr(&mut self, value: Value<'c, 'a>, amount: u32) -> Result<Value<'c, 'a>, Error> {
        let right = self.bitwise.emit_shr(value, amount)?;
        let left = self.bitwise.emit_shl(value, 32 - amount)?;
        let combined = self.bitwise.emit_or(right, left)?;
        let mask = self.bitwise.cache.word_mask()?;
        self.bitwise.emit_and(combined, mask)
    }

    pub fn emit_rotl64(
        &mut self,
        value: Value<'c, 'a>,
        amount: u32,
    ) -> Result<Value<'c, 'a>, Error> {
        let left = self.bitwise.emit_shl(value, amount)?;
        let right = self.bitwise.emit_shr(value, 64 - amount)?;
        let combined = self.bitwise.emit_or(left, right)?;
        let mask = self.bitwise.cache.u64_mask()?;
        self.bitwise.emit_and(combined, mask)
    }

    pub fn emit_message_words(
        &mut self,
        bytes: &[Value<'c, 'a>],
    ) -> Result<Vec<Value<'c, 'a>>, Error> {
        let mut words = Vec::with_capacity(bytes.len() / 4);
        for chunk in bytes.chunks_exact(4) {
            let b0 = chunk[0];
            let b1 = self.bitwise.emit_shl(chunk[1], 8)?;
            let b2 = self.bitwise.emit_shl(chunk[2], 16)?;
            let b3 = self.bitwise.emit_shl(chunk[3], 24)?;
            let word = self
                .bitwise
                .emit_or(self.bitwise.emit_or(b0, self.bitwise.emit_or(b1, b2)?)?, b3)?;
            words.push(word);
        }
        Ok(words)
    }

    pub fn emit_word_to_bytes(&mut self, word: Value<'c, 'a>) -> Result<[Value<'c, 'a>; 4], Error> {
        let mask = self.bitwise.cache.u32(0xff)?;
        let byte0 = self.bitwise.emit_and(word, mask)?;
        let shifted1 = self.bitwise.emit_shr(word, 8)?;
        let byte1 = self.bitwise.emit_and(shifted1, mask)?;
        let shifted2 = self.bitwise.emit_shr(word, 16)?;
        let byte2 = self.bitwise.emit_and(shifted2, mask)?;
        let shifted3 = self.bitwise.emit_shr(word, 24)?;
        let byte3 = self.bitwise.emit_and(shifted3, mask)?;
        Ok([byte0, byte1, byte2, byte3])
    }
}

impl<'c, 'a, 'l> DerefMut for WordArithEmitter<'c, 'a, 'l> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bitwise
    }
}

impl<'c, 'a, 'l> Deref for WordArithEmitter<'c, 'a, 'l> {
    type Target = BitwiseEmitter<'c, 'a, 'l>;

    fn deref(&self) -> &Self::Target {
        &self.bitwise
    }
}
