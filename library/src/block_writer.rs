use std::collections::HashMap;

use acir::{AcirField, FieldElement};
use llzk::builder::OpBuilder;
use llzk::dialect::felt::FeltConstAttribute;
use llzk::prelude::{
    BlockLike, BlockRef, FeltType, LlzkContext, LlzkError, Location, OperationRef, Type, Value,
    dialect,
};

use crate::FIELD_NAME;
use crate::common::field_to_felt_const;

/// Shared LLZK block writer that manages witness reads and emits felt operations.
///
/// Both `ComputeWriter` and `ConstraintWriter` embed this struct to reuse
/// common operations like reading witnesses, accumulating terms, and applying
/// coefficients.
pub(crate) struct BlockWriter<'c, 'a> {
    pub(crate) context: &'c LlzkContext,
    pub(crate) block: BlockRef<'c, 'a>,
    pub(crate) ret_op: OperationRef<'c, 'a>,
    pub(crate) location: Location<'c>,
    pub(crate) self_value: Value<'c, 'a>,
    /// Cache of SSA values for witnesses that have been read from the struct.
    pub(crate) witness_cache: HashMap<u32, Value<'c, 'a>>,
    /// Cached `felt.constant 0` — emitted at most once per block.
    /// Prevents adding a new constant zero value for every assert_zero opcode.
    zero_cache: Option<Value<'c, 'a>>,
}

impl<'c, 'a> BlockWriter<'c, 'a> {
    pub(crate) fn new(
        context: &'c LlzkContext,
        block: BlockRef<'c, 'a>,
        ret_op: OperationRef<'c, 'a>,
        self_value: Value<'c, 'a>,
        witness_cache: HashMap<u32, Value<'c, 'a>>,
    ) -> Self {
        Self {
            context,
            block,
            ret_op,
            location: Location::unknown(context),
            self_value,
            witness_cache,
            zero_cache: None,
        }
    }

    /// Builds a `BlockWriter` from an already-resolved `block` and `self_value`.
    ///
    /// Extracts the block terminator, seeds the witness cache from block arguments
    /// starting at `arg_offset` (`0` for `@compute`, `1` for `@constrain`), and
    /// delegates to [`BlockWriter::new`].
    pub(crate) fn from_block(
        context: &'c LlzkContext,
        block: BlockRef<'c, 'a>,
        self_value: Value<'c, 'a>,
        input_witnesses: &[u32],
        arg_offset: usize,
    ) -> Result<Self, LlzkError> {
        let ret_op = block.terminator().unwrap();
        let mut witness_cache = HashMap::new();
        for (i, &w_idx) in input_witnesses.iter().enumerate() {
            let val: Value = block.argument(i + arg_offset)?.into();
            witness_cache.insert(w_idx, val);
        }
        Ok(Self::new(context, block, ret_op, self_value, witness_cache))
    }

    /// Returns the LLZK value for witness `w_idx`, reading it from `%self`
    /// on first access and caching the result.
    pub(crate) fn read_witness(&mut self, w_idx: u32) -> Result<Value<'c, 'a>, LlzkError> {
        if let Some(&val) = self.witness_cache.get(&w_idx) {
            return Ok(val);
        }

        let felt_type: Type = FeltType::with_field(self.context, FIELD_NAME).into();
        let read_op = self.block.insert_operation_before(
            self.ret_op,
            dialect::r#struct::readm(
                &OpBuilder::new(self.context),
                self.location,
                felt_type,
                self.self_value,
                &format!("w{w_idx}"),
            )?,
        );
        let val: Value = read_op.result(0)?.into();
        self.witness_cache.insert(w_idx, val);
        Ok(val)
    }

    /// Accumulates a list of values by chaining `felt.add` operations.
    ///
    /// Returns `None` if the list is empty.
    pub(crate) fn accumulate_terms(
        &self,
        terms: &[Value<'c, 'a>],
    ) -> Result<Option<Value<'c, 'a>>, LlzkError> {
        if terms.is_empty() {
            return Ok(None);
        }
        let mut acc = terms[0];
        for &term in &terms[1..] {
            let add_op = self.block.insert_operation_before(
                self.ret_op,
                dialect::felt::add(self.location, acc, term)?,
            );
            acc = add_op.result(0)?.into();
        }
        Ok(Some(acc))
    }

    /// Returns a `felt.constant 0` value, emitting the operation at most once per block.
    pub(crate) fn emit_zero(&mut self) -> Result<Value<'c, 'a>, LlzkError> {
        if let Some(zero) = self.zero_cache {
            return Ok(zero);
        }
        let zero_attr = FeltConstAttribute::new(self.context, 0, Some(FIELD_NAME));
        let zero_op = self.block.insert_operation_before(
            self.ret_op,
            dialect::felt::constant(self.location, zero_attr)?,
        );
        let zero: Value = zero_op.result(0)?.into();
        self.zero_cache = Some(zero);
        Ok(zero)
    }

    /// Multiplies a value by a coefficient, with optimizations for 0, 1, and -1.
    ///
    /// Returns `None` if the coefficient is zero (term should be skipped).
    pub(crate) fn apply_coefficient(
        &self,
        value: Value<'c, 'a>,
        coeff: &FieldElement,
    ) -> Result<Option<Value<'c, 'a>>, LlzkError> {
        if coeff.is_zero() {
            return Ok(None);
        }
        if coeff.is_one() {
            return Ok(Some(value));
        }
        if *coeff == -FieldElement::one() {
            let neg_op = self
                .block
                .insert_operation_before(self.ret_op, dialect::felt::neg(self.location, value)?);
            return Ok(Some(neg_op.result(0)?.into()));
        }
        let coeff_attr = field_to_felt_const(self.context, coeff);
        let coeff_op = self.block.insert_operation_before(
            self.ret_op,
            dialect::felt::constant(self.location, coeff_attr)?,
        );
        let coeff_val: Value = coeff_op.result(0)?.into();
        let mul_op = self.block.insert_operation_before(
            self.ret_op,
            dialect::felt::mul(self.location, value, coeff_val)?,
        );
        Ok(Some(mul_op.result(0)?.into()))
    }
}
