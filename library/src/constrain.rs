use acir::native_types::Expression;
use acir::{AcirField, FieldElement};
use llzk::dialect::felt::FeltConstAttribute;
use llzk::prelude::{
    BlockLike, LlzkContext, LlzkError, Location, OperationLike, RegionLike, StructDefOp,
    StructDefOpLike, Value, dialect,
};

use crate::FIELD_NAME;
use crate::common::{BlockWriter, field_to_felt_const};

/// LLZK-side constraint writer that manages witness reads and emits
/// constraint operations into the `@constrain` function body.
///
/// Witnesses are read lazily from `%self` via `struct.readm` on first use
/// and cached for reuse across opcodes.
pub(crate) struct ConstraintWriter<'c, 'a> {
    inner: BlockWriter<'c, 'a>,
}

impl<'c, 'a> ConstraintWriter<'c, 'a> {
    /// Creates a new writer targeting the `@constrain` function of the given struct.
    ///
    /// Seeds `witness_cache` from block arguments so that input witnesses are
    /// resolved from parameters rather than emitting `struct.readm`.
    pub(crate) fn new(
        context: &'c LlzkContext,
        struct_def: &StructDefOp<'c>,
        input_witnesses: &[u32],
    ) -> Result<ConstraintWriter<'c, 'a>, LlzkError> {
        let location = Location::unknown(context);

        let constrain = struct_def
            .get_constrain_func()
            .expect("Struct should have @constrain");
        let block = constrain.region(0)?.first_block().unwrap();
        let ret_op = block.terminator().unwrap();
        let self_value: Value = block.argument(0)?.into();

        let mut witness_cache = std::collections::HashMap::new();

        // Seed cache from input parameters (argument 0 is %self, inputs start at 1).
        for (arg_idx, &w_idx) in input_witnesses.iter().enumerate() {
            // Block argument 0 is %self, so inputs start at index 1.
            let arg_val: Value = block.argument(arg_idx + 1)?.into();
            witness_cache.insert(w_idx, arg_val);
        }

        Ok(ConstraintWriter {
            inner: BlockWriter {
                context,
                block,
                ret_op,
                location,
                self_value,
                witness_cache,
            },
        })
    }

    /// Emits constraint logic for a single `AssertZero(expr)` opcode.
    ///
    /// The expression `sum(mul_terms) + sum(linear_combinations) + q_c = 0`
    /// is translated into felt operations and a `constrain.eq` against zero.
    pub(crate) fn emit_assert_zero(
        &mut self,
        expr: &Expression<FieldElement>,
    ) -> Result<(), LlzkError> {
        let mut terms: Vec<Value<'c, 'a>> = Vec::new();

        // Multiplication terms: coeff * w_i * w_j
        for (coeff, w_i, w_j) in &expr.mul_terms {
            if coeff.is_zero() {
                continue;
            }
            let vi = self.inner.read_witness(w_i.0)?;
            let vj = self.inner.read_witness(w_j.0)?;
            let mul_op = self.inner.block.insert_operation_before(
                self.inner.ret_op,
                dialect::felt::mul(self.inner.location, vi, vj)?,
            );
            let product: Value = mul_op.result(0)?.into();
            if let Some(val) = self.inner.apply_coefficient(product, coeff)? {
                terms.push(val);
            }
        }

        // Linear terms: coeff * w_k
        for (coeff, w_k) in &expr.linear_combinations {
            let vk = self.inner.read_witness(w_k.0)?;
            if let Some(val) = self.inner.apply_coefficient(vk, coeff)? {
                terms.push(val);
            }
        }

        // Constant term q_c
        if !expr.q_c.is_zero() {
            let const_attr = field_to_felt_const(self.inner.context, &expr.q_c);
            let const_op = self.inner.block.insert_operation_before(
                self.inner.ret_op,
                dialect::felt::constant(self.inner.location, const_attr)?,
            );
            terms.push(const_op.result(0)?.into());
        }

        // If no terms at all, expression is trivially 0 = 0, skip
        if terms.is_empty() {
            return Ok(());
        }

        // Accumulate all terms with felt.add
        let acc = self.inner.accumulate_terms(&terms)?.unwrap();

        // constrain.eq acc == 0
        let zero_attr = FeltConstAttribute::new(self.inner.context, 0, Some(FIELD_NAME));
        let zero_op = self.inner.block.insert_operation_before(
            self.inner.ret_op,
            dialect::felt::constant(self.inner.location, zero_attr)?,
        );
        let zero_val: Value = zero_op.result(0)?.into();

        self.inner.block.insert_operation_before(
            self.inner.ret_op,
            dialect::constrain::eq(self.inner.location, acc, zero_val),
        );

        Ok(())
    }
}
