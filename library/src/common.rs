use std::collections::HashSet;

use acir::circuit::Opcode;
use acir::native_types::Expression;
use acir::{AcirField, FieldElement};
use llzk::builder::OpBuilder;
use llzk::dialect::felt::FeltConstAttribute;
use llzk::prelude::{
    BlockLike, BlockRef, FeltType, LlzkContext, LlzkError, Location, OperationRef, Type, Value,
    dialect,
};
use num_bigint::BigUint;
use std::collections::HashMap;

use crate::FIELD_NAME;

/// Returns a human-readable name for an opcode variant.
pub(crate) fn opcode_name(opcode: &Opcode<FieldElement>) -> String {
    match opcode {
        Opcode::AssertZero(_) => "AssertZero".to_string(),
        Opcode::BlackBoxFuncCall(_) => "BlackBoxFuncCall".to_string(),
        Opcode::MemoryOp { .. } => "MemoryOp".to_string(),
        Opcode::MemoryInit { .. } => "MemoryInit".to_string(),
        Opcode::BrilligCall { .. } => "BrilligCall".to_string(),
        Opcode::Call { .. } => "Call".to_string(),
    }
}

/// Converts an ACIR `FieldElement` to an LLZK `FeltConstAttribute`.
pub(crate) fn field_to_felt_const<'c>(
    context: &'c LlzkContext,
    fe: &FieldElement,
) -> FeltConstAttribute<'c> {
    let bytes = fe.to_le_bytes();
    let biguint = BigUint::from_bytes_le(&bytes);
    FeltConstAttribute::from_biguint(context, &biguint, Some(FIELD_NAME))
}

/// Collects all unique witness indices referenced in an expression.
pub(crate) fn collect_witnesses(expr: &Expression<FieldElement>) -> HashSet<u32> {
    let mut witnesses = HashSet::new();
    for (_, w_i, w_j) in &expr.mul_terms {
        witnesses.insert(w_i.0);
        witnesses.insert(w_j.0);
    }
    for (_, w_k) in &expr.linear_combinations {
        witnesses.insert(w_k.0);
    }
    witnesses
}

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
}

impl<'c, 'a> BlockWriter<'c, 'a> {
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
