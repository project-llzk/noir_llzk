use std::collections::HashMap;

use acir::circuit::{Circuit, Opcode};
use acir::native_types::Expression;
use acir::{AcirField, FieldElement};
use llzk::builder::OpBuilder;
use llzk::dialect::felt::FeltConstAttribute;
use llzk::prelude::{
    BlockLike, BlockRef, FeltType, LlzkContext, LlzkError, Location, OperationLike, OperationRef,
    RegionLike, StructDefOp, StructDefOpLike, Type, Value, dialect,
};
use num_bigint::BigUint;

use crate::FIELD_NAME;
use crate::error::Error;

/// Emits constraint logic for all opcodes in the `@constrain` function body.
///
/// Iterates opcode by opcode on the ACIR side, dispatching to the
/// [`ConstraintWriter`] to emit LLZK operations.
///
/// Returns an error if any unsupported (non-`AssertZero`) opcode is encountered.
pub(crate) fn emit_constrain_body<'c>(
    context: &'c LlzkContext,
    struct_def: &StructDefOp<'c>,
    circuit: &Circuit<FieldElement>,
) -> Result<(), Error> {
    let mut writer = ConstraintWriter::new(context, struct_def)?;

    for opcode in &circuit.opcodes {
        match opcode {
            Opcode::AssertZero(expr) => writer.emit_assert_zero(expr)?,
            other => return Err(Error::UnsupportedOpcode(opcode_name(other))),
        }
    }

    Ok(())
}

/// Returns a human-readable name for an opcode variant.
fn opcode_name(opcode: &Opcode<FieldElement>) -> String {
    match opcode {
        Opcode::AssertZero(_) => "AssertZero".to_string(),
        Opcode::BlackBoxFuncCall(_) => "BlackBoxFuncCall".to_string(),
        Opcode::MemoryOp { .. } => "MemoryOp".to_string(),
        Opcode::MemoryInit { .. } => "MemoryInit".to_string(),
        Opcode::BrilligCall { .. } => "BrilligCall".to_string(),
        Opcode::Call { .. } => "Call".to_string(),
    }
}

/// LLZK-side constraint writer that manages witness reads and emits
/// constraint operations into the `@constrain` function body.
///
/// Witnesses are read lazily from `%self` via `struct.readm` on first use
/// and cached for reuse across opcodes.
struct ConstraintWriter<'c, 'a> {
    context: &'c LlzkContext,
    block: BlockRef<'c, 'a>,
    ret_op: OperationRef<'c, 'a>,
    location: Location<'c>,
    self_value: Value<'c, 'a>,
    witness_cache: HashMap<u32, Value<'c, 'a>>,
}

impl<'c, 'a> ConstraintWriter<'c, 'a> {
    /// Creates a new writer targeting the `@constrain` function of the given struct.
    fn new(
        context: &'c LlzkContext,
        struct_def: &StructDefOp<'c>,
    ) -> Result<ConstraintWriter<'c, 'a>, LlzkError> {
        let _builder = OpBuilder::new(context);
        let location = Location::unknown(context);

        let constrain = struct_def
            .get_constrain_func()
            .expect("Struct should have @constrain");
        let block = constrain.region(0)?.first_block().unwrap();
        let ret_op = block.terminator().unwrap();
        let self_value: Value = block.argument(0)?.into();

        Ok(ConstraintWriter {
            context,
            block,
            ret_op,
            location,
            self_value,
            witness_cache: HashMap::new(),
        })
    }

    /// Returns the LLZK value for witness `w_idx`, reading it from `%self`
    /// on first access and caching the result.
    fn read_witness(&mut self, w_idx: u32) -> Result<Value<'c, 'a>, LlzkError> {
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

    /// Emits constraint logic for a single `AssertZero(expr)` opcode.
    ///
    /// The expression `sum(mul_terms) + sum(linear_combinations) + q_c = 0`
    /// is translated into felt operations and a `constrain.eq` against zero.
    fn emit_assert_zero(&mut self, expr: &Expression<FieldElement>) -> Result<(), LlzkError> {
        let mut terms: Vec<Value<'c, 'a>> = Vec::new();

        // Multiplication terms: coeff * w_i * w_j
        for (coeff, w_i, w_j) in &expr.mul_terms {
            if coeff.is_zero() {
                continue;
            }
            let vi = self.read_witness(w_i.0)?;
            let vj = self.read_witness(w_j.0)?;
            let mul_op = self
                .block
                .insert_operation_before(self.ret_op, dialect::felt::mul(self.location, vi, vj)?);
            let product: Value = mul_op.result(0)?.into();
            if let Some(val) = self.apply_coefficient(product, coeff)? {
                terms.push(val);
            }
        }

        // Linear terms: coeff * w_k
        for (coeff, w_k) in &expr.linear_combinations {
            let vk = self.read_witness(w_k.0)?;
            if let Some(val) = self.apply_coefficient(vk, coeff)? {
                terms.push(val);
            }
        }

        // Constant term q_c
        if !expr.q_c.is_zero() {
            let const_attr = field_to_felt_const(self.context, &expr.q_c);
            let const_op = self.block.insert_operation_before(
                self.ret_op,
                dialect::felt::constant(self.location, const_attr)?,
            );
            terms.push(const_op.result(0)?.into());
        }

        // If no terms at all, expression is trivially 0 = 0, skip
        if terms.is_empty() {
            return Ok(());
        }

        // Accumulate all terms with felt.add
        let acc = self.accumulate_terms(&terms)?.unwrap();

        // constrain.eq acc == 0
        let zero_attr = FeltConstAttribute::new(self.context, 0, Some(FIELD_NAME));
        let zero_op = self.block.insert_operation_before(
            self.ret_op,
            dialect::felt::constant(self.location, zero_attr)?,
        );
        let zero_val: Value = zero_op.result(0)?.into();

        self.block.insert_operation_before(
            self.ret_op,
            dialect::constrain::eq(self.location, acc, zero_val),
        );

        Ok(())
    }

    /// Accumulates a list of values by chaining `felt.add` operations.
    ///
    /// Returns `None` if the list is empty.
    fn accumulate_terms(
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
    fn apply_coefficient(
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
        // General case: multiply by coefficient constant
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

/// Converts an ACIR `FieldElement` to an LLZK `FeltConstAttribute`.
fn field_to_felt_const<'c>(context: &'c LlzkContext, fe: &FieldElement) -> FeltConstAttribute<'c> {
    let bytes = fe.to_le_bytes();
    let biguint = BigUint::from_bytes_le(&bytes);
    FeltConstAttribute::from_biguint(context, &biguint, Some(FIELD_NAME))
}
