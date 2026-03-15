use std::collections::HashSet;

use acir::native_types::Expression;
use acir::{AcirField, FieldElement};
use llzk::dialect::felt::FeltConstAttribute;
use llzk::prelude::{
    BlockLike, LlzkContext, LlzkError, Location, OperationLike, RegionLike, StructDefOp,
    StructDefOpLike, Value, dialect,
};

use crate::FIELD_NAME;
use crate::common::{BlockWriter, collect_witnesses, field_to_felt_const};
use crate::error::Error;

/// LLZK-side compute writer that manages witness solving and emits
/// operations into the `@compute` function body.
///
/// Input witnesses are written to the struct from function parameters.
/// Intermediate witnesses are solved from `AssertZero` expressions and
/// written to the struct as they are computed.
pub(crate) struct ComputeWriter<'c, 'a> {
    inner: BlockWriter<'c, 'a>,
    /// Set of witness indices that are currently known (solved or input).
    known: HashSet<u32>,
}

impl<'c, 'a> ComputeWriter<'c, 'a> {
    /// Creates a new writer targeting the `@compute` function of the given struct.
    ///
    /// Writes all input parameters (private then public) to the struct as initial
    /// known witnesses.
    pub(crate) fn new(
        context: &'c LlzkContext,
        struct_def: &StructDefOp<'c>,
        input_witnesses: &[u32],
    ) -> Result<ComputeWriter<'c, 'a>, LlzkError> {
        let location = Location::unknown(context);

        let compute = struct_def
            .get_compute_func()
            .expect("Struct should have @compute");
        let block = compute.region(0)?.first_block().unwrap();
        let ret_op = block.terminator().unwrap();

        // The first operation in compute is `struct.new`, its result is %self.
        let first_op = block.first_operation().unwrap();
        let self_value: Value = first_op.result(0)?.into();

        let mut writer = ComputeWriter {
            inner: BlockWriter {
                context,
                block,
                ret_op,
                location,
                self_value,
                witness_cache: Default::default(),
            },
            known: HashSet::new(),
        };

        // Populate known set and witness cache from input parameters.
        // Inputs are available as function arguments — no struct.writem needed.
        for (arg_idx, &w_idx) in input_witnesses.iter().enumerate() {
            // Block argument 0 is the first input param (compute has no %self arg).
            let arg_val: Value = block.argument(arg_idx)?.into();
            writer.known.insert(w_idx);
            writer.inner.witness_cache.insert(w_idx, arg_val);
        }
        Ok(writer)
    }

    /// Processes a single `AssertZero(expr)` opcode for witness solving.
    ///
    /// The expression has the form: `sum(mul_terms) + sum(linear_combinations) + q_c = 0`
    ///
    /// - If all witnesses are known, nothing is emitted (pure assertion).
    /// - If exactly one witness is unknown, it is solved algebraically.
    /// - If two or more are unknown, an error is returned.
    pub(crate) fn emit_assert_zero(
        &mut self,
        expr: &Expression<FieldElement>,
        opcode_index: usize,
    ) -> Result<(), Error> {
        // Collect all witness indices referenced in this expression.
        let all_witnesses = collect_witnesses(expr);
        let unknowns: Vec<u32> = all_witnesses
            .iter()
            .filter(|w| !self.known.contains(w))
            .copied()
            .collect();
        match unknowns.len() {
            0 => Ok(()),
            1 => {
                let w_u = unknowns[0];
                self.solve_witness(expr, w_u)?;
                Ok(())
            }
            n => {
                // Report the first unknown witness in the error.
                Err(Error::UnsolvableWitness {
                    witness: unknowns[0],
                    num_unknowns: n,
                    opcode_index,
                })
            }
        }
    }

    /// Solves for the unknown witness `w_u` in the expression `expr = 0`.
    ///
    /// The unknown witness only appears as a linear term, so the expression
    /// has the form:
    /// ```text
    /// w_u * coeff + B = 0
    /// ```
    /// where `coeff` is the linear coefficient of `w_u` and `B` is the sum of
    /// all other terms (mul_terms with known witnesses, other linear terms, q_c).
    /// So `w_u = -B / coeff`.
    fn solve_witness(
        &mut self,
        expr: &Expression<FieldElement>,
        w_u: u32,
    ) -> Result<(), LlzkError> {
        let mut b_terms: Vec<Value<'c, 'a>> = Vec::new();
        let mut coeff_of_unknown: Option<FieldElement> = None;

        // Process multiplication terms — all witnesses are known.
        for (coeff, w_i, w_j) in &expr.mul_terms {
            if coeff.is_zero() {
                continue;
            }
            debug_assert!(
                w_i.0 != w_u && w_j.0 != w_u,
                "unknown witness w{w_u} in mul_term"
            );

            let vi = self.inner.read_witness(w_i.0)?;
            let vj = self.inner.read_witness(w_j.0)?;
            let mul_op = self.inner.block.insert_operation_before(
                self.inner.ret_op,
                dialect::felt::mul(self.inner.location, vi, vj)?,
            );
            let product: Value = mul_op.result(0)?.into();
            if let Some(val) = self.inner.apply_coefficient(product, coeff)? {
                b_terms.push(val);
            }
        }

        // Process linear terms.
        // In practice, the unknown witness appears exactly once with coeff = -1,
        // We handle the general case below but the coeff = -1 fast path (w_u = B) is the common one.
        for (coeff, w_k) in &expr.linear_combinations {
            if coeff.is_zero() {
                continue;
            }
            if w_k.0 == w_u {
                coeff_of_unknown = Some(*coeff);
            } else {
                let vk = self.inner.read_witness(w_k.0)?;
                if let Some(val) = self.inner.apply_coefficient(vk, coeff)? {
                    b_terms.push(val);
                }
            }
        }

        // Constant term q_c contributes to B.
        if !expr.q_c.is_zero() {
            let const_attr = field_to_felt_const(self.inner.context, &expr.q_c);
            let const_op = self.inner.block.insert_operation_before(
                self.inner.ret_op,
                dialect::felt::constant(self.inner.location, const_attr)?,
            );
            b_terms.push(const_op.result(0)?.into());
        }

        let coeff = coeff_of_unknown.expect("unknown witness should have a linear term");

        // Compute B = sum of b_terms (may be empty → B = 0).
        let b_val = self.inner.accumulate_terms(&b_terms)?;

        // Solve w_u = -B / coeff, with optimizations:
        //   B = 0         → w_u = 0
        //   coeff =  1    → w_u = -B
        //   coeff = -1    → w_u =  B
        //   otherwise     → w_u = -B / coeff
        let result = if let Some(b) = b_val {
            if coeff.is_one() {
                // coeff = 1 → w_u = -B
                let neg_op = self.inner.block.insert_operation_before(
                    self.inner.ret_op,
                    dialect::felt::neg(self.inner.location, b)?,
                );
                neg_op.result(0)?.into()
            } else if coeff == -FieldElement::one() {
                // coeff = -1 → w_u = B
                b
            } else {
                // General case: w_u = -B / coeff
                // This is never supposed to happen, but not guaranteed by
                // Noir type system
                let neg_op = self.inner.block.insert_operation_before(
                    self.inner.ret_op,
                    dialect::felt::neg(self.inner.location, b)?,
                );
                let neg_b: Value = neg_op.result(0)?.into();

                let coeff_attr = field_to_felt_const(self.inner.context, &coeff);
                let coeff_op = self.inner.block.insert_operation_before(
                    self.inner.ret_op,
                    dialect::felt::constant(self.inner.location, coeff_attr)?,
                );
                let coeff_val: Value = coeff_op.result(0)?.into();

                let div_op = self.inner.block.insert_operation_before(
                    self.inner.ret_op,
                    dialect::felt::div(self.inner.location, neg_b, coeff_val)?,
                );
                div_op.result(0)?.into()
            }
        } else {
            // B = 0, so w_u = 0.
            let zero_attr = FeltConstAttribute::new(self.inner.context, 0, Some(FIELD_NAME));
            let zero_op = self.inner.block.insert_operation_before(
                self.inner.ret_op,
                dialect::felt::constant(self.inner.location, zero_attr)?,
            );
            zero_op.result(0)?.into()
        };

        // Write the solved witness to the struct.
        self.inner.block.insert_operation_before(
            self.inner.ret_op,
            dialect::r#struct::writem(
                self.inner.location,
                self.inner.self_value,
                &format!("w{w_u}"),
                result,
            )?,
        );

        // Mark as known and cache the value.
        self.known.insert(w_u);
        self.inner.witness_cache.insert(w_u, result);

        Ok(())
    }
}
