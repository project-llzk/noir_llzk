use acir::{AcirField, FieldElement, native_types::Expression};
use llzk::dialect::felt::FeltConstAttribute;
use llzk::prelude::{BlockLike, LlzkError, Value, dialect};

use crate::{
    FIELD_NAME,
    common::{collect_witnesses, field_to_felt_const},
    compute::ComputeWriter,
    constrain::ConstraintWriter,
    error::Error,
    opcode::OpcodeEmitter,
};

pub(crate) struct AssertZero<'a> {
    pub(crate) expr: &'a Expression<FieldElement>,
    pub(crate) index: usize,
}

impl OpcodeEmitter for AssertZero<'_> {
    fn emit_compute<'c, 'b>(&self, writer: &mut ComputeWriter<'c, 'b>) -> Result<(), Error> {
        let all_witnesses = collect_witnesses(self.expr);
        let unknowns: Vec<u32> = all_witnesses
            .iter()
            .filter(|w| !writer.known.contains(w))
            .copied()
            .collect();
        match unknowns.len() {
            0 => Ok(()),
            1 => {
                solve_witness(writer, self.expr, unknowns[0])?;
                Ok(())
            }
            n => Err(Error::UnsolvableWitness {
                witness: unknowns[0],
                num_unknowns: n,
                opcode_index: self.index,
            }),
        }
    }

    fn emit_constrain<'c, 'b>(&self, writer: &mut ConstraintWriter<'c, 'b>) -> Result<(), Error> {
        let mut terms: Vec<Value<'c, 'b>> = Vec::new();

        // Multiplication terms: coeff * w_i * w_j
        for (coeff, w_i, w_j) in &self.expr.mul_terms {
            if coeff.is_zero() {
                continue;
            }
            let vi = writer.inner.read_witness(w_i.0)?;
            let vj = writer.inner.read_witness(w_j.0)?;
            let mul_op = writer.inner.block.insert_operation_before(
                writer.inner.ret_op,
                dialect::felt::mul(writer.inner.location, vi, vj)?,
            );
            let product: Value = mul_op.result(0).map_err(LlzkError::from)?.into();
            if let Some(val) = writer.inner.apply_coefficient(product, coeff)? {
                terms.push(val);
            }
        }

        // Linear terms: coeff * w_k
        for (coeff, w_k) in &self.expr.linear_combinations {
            let vk = writer.inner.read_witness(w_k.0)?;
            if let Some(val) = writer.inner.apply_coefficient(vk, coeff)? {
                terms.push(val);
            }
        }

        // Constant term q_c
        if !self.expr.q_c.is_zero() {
            let const_attr = field_to_felt_const(writer.inner.context, &self.expr.q_c);
            let const_op = writer.inner.block.insert_operation_before(
                writer.inner.ret_op,
                dialect::felt::constant(writer.inner.location, const_attr)?,
            );
            terms.push(const_op.result(0).map_err(LlzkError::from)?.into());
        }

        // If no terms at all, expression is trivially 0 = 0, skip
        if terms.is_empty() {
            return Ok(());
        }

        // Accumulate all terms with felt.add
        let acc = writer.inner.accumulate_terms(&terms)?.unwrap();

        // constrain.eq acc == 0
        let zero_attr = FeltConstAttribute::new(writer.inner.context, 0, Some(FIELD_NAME));
        let zero_op = writer.inner.block.insert_operation_before(
            writer.inner.ret_op,
            dialect::felt::constant(writer.inner.location, zero_attr)?,
        );
        let zero_val: Value = zero_op.result(0).map_err(LlzkError::from)?.into();

        writer.inner.block.insert_operation_before(
            writer.inner.ret_op,
            dialect::constrain::eq(writer.inner.location, acc, zero_val),
        );

        Ok(())
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
fn solve_witness<'c, 'b>(
    writer: &mut ComputeWriter<'c, 'b>,
    expr: &Expression<FieldElement>,
    w_u: u32,
) -> Result<(), LlzkError> {
    let mut b_terms: Vec<Value<'c, 'b>> = Vec::new();
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

        let vi = writer.inner.read_witness(w_i.0)?;
        let vj = writer.inner.read_witness(w_j.0)?;
        let mul_op = writer.inner.block.insert_operation_before(
            writer.inner.ret_op,
            dialect::felt::mul(writer.inner.location, vi, vj)?,
        );
        let product: Value = mul_op.result(0)?.into();
        if let Some(val) = writer.inner.apply_coefficient(product, coeff)? {
            b_terms.push(val);
        }
    }

    // Process linear terms.
    for (coeff, w_k) in &expr.linear_combinations {
        if coeff.is_zero() {
            continue;
        }
        if w_k.0 == w_u {
            coeff_of_unknown = Some(*coeff);
        } else {
            let vk = writer.inner.read_witness(w_k.0)?;
            if let Some(val) = writer.inner.apply_coefficient(vk, coeff)? {
                b_terms.push(val);
            }
        }
    }

    // Constant term q_c contributes to B.
    if !expr.q_c.is_zero() {
        let const_attr = field_to_felt_const(writer.inner.context, &expr.q_c);
        let const_op = writer.inner.block.insert_operation_before(
            writer.inner.ret_op,
            dialect::felt::constant(writer.inner.location, const_attr)?,
        );
        b_terms.push(const_op.result(0)?.into());
    }

    let coeff = coeff_of_unknown.expect("unknown witness should have a linear term");

    // Compute B = sum of b_terms (may be empty → B = 0).
    let b_val = writer.inner.accumulate_terms(&b_terms)?;

    // Solve w_u = -B / coeff, with optimizations:
    //   B = 0         → w_u = 0
    //   coeff =  1    → w_u = -B
    //   coeff = -1    → w_u =  B
    //   otherwise     → w_u = -B / coeff
    let result = if let Some(b) = b_val {
        if coeff.is_one() {
            // coeff = 1 → w_u = -B
            let neg_op = writer.inner.block.insert_operation_before(
                writer.inner.ret_op,
                dialect::felt::neg(writer.inner.location, b)?,
            );
            neg_op.result(0)?.into()
        } else if coeff == -FieldElement::one() {
            // coeff = -1 → w_u = B
            b
        } else {
            // General case: w_u = -B / coeff
            let neg_op = writer.inner.block.insert_operation_before(
                writer.inner.ret_op,
                dialect::felt::neg(writer.inner.location, b)?,
            );
            let neg_b: Value = neg_op.result(0)?.into();

            let coeff_attr = field_to_felt_const(writer.inner.context, &coeff);
            let coeff_op = writer.inner.block.insert_operation_before(
                writer.inner.ret_op,
                dialect::felt::constant(writer.inner.location, coeff_attr)?,
            );
            let coeff_val: Value = coeff_op.result(0)?.into();

            let div_op = writer.inner.block.insert_operation_before(
                writer.inner.ret_op,
                dialect::felt::div(writer.inner.location, neg_b, coeff_val)?,
            );
            div_op.result(0)?.into()
        }
    } else {
        // B = 0, so w_u = 0.
        let zero_attr = FeltConstAttribute::new(writer.inner.context, 0, Some(FIELD_NAME));
        let zero_op = writer.inner.block.insert_operation_before(
            writer.inner.ret_op,
            dialect::felt::constant(writer.inner.location, zero_attr)?,
        );
        zero_op.result(0)?.into()
    };

    // Write the solved witness to the struct.
    writer.inner.block.insert_operation_before(
        writer.inner.ret_op,
        dialect::r#struct::writem(
            writer.inner.location,
            writer.inner.self_value,
            &format!("w{w_u}"),
            result,
        )?,
    );

    // Mark as known and cache the value.
    writer.known.insert(w_u);
    writer.inner.witness_cache.insert(w_u, result);

    Ok(())
}
