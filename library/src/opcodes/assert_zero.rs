use acir::{AcirField, FieldElement, native_types::Expression};
use llzk::prelude::{BlockLike, LlzkError, Value, dialect};

use crate::{
    common::{BlockWriter, collect_witnesses, field_to_felt_const},
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
        let (terms, _) = collect_expr_terms(&mut writer.inner, self.expr, None)?;

        if terms.is_empty() {
            return Ok(());
        }

        // Accumulate all terms, then assert their sum == 0.
        let acc = writer.inner.accumulate_terms(&terms)?.unwrap();
        let zero_val = writer.inner.emit_zero()?;
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
    let (b_terms, coeff_of_unknown) = collect_expr_terms(&mut writer.inner, expr, Some(w_u))?;
    let coeff = coeff_of_unknown.expect("unknown witness should have a linear term");

    let b_val = writer.inner.accumulate_terms(&b_terms)?;

    // Solve w_u = -B / coeff, with optimizations:
    //   B = 0         → w_u = 0
    //   coeff =  1    → w_u = -B
    //   coeff = -1    → w_u =  B
    //   otherwise     → w_u = -B / coeff
    let result = match b_val {
        // B = 0 → w_u = 0
        None => writer.inner.emit_zero()?,
        // coeff = -1 → w_u = B
        Some(b) if coeff == -FieldElement::one() => b,
        // coeff = 1 → w_u = -B  /  general → w_u = -B / coeff
        Some(b) => {
            let neg_op = writer.inner.block.insert_operation_before(
                writer.inner.ret_op,
                dialect::felt::neg(writer.inner.location, b)?,
            );
            let neg_b: Value = neg_op.result(0)?.into();

            if coeff.is_one() {
                neg_b
            } else {
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
        }
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

/// Collects LLZK values for all terms in `expr`, optionally skipping one linear witness.
///
/// Iterates mul_terms, linear_combinations, and q_c, emitting the corresponding
/// LLZK operations via `inner`. If `skip_witness` is `Some(w_u)`, that witness's
/// linear term is excluded from the returned values and its coefficient is returned
/// as the second element of the tuple instead.
///
/// This is the shared core of both `emit_constrain` (skip_witness = None) and
/// `solve_witness` (skip_witness = Some(w_u) to isolate B from the unknown term).
fn collect_expr_terms<'c, 'b>(
    inner: &mut BlockWriter<'c, 'b>,
    expr: &Expression<FieldElement>,
    skip_witness: Option<u32>,
) -> Result<(Vec<Value<'c, 'b>>, Option<FieldElement>), LlzkError> {
    let mut terms = Vec::new();
    let mut skipped_coeff = None;

    // Multiplication terms: coeff * w_i * w_j
    for (coeff, w_i, w_j) in &expr.mul_terms {
        if coeff.is_zero() {
            continue;
        }
        let vi = inner.read_witness(w_i.0)?;
        let vj = inner.read_witness(w_j.0)?;
        let mul_op = inner
            .block
            .insert_operation_before(inner.ret_op, dialect::felt::mul(inner.location, vi, vj)?);
        let product: Value = mul_op.result(0)?.into();
        if let Some(val) = inner.apply_coefficient(product, coeff)? {
            terms.push(val);
        }
    }

    // Linear terms: coeff * w_k
    for (coeff, w_k) in &expr.linear_combinations {
        if coeff.is_zero() {
            continue;
        }
        if skip_witness == Some(w_k.0) {
            skipped_coeff = Some(*coeff);
            continue;
        }
        let vk = inner.read_witness(w_k.0)?;
        if let Some(val) = inner.apply_coefficient(vk, coeff)? {
            terms.push(val);
        }
    }

    // Constant term q_c
    if !expr.q_c.is_zero() {
        let const_attr = field_to_felt_const(inner.context, &expr.q_c);
        let const_op = inner.block.insert_operation_before(
            inner.ret_op,
            dialect::felt::constant(inner.location, const_attr)?,
        );
        terms.push(const_op.result(0)?.into());
    }

    Ok((terms, skipped_coeff))
}
