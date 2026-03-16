use super::OpcodeEmitter;
use crate::{
    block_writer::BlockWriter,
    common::{collect_witnesses, field_to_felt_const},
    error::Error,
};
use acir::{AcirField, FieldElement, native_types::Expression};
use llzk::prelude::{Value, dialect};

pub(crate) struct AssertZero<'a> {
    pub(crate) expr: &'a Expression<FieldElement>,
    pub(crate) index: usize,
}

impl OpcodeEmitter for AssertZero<'_> {
    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let all_witnesses = collect_witnesses(self.expr);
        let unknowns: Vec<u32> = all_witnesses
            .iter()
            .filter(|w| !writer.is_known(**w))
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

    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let (terms, _) = collect_expr_terms(writer, self.expr, None)?;

        if terms.is_empty() {
            return Ok(());
        }

        // Accumulate all terms, then assert their sum == 0.
        let acc = accumulate_terms(writer, &terms)?.expect("terms is non-empty; guarded above");
        let zero_val = writer.emit_zero()?;
        writer.insert_op(dialect::constrain::eq(writer.location, acc, zero_val));

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
    writer: &mut BlockWriter<'c, 'b>,
    expr: &Expression<FieldElement>,
    w_u: u32,
) -> Result<(), Error> {
    let (b_terms, coeff_of_unknown) = collect_expr_terms(writer, expr, Some(w_u))?;
    let coeff = coeff_of_unknown.expect("unknown witness should have a linear term");

    let b_val = accumulate_terms(writer, &b_terms)?;

    // Solve w_u = -B / coeff, with optimizations:
    //   B = 0         → w_u = 0
    //   coeff =  1    → w_u = -B
    //   coeff = -1    → w_u =  B
    //   otherwise     → w_u = -B / coeff
    let result = match b_val {
        // B = 0 → w_u = 0
        None => writer.emit_zero()?,
        // coeff = -1 → w_u = B
        Some(b) if coeff == -FieldElement::one() => b,
        // coeff = 1 → w_u = -B  /  general → w_u = -B / coeff
        Some(b) => {
            let neg_b: Value = writer
                .insert_op(dialect::felt::neg(writer.location, b)?)
                .result(0)?
                .into();

            if coeff.is_one() {
                neg_b
            } else {
                let coeff_attr = field_to_felt_const(writer.context, &coeff);
                let coeff_val: Value = writer
                    .insert_op(dialect::felt::constant(writer.location, coeff_attr)?)
                    .result(0)?
                    .into();

                writer
                    .insert_op(dialect::felt::div(writer.location, neg_b, coeff_val)?)
                    .result(0)?
                    .into()
            }
        }
    };

    // Write the solved witness to the struct.
    writer.write_member(&format!("w{w_u}"), result)?;

    // Mark as known and cache the value.
    writer.mark_known(w_u, result);

    Ok(())
}

/// Collects LLZK values for all terms in `expr`, optionally skipping one linear witness.
///
/// Iterates mul_terms, linear_combinations, and q_c, emitting the corresponding
/// LLZK operations via `writer`. If `skip_witness` is `Some(w_u)`, that witness's
/// linear term is excluded from the returned values and its coefficient is returned
/// as the second element of the tuple instead.
///
/// This is the shared core of both `emit_constrain` (skip_witness = None) and
/// `solve_witness` (skip_witness = Some(w_u) to isolate B from the unknown term).
fn collect_expr_terms<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    expr: &Expression<FieldElement>,
    skip_witness: Option<u32>,
) -> Result<(Vec<Value<'c, 'b>>, Option<FieldElement>), Error> {
    let mut terms = Vec::new();
    let mut skipped_coeff = None;

    // Multiplication terms: coeff * w_i * w_j
    for (coeff, w_i, w_j) in &expr.mul_terms {
        if coeff.is_zero() {
            continue;
        }
        let vi = writer.read_witness(w_i.0)?;
        let vj = writer.read_witness(w_j.0)?;
        let product: Value = writer
            .insert_op(dialect::felt::mul(writer.location, vi, vj)?)
            .result(0)?
            .into();
        if let Some(val) = apply_coefficient(writer, product, coeff)? {
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
        let vk = writer.read_witness(w_k.0)?;
        if let Some(val) = apply_coefficient(writer, vk, coeff)? {
            terms.push(val);
        }
    }

    // Constant term q_c
    if !expr.q_c.is_zero() {
        let const_attr = field_to_felt_const(writer.context, &expr.q_c);
        terms.push(
            writer
                .insert_op(dialect::felt::constant(writer.location, const_attr)?)
                .result(0)?
                .into(),
        );
    }

    Ok((terms, skipped_coeff))
}

/// Accumulates a list of values by chaining `felt.add` operations.
///
/// Returns `None` if the list is empty.
fn accumulate_terms<'c, 'b>(
    writer: &BlockWriter<'c, 'b>,
    terms: &[Value<'c, 'b>],
) -> Result<Option<Value<'c, 'b>>, Error> {
    if terms.is_empty() {
        return Ok(None);
    }
    let mut acc = terms[0];
    for &term in &terms[1..] {
        acc = writer
            .insert_op(dialect::felt::add(writer.location, acc, term)?)
            .result(0)?
            .into();
    }
    Ok(Some(acc))
}

/// Multiplies a value by a coefficient, with optimizations for 0, 1, and -1.
///
/// Returns `None` if the coefficient is zero (term should be skipped).
fn apply_coefficient<'c, 'b>(
    writer: &BlockWriter<'c, 'b>,
    value: Value<'c, 'b>,
    coeff: &FieldElement,
) -> Result<Option<Value<'c, 'b>>, Error> {
    if coeff.is_zero() {
        return Ok(None);
    }
    if coeff.is_one() {
        return Ok(Some(value));
    }
    if *coeff == -FieldElement::one() {
        let neg_op = writer.insert_op(dialect::felt::neg(writer.location, value)?);
        return Ok(Some(neg_op.result(0)?.into()));
    }
    let coeff_attr = field_to_felt_const(writer.context, coeff);
    let coeff_val: Value = writer
        .insert_op(dialect::felt::constant(writer.location, coeff_attr)?)
        .result(0)?
        .into();
    let mul_op = writer.insert_op(dialect::felt::mul(writer.location, value, coeff_val)?);
    Ok(Some(mul_op.result(0)?.into()))
}
