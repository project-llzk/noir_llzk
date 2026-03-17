use std::collections::BTreeSet;

use acir::native_types::Expression;
use acir::{AcirField, FieldElement};
use llzk::dialect::felt::FeltConstAttribute;
use llzk::prelude::{LlzkContext, Value, dialect::constrain, dialect::felt};
use num_bigint::BigUint;

use crate::FIELD_NAME;
use crate::block_writer::BlockWriter;
use crate::error::Error;

/// Converts an ACIR `FieldElement` to an LLZK `FeltConstAttribute`.
pub(crate) fn field_to_felt_const<'c>(
    context: &'c LlzkContext,
    fe: &FieldElement,
) -> FeltConstAttribute<'c> {
    let bytes = fe.to_le_bytes();
    let biguint = BigUint::from_bytes_le(&bytes);
    FeltConstAttribute::from_biguint(context, &biguint, Some(FIELD_NAME))
}

/// Returns `true` if the predicate expression is a trivial constant `1`
/// (i.e., always true — the call is unconditional).
pub(crate) fn is_trivial_predicate(expr: &Expression<FieldElement>) -> bool {
    expr.mul_terms.is_empty() && expr.linear_combinations.is_empty() && expr.q_c.is_one()
}

/// Evaluates an ACIR `Expression` into a single LLZK SSA `Value`
pub(crate) fn emit_expression<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    expr: &Expression<FieldElement>,
) -> Result<Value<'c, 'b>, Error> {
    match emit_expression_excluding(writer, expr, None)?.0 {
        Some(val) => Ok(val),
        None => writer.emit_zero(),
    }
}

/// Evaluates an ACIR `Expression` into an LLZK SSA `Value`, optionally
/// excluding one linear witness term.
///
/// When `skip_witness` is `Some(w_u)`, the linear term for `w_u` is omitted
/// from the sum and its coefficient is returned as the second element. This
/// is used by the witness solver to isolate `B` from `w_u * coeff + B = 0`.
///
/// Returns `(None, _)` when all (non-skipped) terms sum to zero.
pub(crate) fn emit_expression_excluding<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    expr: &Expression<FieldElement>,
    skip_witness: Option<u32>,
) -> Result<(Option<Value<'c, 'b>>, Option<FieldElement>), Error> {
    let mut terms: Vec<Value<'c, 'b>> = Vec::new();
    let mut skipped_coeff = None;

    // Multiplication terms: coeff * w_i * w_j
    for (coeff, w_i, w_j) in &expr.mul_terms {
        if coeff.is_zero() {
            continue;
        }
        let vi = writer.read_witness(w_i.0)?;
        let vj = writer.read_witness(w_j.0)?;
        let product = writer.insert_op_with_result(felt::mul(writer.location, vi, vj)?)?;
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
        terms.push(writer.insert_op_with_result(felt::constant(writer.location, const_attr)?)?);
    }

    // Sum all terms.
    if terms.is_empty() {
        return Ok((None, skipped_coeff));
    }
    let mut acc = terms[0];
    for &term in &terms[1..] {
        acc = writer.insert_op_with_result(felt::add(writer.location, acc, term)?)?;
    }
    Ok((Some(acc), skipped_coeff))
}

/// Multiplies a value by a coefficient, with optimizations for 0, 1, and -1.
///
/// Returns `None` if the coefficient is zero (term should be skipped).
pub(crate) fn apply_coefficient<'c, 'b>(
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
        return Ok(Some(
            writer.insert_op_with_result(felt::neg(writer.location, value)?)?,
        ));
    }
    let coeff_attr = field_to_felt_const(writer.context, coeff);
    let coeff_val = writer.insert_op_with_result(felt::constant(writer.location, coeff_attr)?)?;
    Ok(Some(writer.insert_op_with_result(felt::mul(
        writer.location,
        value,
        coeff_val,
    )?)?))
}

/// Emits a gated equality constraint: `predicate * (lhs - rhs) == 0`.
///
/// This is trivially satisfied when the predicate is zero, allowing the
/// constraint to be conditionally enforced.
pub(crate) fn emit_gated_eq<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    predicate: Value<'c, 'b>,
    lhs: Value<'c, 'b>,
    rhs: Value<'c, 'b>,
) -> Result<(), Error> {
    let neg_rhs = writer.insert_op_with_result(felt::neg(writer.location, rhs)?)?;
    let diff = writer.insert_op_with_result(felt::add(writer.location, lhs, neg_rhs)?)?;
    let gated = writer.insert_op_with_result(felt::mul(writer.location, predicate, diff)?)?;
    let zero = writer.emit_zero()?;
    writer.insert_op(constrain::eq(writer.location, gated, zero));
    Ok(())
}

/// Collects all unique witness indices referenced in an expression.
pub(crate) fn collect_witnesses(expr: &Expression<FieldElement>) -> BTreeSet<u32> {
    let mut witnesses = BTreeSet::new();
    for (_, w_i, w_j) in &expr.mul_terms {
        witnesses.insert(w_i.0);
        witnesses.insert(w_j.0);
    }
    for (_, w_k) in &expr.linear_combinations {
        witnesses.insert(w_k.0);
    }
    witnesses
}
