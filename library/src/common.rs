use std::collections::BTreeSet;

use acir::native_types::Expression;
use acir::{AcirField, FieldElement};
use llzk::dialect::felt::FeltConstAttribute;
use llzk::prelude::{
    Block, BlockLike, LlzkContext, Location, OperationRef, Region, RegionLike, Type, Value,
    melior_dialects::scf,
};
use num_bigint::BigUint;

use crate::FIELD_NAME;
use crate::block_writer::BlockWriter;
use crate::error::Error;
use crate::writer::Writer;

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
        None => writer.emit_constant(&FieldElement::zero()),
    }
}

/// Evaluates an ACIR `Expression` into an LLZK SSA `Value`, optionally
/// excluding terms that reference one witness.
pub(crate) fn emit_expression_excluding<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    expr: &Expression<FieldElement>,
    skip_witness: Option<u32>,
) -> Result<(Option<Value<'c, 'b>>, SkippedCoeff<'c, 'b>), Error> {
    let mut terms: Vec<Value<'c, 'b>> = Vec::new();
    let mut skipped = SkippedCoeff::new();

    // Multiplication terms: coeff * w_i * w_j
    for (coeff, w_i, w_j) in &expr.mul_terms {
        if coeff.is_zero() {
            continue;
        }
        // If the unknown appears here, fold the term into the skipped coefficient
        if let Some(w_u) = skip_witness {
            let i_is_unknown = w_i.0 == w_u;
            let j_is_unknown = w_j.0 == w_u;
            if i_is_unknown && j_is_unknown {
                return Err(Error::NonLinearUnknown { witness: w_u });
            }
            if i_is_unknown || j_is_unknown {
                let other = if i_is_unknown { w_j.0 } else { w_i.0 };
                let other_val = writer.read_witness(other)?;
                let contribution = apply_coefficient(writer, other_val, coeff)?
                    .expect("zero coefficient already filtered above");
                skipped.mul = Some(match skipped.mul {
                    None => contribution,
                    Some(prev) => writer.insert_add(prev, contribution)?,
                });
                continue;
            }
        }
        let vi = writer.read_witness(w_i.0)?;
        let vj = writer.read_witness(w_j.0)?;
        let product = writer.insert_mul(vi, vj)?;
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
            skipped.linear += *coeff;
            continue;
        }
        let vk = writer.read_witness(w_k.0)?;
        if let Some(val) = apply_coefficient(writer, vk, coeff)? {
            terms.push(val);
        }
    }

    // Constant term q_c
    if !expr.q_c.is_zero() {
        terms.push(writer.emit_constant(&expr.q_c)?);
    }

    // Sum all terms.
    if terms.is_empty() {
        return Ok((None, skipped));
    }
    let mut acc = terms[0];
    for &term in &terms[1..] {
        acc = writer.insert_add(acc, term)?;
    }
    Ok((Some(acc), skipped))
}

/// The linear coefficient of the skipped witness, accumulated by
/// [`emit_expression_excluding`].
#[derive(Clone, Copy)]
pub(crate) struct SkippedCoeff<'c, 'b> {
    /// Sum of `linear_combinations` coefficients on the skipped witness.
    pub(crate) linear: FieldElement,
    /// Sum of `coeff * other_value` runtime products from `mul_terms` that
    /// involve the skipped witness exactly once.
    pub(crate) mul: Option<Value<'c, 'b>>,
}

impl<'c, 'b> SkippedCoeff<'c, 'b> {
    fn new() -> Self {
        Self {
            linear: FieldElement::zero(),
            mul: None,
        }
    }

    /// True when no term referenced the skipped witness with a non-zero coefficient.
    pub(crate) fn is_zero(&self) -> bool {
        self.linear.is_zero() && self.mul.is_none()
    }

    /// The compile-time coefficient, if no mul terms contributed.
    pub(crate) fn as_scalar(&self) -> Option<FieldElement> {
        self.mul.is_none().then_some(self.linear)
    }

    /// Materializes the coefficient as a single SSA value.
    pub(crate) fn to_value(self, writer: &mut BlockWriter<'c, 'b>) -> Result<Value<'c, 'b>, Error> {
        match self.mul {
            None => writer.emit_constant(&self.linear),
            Some(m) if self.linear.is_zero() => Ok(m),
            Some(m) => {
                let lv = writer.emit_constant(&self.linear)?;
                writer.insert_add(m, lv)
            }
        }
    }
}
/// Multiplies a value by a coefficient, with optimizations for 0, 1, and -1.
///
/// Returns `None` if the coefficient is zero (term should be skipped).
pub(crate) fn apply_coefficient<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
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
        return Ok(Some(writer.insert_neg(value)?));
    }
    let coeff_val = writer.emit_constant(coeff)?;
    Ok(Some(writer.insert_mul(value, coeff_val)?))
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
    let neg_rhs = writer.insert_neg(rhs)?;
    let diff = writer.insert_add(lhs, neg_rhs)?;
    let gated = writer.insert_mul(predicate, diff)?;
    let zero = writer.emit_constant(&FieldElement::zero())?;
    writer.insert_constrain_eq(gated, zero);
    Ok(())
}

pub(crate) fn build_yielding_region<'c, const N: usize, F>(
    location: Location<'c>,
    build: F,
) -> Result<Region<'c>, Error>
where
    F: for<'a> FnOnce(&'a Block<'c>) -> Result<[Value<'c, 'a>; N], Error>,
{
    let region = Region::new();
    let block = Block::new(&[]);
    let values = build(&block)?;
    block.append_operation(scf::r#yield(&values, location));
    region.append_block(block);
    Ok(region)
}

pub(crate) fn append_if_with_results<'c, 'a, const N: usize, Then, Else>(
    block: &'a Block<'c>,
    location: Location<'c>,
    condition: Value<'c, 'a>,
    result_types: &[Type<'c>; N],
    then_build: Then,
    else_build: Else,
) -> Result<[Value<'c, 'a>; N], Error>
where
    Then: for<'r> FnOnce(&'r Block<'c>) -> Result<[Value<'c, 'r>; N], Error>,
    Else: for<'r> FnOnce(&'r Block<'c>) -> Result<[Value<'c, 'r>; N], Error>,
{
    let then_region = build_yielding_region(location, then_build)?;
    let else_region = build_yielding_region(location, else_build)?;
    let result_op = block.append_operation(scf::r#if(
        condition,
        result_types,
        then_region,
        else_region,
        location,
    ));
    collect_results(result_op)
}

pub(crate) fn insert_if_with_results<'c, 'a, const N: usize, Then, Else>(
    writer: &BlockWriter<'c, 'a>,
    condition: Value<'c, 'a>,
    result_types: &[Type<'c>; N],
    then_build: Then,
    else_build: Else,
) -> Result<[Value<'c, 'a>; N], Error>
where
    Then: for<'r> FnOnce(&'r Block<'c>) -> Result<[Value<'c, 'r>; N], Error>,
    Else: for<'r> FnOnce(&'r Block<'c>) -> Result<[Value<'c, 'r>; N], Error>,
{
    let location = writer.location();
    let then_region = build_yielding_region(location, then_build)?;
    let else_region = build_yielding_region(location, else_build)?;
    let result_op = writer.insert_op(scf::r#if(
        condition,
        result_types,
        then_region,
        else_region,
        location,
    ));
    collect_results(result_op)
}

fn collect_results<'c, 'a, const N: usize>(
    op: OperationRef<'c, 'a>,
) -> Result<[Value<'c, 'a>; N], Error> {
    let mut values = Vec::with_capacity(N);
    for index in 0..N {
        values.push(op.result(index)?.into());
    }
    Ok(values.try_into().unwrap_or_else(|_| unreachable!()))
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
