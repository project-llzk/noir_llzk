use std::collections::BTreeSet;

use super::OpcodeEmitter;
use crate::{
    block_writer::BlockWriter,
    common::{collect_witnesses, emit_expression, emit_expression_excluding},
    error::Error,
};
use acir::{AcirField, FieldElement, native_types::Expression};

pub(crate) struct AssertZero<'a> {
    pub(crate) expr: &'a Expression<FieldElement>,
    pub(crate) index: usize,
}

impl OpcodeEmitter for AssertZero<'_> {
    fn get_witnesses(&self) -> BTreeSet<u32> {
        collect_witnesses(self.expr)
    }

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
        let expr_val = emit_expression(writer, self.expr)?;

        // If the expression is trivially zero the constraint is vacuous.
        if expr_val == writer.emit_constant(&FieldElement::zero())? {
            return Ok(());
        }

        let zero_val = writer.emit_constant(&FieldElement::zero())?;
        writer.insert_constrain_eq(expr_val, zero_val);

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
    let (b_val, coeff_of_unknown) = emit_expression_excluding(writer, expr, Some(w_u))?;
    let coeff = coeff_of_unknown.expect("unknown witness should have a linear term");

    // Solve w_u = -B / coeff, with optimizations:
    //   B = 0         → w_u = 0
    //   coeff =  1    → w_u = -B
    //   coeff = -1    → w_u =  B
    //   otherwise     → w_u = -B / coeff
    let result = match b_val {
        // B = 0 → w_u = 0
        None => writer.emit_constant(&FieldElement::zero())?,
        // coeff = -1 → w_u = B
        Some(b) if coeff == -FieldElement::one() => b,
        // coeff = 1 → w_u = -B  /  general → w_u = -B / coeff
        Some(b) => {
            let neg_b = writer.insert_neg(b)?;

            if coeff.is_one() {
                neg_b
            } else {
                let coeff_val = writer.emit_constant(&coeff)?;
                writer.insert_div(neg_b, coeff_val)?
            }
        }
    };

    // Write the solved witness to the struct.
    writer.write_member(&format!("w{w_u}"), result)?;

    // Mark as known and cache the value.
    writer.mark_known(w_u, result);

    Ok(())
}
