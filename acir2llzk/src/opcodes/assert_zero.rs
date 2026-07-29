use std::collections::BTreeSet;

use super::OpcodeEmitter;

use crate::{
    block_writer::BlockWriter,
    common::{collect_witnesses, emit_expression, emit_expression_excluding},
    error::Error,
    writer::Writer,
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
            1 => solve_witness(writer, self.expr, unknowns[0]),
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
/// The unknown witness appears at most linearly , so the expression has the form:
/// ```text
/// w_u * coeff + B = 0
/// ```.
fn solve_witness<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    expr: &Expression<FieldElement>,
    w_u: u32,
) -> Result<(), Error> {
    let (b_val, skipped) = emit_expression_excluding(writer, expr, Some(w_u))?;
    if skipped.is_zero() {
        return Err(Error::UnconstrainedUnknown { witness: w_u });
    }

    let result = match (b_val, skipped.as_scalar()) {
        // B = 0 → w_u = 0
        (None, _) => writer.emit_constant(&FieldElement::zero())?,
        // coeff = -1 → w_u = B
        (Some(b), Some(c)) if c == -FieldElement::one() => b,
        // coeff = 1 → w_u = -B
        (Some(b), Some(c)) if c.is_one() => writer.insert_neg(b)?,
        // General: w_u = -B / coeff
        (Some(b), _) => {
            let coeff_val = skipped.to_value(writer)?;
            let neg_b = writer.insert_neg(b)?;
            writer.insert_div(neg_b, coeff_val)?
        }
    };

    // Write the solved witness to the struct.
    writer.write_member(&format!("w{w_u}"), result)?;

    // Mark as known and cache the value.
    writer.mark_known(w_u, result);

    Ok(())
}
