use acir::{AcirField, FieldElement, circuit::opcodes::MemOp};

use crate::{Error, opcodes::TranslatedOpcode};

mod memory_init;
mod memory_read;
mod memory_write;
mod selectors;

pub(crate) use memory_init::MemoryInit;
pub(crate) use memory_read::MemoryRead;
pub(crate) use memory_write::MemoryWrite;

/// Builds a [`MemoryRead`] or [`MemoryWrite`] from an ACIR [`MemOp`].
///
/// Inspects `op.operation` to determine the direction:
/// - `0` → read (extracts the single value witness)
/// - `1` → write
pub(crate) fn from_opcode<'p>(
    block_id: u32,
    op: &'p MemOp<FieldElement>,
) -> Result<TranslatedOpcode<'p>, Error> {
    let is_write = parse_mem_op_type(&op.operation)?;
    if is_write {
        Ok(Box::new(MemoryWrite {
            block_id,
            index: &op.index,
            value: &op.value,
        }))
    } else {
        let value_witness = extract_value_witness(&op.value)?;
        Ok(Box::new(MemoryRead {
            block_id,
            index: &op.index,
            value_witness,
        }))
    }
}

pub(super) fn uninit_error(block_id: u32) -> Error {
    Error::UnsupportedOpcode(format!("MemoryOp on block {block_id} before MemoryInit"))
}

/// Returns `true` for a write (`operation = 1`), `false` for a read (`operation = 0`).
///
/// Errors if the operation expression is not a plain constant 0 or 1.
fn parse_mem_op_type(op: &acir::native_types::Expression<FieldElement>) -> Result<bool, Error> {
    if !op.mul_terms.is_empty() || !op.linear_combinations.is_empty() {
        return Err(Error::UnsupportedOpcode(
            "MemoryOp operation must be a constant expression".into(),
        ));
    }
    if op.q_c == FieldElement::zero() {
        Ok(false)
    } else if op.q_c == FieldElement::one() {
        Ok(true)
    } else {
        Err(Error::UnsupportedOpcode(
            "MemoryOp operation constant must be 0 (read) or 1 (write)".into(),
        ))
    }
}

/// Extracts the single witness index from a read-value expression `1 * w`.
///
/// ACIR always encodes the value field of a read as a single-witness expression.
/// Returns an error for any other shape.
fn extract_value_witness(
    expr: &acir::native_types::Expression<FieldElement>,
) -> Result<u32, Error> {
    match (
        expr.mul_terms.as_slice(),
        expr.linear_combinations.as_slice(),
    ) {
        ([], [(coeff, w)]) if coeff.is_one() && expr.q_c.is_zero() => Ok(w.0),
        _ => Err(Error::UnsupportedOpcode(
            "MemoryOp read: value must be a single witness (1*w + 0)".into(),
        )),
    }
}
