mod memory_read;
mod memory_write;

pub(crate) use memory_read::{MemoryRead, emit_struct_def as emit_mem_read_struct_def};
pub(crate) use memory_write::{MemoryWrite, emit_struct_def as emit_mem_write_struct_def};

use acir::circuit::Opcode;
use acir::{AcirField, FieldElement};

use crate::error::Error;
use crate::opcodes::{BuildContext, TranslatedOpcode};

/// Dispatches an ACIR `MemoryOp` opcode to either [`MemoryRead`] or
/// [`MemoryWrite`] based on the `operation` expression, updating counters and
/// size sets in `ctx`.
pub(crate) fn from_opcode<'p>(
    opcode: &'p Opcode<FieldElement>,
    index: usize,
    ctx: &mut BuildContext<'p>,
) -> Result<TranslatedOpcode<'p>, Error> {
    let Opcode::MemoryOp {
        block_id,
        op: mem_op,
        ..
    } = opcode
    else {
        unreachable!("memory_op::from_opcode called with non-MemoryOp opcode");
    };

    let array_len = *ctx
        .block_sizes
        .get(&block_id.0)
        .ok_or(Error::UninitializedMemoryBlock {
            block_id: block_id.0,
            opcode_index: index,
        })?;

    // Determine read vs write from the operation expression.
    let op_expr = &mem_op.operation;
    let is_write = if op_expr.is_const() {
        if op_expr.q_c.is_zero() {
            false // read
        } else if op_expr.q_c.is_one() {
            true // write
        } else {
            return Err(Error::NonConstantMemoryOperation {
                opcode_index: index,
            });
        }
    } else {
        return Err(Error::NonConstantMemoryOperation {
            opcode_index: index,
        });
    };

    if is_write {
        let mi = ctx.write_count;
        ctx.write_count += 1;
        ctx.write_sizes.insert(array_len);
        Ok(Box::new(MemoryWrite {
            member_index: mi,
            block_id: block_id.0,
            array_len,
            index_expr: &mem_op.index,
            value_expr: &mem_op.value,
        }))
    } else {
        let mi = ctx.read_count;
        ctx.read_count += 1;
        ctx.read_sizes.insert(array_len);
        Ok(Box::new(MemoryRead {
            member_index: mi,
            block_id: block_id.0,
            array_len,
            index_expr: &mem_op.index,
            value_expr: &mem_op.value,
        }))
    }
}
