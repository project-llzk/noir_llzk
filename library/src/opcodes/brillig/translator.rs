//! Brillig bytecode → LLZK body translator.
//!
//! The main entry point is [`translate_bytecode`], which builds a
//! [`BrilligHandler`](super::opcodes::BrilligHandler) trait object for each
//! opcode via [`build_handler`](super::opcodes::build_handler) and executes
//! it against the shared [`TranslationCtx`].

use acir::FieldElement;
use acir::brillig::{
    BinaryFieldOp, BinaryIntOp, BitSize, HeapVector, IntegerBitSize, MemoryAddress,
};
use acir::circuit::brillig::BrilligBytecode;
use llzk::prelude::Value;

use crate::brillig_writer::BrilligWriter;
use crate::error::Error;

use super::memory::Memory;
use super::opcodes::build_handler;

// ── Core types ─────────────────────────────────────────────────────────

/// Result of handling a single Brillig opcode.
pub(crate) enum OpcodeAction<'c, 'b> {
    /// Continue to the next opcode.
    Continue,
    /// Return these values (from `Stop`).
    Return(Vec<Value<'c, 'b>>),
}

/// Shared translation state passed to each opcode handler.
///
/// Bundles the mutable state that every handler needs: the LLZK writer, the
/// Brillig memory model (register file + tracked integer constants), and
/// the function's calldata.
pub(crate) struct TranslationCtx<'c, 'b, 'r> {
    pub(crate) writer: &'r mut BrilligWriter<'c, 'b>,
    pub(crate) memory: Memory,
    pub(crate) calldata: &'r [Value<'c, 'b>],
    pub(crate) expected_output_count: usize,
}

// ── TranslationCtx shared helpers ──────────────────────────────────────

impl<'c, 'b, 'r> TranslationCtx<'c, 'b, 'r> {
    /// Emits a felt constant. ACVM produces canonical bytecode, so integer
    /// width is enforced downstream on cast/use rather than here.
    pub(super) fn emit_const(&mut self, value: &FieldElement) -> Result<Value<'c, 'b>, Error> {
        self.writer.emit_constant(value)
    }

    /// Emits conversion ops to reinterpret `src` (a felt) as
    /// `target_bit_size`. Field targets are a no-op; integer targets apply
    /// `felt.bit_and` against `2^n - 1` to enforce the bit-width invariant.
    pub(super) fn emit_cast(
        &mut self,
        src: Value<'c, 'b>,
        target_bit_size: &BitSize,
    ) -> Result<Value<'c, 'b>, Error> {
        match target_bit_size {
            BitSize::Field => Ok(src),
            BitSize::Integer(int_size) => self.emit_mask(src, *int_size),
        }
    }

    /// Applies `v & (2^n - 1)` via `felt.bit_and` with a constant mask,
    /// forcing `v` into the `[0, 2^n)` range.
    pub(super) fn emit_mask(
        &mut self,
        val: Value<'c, 'b>,
        int_size: IntegerBitSize,
    ) -> Result<Value<'c, 'b>, Error> {
        let mask = mask_for(int_size);
        let mask_val = self.writer.emit_constant(&FieldElement::from(mask))?;
        self.writer.insert_felt_bit_and(val, mask_val)
    }

    /// Emits the LLZK op for a `BinaryFieldOp`.
    pub(super) fn emit_binary_field_op(
        &self,
        op: &BinaryFieldOp,
        lhs: Value<'c, 'b>,
        rhs: Value<'c, 'b>,
    ) -> Result<Value<'c, 'b>, Error> {
        match op {
            BinaryFieldOp::Add => self.writer.insert_add(lhs, rhs),
            BinaryFieldOp::Sub => self.writer.insert_sub(lhs, rhs),
            BinaryFieldOp::Mul => self.writer.insert_mul(lhs, rhs),
            BinaryFieldOp::Div => self.writer.insert_div(lhs, rhs),
            BinaryFieldOp::Equals => self.writer.insert_bool_eq(lhs, rhs),
            BinaryFieldOp::LessThan => self.writer.insert_bool_lt(lhs, rhs),
            BinaryFieldOp::LessThanEquals => self.writer.insert_bool_le(lhs, rhs),
            BinaryFieldOp::IntegerDiv => self.writer.insert_uintdiv(lhs, rhs),
        }
    }

    /// Emits the LLZK op for a `BinaryIntOp`, producing a felt result.
    ///
    /// Operations that can exceed the bit width (`Add`, `Sub`, `Mul`,
    /// `Shl`) are masked back into `[0, 2^n)` here. Bitwise ops, shifts
    /// right, and divisions are already width-preserving when their
    /// inputs are. Comparisons return a bare `i1` via `bool.cmp` and
    /// never need masking.
    pub(super) fn emit_binary_int_op(
        &mut self,
        op: &BinaryIntOp,
        bit_size: IntegerBitSize,
        lhs: Value<'c, 'b>,
        rhs: Value<'c, 'b>,
    ) -> Result<Value<'c, 'b>, Error> {
        let raw = match op {
            BinaryIntOp::Add => self.writer.insert_add(lhs, rhs)?,
            BinaryIntOp::Sub => self.writer.insert_sub(lhs, rhs)?,
            BinaryIntOp::Mul => self.writer.insert_mul(lhs, rhs)?,
            BinaryIntOp::Div => return self.writer.insert_uintdiv(lhs, rhs),
            BinaryIntOp::Equals => return self.writer.insert_bool_eq(lhs, rhs),
            BinaryIntOp::LessThan => return self.writer.insert_bool_lt(lhs, rhs),
            BinaryIntOp::LessThanEquals => return self.writer.insert_bool_le(lhs, rhs),
            BinaryIntOp::And => return self.writer.insert_felt_bit_and(lhs, rhs),
            BinaryIntOp::Or => return self.writer.insert_felt_bit_or(lhs, rhs),
            BinaryIntOp::Xor => return self.writer.insert_felt_bit_xor(lhs, rhs),
            BinaryIntOp::Shl => self.writer.insert_felt_shl(lhs, rhs)?,
            BinaryIntOp::Shr => return self.writer.insert_felt_shr(lhs, rhs),
        };
        self.emit_mask(raw, bit_size)
    }

    /// Reads the `Stop` opcode's `return_data` HeapVector and emits
    /// `ram.load` ops for each return slot.
    pub(super) fn emit_return_data(
        &mut self,
        return_data: &HeapVector,
        opcode_index: usize,
    ) -> Result<Vec<Value<'c, 'b>>, Error> {
        if self.expected_output_count == 0 {
            return Ok(Vec::new());
        }

        let size =
            self.memory
                .get_const(return_data.size)?
                .ok_or_else(|| Error::UnsupportedBrillig {
                    reason: format!(
                        "Stop at bytecode index {opcode_index}: return_data size register {} \
                     is not a known integer constant",
                        return_data.size.to_u32()
                    ),
                })?;
        let pointer = self.memory.get_const(return_data.pointer)?.ok_or_else(|| {
            Error::UnsupportedBrillig {
                reason: format!(
                    "Stop at bytecode index {opcode_index}: return_data pointer register {} \
                     is not a known integer constant",
                    return_data.pointer.to_u32()
                ),
            }
        })?;

        if size != self.expected_output_count {
            return Err(Error::UnsupportedBrillig {
                reason: format!(
                    "Stop at bytecode index {opcode_index}: return_data size is {size} \
                     but expected {} output(s)",
                    self.expected_output_count
                ),
            });
        }

        let mut returns = Vec::with_capacity(size);
        for j in 0..size {
            let addr = MemoryAddress::Direct((pointer + j) as u32);
            let val = self.memory.read(self.writer, addr)?;
            returns.push(val);
        }
        Ok(returns)
    }
}

/// Returns `2^n - 1` as a `u128`, saturating at `u128::MAX` for `n = 128`.
fn mask_for(int_size: IntegerBitSize) -> u128 {
    let n = u32::from(int_size);
    if n >= 128 {
        u128::MAX
    } else {
        (1u128 << n) - 1
    }
}

// ── Main entry point ───────────────────────────────────────────────────

/// Translates `bytecode` into the body of a Brillig sibling function.
///
/// Each opcode is converted to a [`BrilligHandler`](super::opcodes::BrilligHandler)
/// trait object via [`build_handler`](super::opcodes::build_handler), then
/// executed against the shared [`TranslationCtx`]. On `Stop` (or
/// end-of-bytecode) the translator returns the SSA values the caller
/// should pass to `function.return`.
///
/// `calldata` carries the function's block arguments in the order dictated by
/// the flattened `BrilligInputs`. `CalldataCopy` opcodes in the bytecode read
/// from this slice to seed the register map.
pub(super) fn translate_bytecode<'c, 'b>(
    writer: &mut BrilligWriter<'c, 'b>,
    bytecode: &BrilligBytecode<FieldElement>,
    calldata: &[Value<'c, 'b>],
    expected_output_count: usize,
) -> Result<Vec<Value<'c, 'b>>, Error> {
    let mut ctx = TranslationCtx {
        writer,
        memory: Memory::new(),
        calldata,
        expected_output_count,
    };

    for (i, op) in bytecode.bytecode.iter().enumerate() {
        let handler = build_handler(i, op)?;
        if let OpcodeAction::Return(vals) = handler.execute(&mut ctx, i)? {
            return Ok(vals);
        }
    }

    // End-of-bytecode without an explicit `Stop` — no return data.
    if ctx.expected_output_count != 0 {
        return Err(Error::UnsupportedBrillig {
            reason: format!(
                "brillig function declares {} output(s) but \
                 bytecode ended without a Stop opcode",
                ctx.expected_output_count
            ),
        });
    }
    Ok(Vec::new())
}
