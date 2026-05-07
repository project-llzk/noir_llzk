//! Brillig bytecode → LLZK body translator.

use std::ops::Range;

use acir::FieldElement;
use acir::brillig::{
    BinaryFieldOp, BinaryIntOp, BitSize, HeapVector, IntegerBitSize, MemoryAddress,
    Opcode as BrilligOpcode,
};
use llzk::prelude::Value;

use crate::brillig_writer::BrilligWriter;
use crate::error::Error;
use crate::opcodes::brillig::opcodes::require_const;

use super::memory::Memory;
use super::opcodes::build_handler;

// ── Core types ─────────────────────────────────────────────────────────

/// Shared translation state passed to each opcode handler.
///
/// Bundles the mutable state that every handler needs: the LLZK writer, the
/// Brillig memory model (register file + tracked integer constants), and
/// the function's calldata.
pub(crate) struct TranslationCtx<'c, 'b, 'r, M: Memory> {
    pub(crate) writer: &'r mut BrilligWriter<'c, 'b>,
    pub(crate) memory: &'r mut M,
    pub(crate) calldata: &'r [Value<'c, 'b>],
    pub(crate) expected_output_count: usize,
    pub(crate) escape_flag_addrs: Vec<Value<'c, 'b>>,
}

// ── TranslationCtx shared helpers ──────────────────────────────────────

impl<'c, 'b, 'r, M: Memory> TranslationCtx<'c, 'b, 'r, M> {
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
        let mask_val = self.emit_mask_constant(int_size)?;
        self.writer.insert_felt_bit_and(val, mask_val)
    }

    /// Emits the `2^n - 1` bitmask for `int_size` as a felt constant.
    pub(super) fn emit_mask_constant(
        &mut self,
        int_size: IntegerBitSize,
    ) -> Result<Value<'c, 'b>, Error> {
        self.writer
            .emit_constant(&FieldElement::from(mask_for(int_size)))
    }

    /// Emits the LLZK op for a `BinaryFieldOp`, returning a felt result.
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
            BinaryFieldOp::Equals => {
                let i1 = self.writer.insert_bool_eq(lhs, rhs)?;
                self.writer.insert_cast_to_felt(i1)
            }
            BinaryFieldOp::LessThan => {
                let i1 = self.writer.insert_bool_lt(lhs, rhs)?;
                self.writer.insert_cast_to_felt(i1)
            }
            BinaryFieldOp::LessThanEquals => {
                let i1 = self.writer.insert_bool_le(lhs, rhs)?;
                self.writer.insert_cast_to_felt(i1)
            }
            BinaryFieldOp::IntegerDiv => self.writer.insert_uintdiv(lhs, rhs),
        }
    }

    /// Emits the LLZK op for a `BinaryIntOp`, producing a felt result.
    ///
    /// Operations that can exceed the bit width (`Add`, `Sub`, `Mul`,
    /// `Shl`) are masked back into `[0, 2^n)` here.
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
            BinaryIntOp::Equals => {
                let i1 = self.writer.insert_bool_eq(lhs, rhs)?;
                return self.writer.insert_cast_to_felt(i1);
            }
            BinaryIntOp::LessThan => {
                let i1 = self.writer.insert_bool_lt(lhs, rhs)?;
                return self.writer.insert_cast_to_felt(i1);
            }
            BinaryIntOp::LessThanEquals => {
                let i1 = self.writer.insert_bool_le(lhs, rhs)?;
                return self.writer.insert_cast_to_felt(i1);
            }
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
    ) -> Result<Vec<Value<'c, 'b>>, Error> {
        if self.expected_output_count == 0 {
            return Ok(Vec::new());
        }
        let pointer = require_const(self, return_data.pointer, "Stop", "return data")?;
        let size = self.expected_output_count;
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

// ── Per-range emission ─────────────────────────────────────────────────

/// Runs per-opcode handlers over `bytecode[range.start..range.end]`
/// against `ctx`. Terminator opcodes (those for which [`build_handler`]
/// returns `None`) are skipped — the structured emitter translates them
/// via region nodes, not per-opcode.
pub(crate) fn translate_block_body<M: Memory>(
    ctx: &mut TranslationCtx<'_, '_, '_, M>,
    bytecode: &[BrilligOpcode<FieldElement>],
    range: Range<usize>,
) -> Result<(), Error> {
    for i in range {
        let Some(handler) = build_handler::<M>(&bytecode[i]) else {
            continue;
        };
        handler.execute(ctx, i)?;
    }
    Ok(())
}
