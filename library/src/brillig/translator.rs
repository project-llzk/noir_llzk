//! Brillig bytecode → LLZK body translator.

use std::ops::Range;

use acir::FieldElement;
use acir::brillig::{
    BinaryFieldOp, BinaryIntOp, BitSize, HeapVector, IntegerBitSize, MemoryAddress,
    Opcode as BrilligOpcode,
};
use brillig_vm::FREE_MEMORY_POINTER_ADDRESS;
use llzk::prelude::{Block, Value};

use super::memory::Memory;
use super::opcodes::build_handler;
use crate::brillig::cfg::BlockId;
use crate::brillig::opcodes::{require_const, slot_at_offset};
use crate::brillig::structurer::{CondPolarity, EscapeFlagSlot, LoopCondition};
use crate::brillig_writer::BrilligWriter;
use crate::error::Error;
use crate::writer::Writer;

// ── Core types ─────────────────────────────────────────────────────────

/// Shared state passed to each per-opcode handler.
pub(super) struct TranslationCtx<'c, 'b, 'r, M: Memory> {
    pub(super) writer: &'r mut BrilligWriter<'c, 'b>,
    pub(super) memory: &'r mut M,
    pub(super) calldata: &'r [Value<'c, 'b>],
}

// ── Per-range emission ─────────────────────────────────────────────────

/// Runs per-opcode handlers over `bytecode[range.start..range.end]`
/// against `ctx`. Terminator opcodes (those for which [`build_handler`]
/// returns `None`) are skipped — the structured emitter translates them
/// via region nodes, not per-opcode.
pub(super) fn translate_block_body<M: Memory>(
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

// ── TranslationCtx shared helpers ──────────────────────────────────────

impl<'c, 'b, 'r, M: Memory> TranslationCtx<'c, 'b, 'r, M> {
    pub(super) fn new(
        writer: &'r mut BrilligWriter<'c, 'b>,
        memory: &'r mut M,
        calldata: &'r [Value<'c, 'b>],
    ) -> Self {
        Self {
            writer,
            memory,
            calldata,
        }
    }

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
    fn emit_mask(
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

/// Creates a fresh [`Block`], runs `f` with the writer redirected to it,
/// then restores the previous insertion target. Returns the populated
/// block (or propagates the closure's error).
pub(super) fn build_block_with<'c, 'b, M, F>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
    f: F,
) -> Result<Block<'c>, Error>
where
    M: Memory,
    F: FnOnce(&mut TranslationCtx<'c, 'b, '_, M>) -> Result<(), Error>,
{
    let block = Block::new(&[]);
    let saved = ctx.writer.enter_block(&block);
    let outcome = f(ctx);
    ctx.writer.leave_block(saved);
    outcome?;
    Ok(block)
}

/// Allocates `count` escape-flag cells from the Brillig heap by bumping
/// `FREE_MEMORY_POINTER_ADDRESS` (`@1`), zero-initialises them so loop
/// test-prefix reads observe `flag = 0` on the first iteration, and
/// returns their index-typed addresses.
///
/// Cooperates with the Brillig program's own allocator: the bump tells
/// any subsequent FMP-routed allocation to skip our slots.
pub(super) fn init_escape_flags<'c, 'b, M: Memory>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
    count: usize,
) -> Result<Vec<Value<'c, 'b>>, Error> {
    if count == 0 {
        return Ok(Vec::new());
    }

    let fmp_slot = match FREE_MEMORY_POINTER_ADDRESS {
        MemoryAddress::Direct(s) => s as usize,
        MemoryAddress::Relative(_) => {
            unreachable!("FREE_MEMORY_POINTER_ADDRESS is defined as Direct in brillig_vm")
        }
    };
    let fmp_addr = ctx.writer.insert_integer(fmp_slot)?;
    let fmp_felt = ctx.writer.insert_ram_load(fmp_addr)?;
    let fmp_idx = ctx.writer.cast_to_index(fmp_felt)?;

    let zero = ctx.writer.emit_constant(&FieldElement::from(0u128))?;
    let mut escape_flag_addrs = Vec::with_capacity(count);
    for i in 0..count {
        let slot_addr = slot_at_offset(ctx, fmp_idx, i)?;
        ctx.writer.insert_ram_store(slot_addr, zero);
        escape_flag_addrs.push(slot_addr);
    }

    let count_idx = ctx.writer.insert_integer(count)?;
    let bumped_idx = ctx.writer.insert_index_add(fmp_idx, count_idx)?;
    let bumped_felt = ctx.writer.insert_cast_to_felt(bumped_idx)?;
    ctx.writer.insert_ram_store(fmp_addr, bumped_felt);
    Ok(escape_flag_addrs)
}

/// Builds the `i1` continuation condition for an `scf.while`:
///   - `Some(loop_cond)`: load the register, convert felt → i1; invert
///     when polarity is `ExitOnTrue` so "true means continue".
///   - `Some(slot)`: load the escape flag, convert to i1, invert (we
///     want "true means *not* set, i.e. continue").
///   - When both are present, AND them.
pub(super) fn compute_loop_continue_cond<'c, 'b, M: Memory>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
    escape_flag_addrs: &[Value<'c, 'b>],
    condition: &Option<LoopCondition>,
    escape_flag: Option<EscapeFlagSlot>,
    header: super::cfg::BlockId,
) -> Result<Value<'c, 'b>, Error> {
    let from_cond = match condition {
        Some(loop_cond) => {
            let cond_felt = ctx.memory.read(ctx.writer, loop_cond.register)?;
            let cond_bool = ctx.writer.insert_felt_to_bool(cond_felt)?;
            Some(match loop_cond.polarity {
                CondPolarity::ContinueOnTrue => cond_bool,
                CondPolarity::ExitOnTrue => ctx.writer.insert_bool_not(cond_bool)?,
            })
        }
        None => None,
    };
    let from_flag = match escape_flag {
        Some(slot) => {
            let addr = escape_flag_addrs[slot.0];
            let flag_felt = ctx.writer.insert_ram_load(addr)?;
            let flag_bool = ctx.writer.insert_felt_to_bool(flag_felt)?;
            Some(ctx.writer.insert_bool_not(flag_bool)?)
        }
        None => None,
    };
    match (from_cond, from_flag) {
        (Some(c), Some(f)) => ctx.writer.insert_bool_and(c, f),
        (Some(c), None) => Ok(c),
        (None, Some(f)) => Ok(f),
        (None, None) => Err(Error::UnsupportedBrillig {
            reason: format!(
                "Loop(header=b{}): no condition and no escape flag — \
                 infinite loop with no exit",
                header.0
            ),
        }),
    }
}

/// Emits an `scf.if` whose then- and else-region bodies are produced by
/// invoking `emit` against `then_arg` and `else_arg` respectively. The
/// `i1` condition is materialised in the current block; the memory
/// cache is snapshotted before the arms and met across them at the
/// join, so post-`if` cache state never claims a value that holds on
/// only one path.
///
/// `emit` is a single `FnMut` rather than two `FnOnce` closures so the
/// caller can capture `&mut self` once. Two `FnOnce` closures both
/// borrowing `&mut self` would conflict at the call site.
pub(super) fn emit_if_with<'c, 'b, M, T, F>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
    condition: MemoryAddress,
    then_arg: T,
    else_arg: T,
    mut emit: F,
) -> Result<(), Error>
where
    M: Memory,
    F: FnMut(&mut TranslationCtx<'c, 'b, '_, M>, T) -> Result<(), Error>,
{
    let cond_felt = ctx.memory.read(ctx.writer, condition)?;
    let cond_bool = ctx.writer.insert_felt_to_bool(cond_felt)?;

    let pre_branch = ctx.memory.clone();
    let then_block = build_block_with(ctx, |ctx| emit(ctx, then_arg))?;
    let after_then = ctx.memory.clone();
    *ctx.memory = pre_branch;
    let else_block = build_block_with(ctx, |ctx| emit(ctx, else_arg))?;
    ctx.memory.meet(&after_then);

    ctx.writer
        .insert_scf_if(cond_bool, then_block, else_block)?;
    Ok(())
}

/// Emits an `scf.while`. The before-region body is `emit(test_prefix_arg)`
/// followed by a [`compute_loop_continue_cond`]-derived `scf.condition`
/// terminator; the after-region body is `emit(body_arg)` followed by
/// `scf.yield`.
///
/// `emit` is a single `FnMut` (see [`emit_if_with`] for the rationale).
pub(super) fn emit_while_with<'c, 'b, M, T, F>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
    test_prefix_arg: T,
    body_arg: T,
    escape_flag_addrs: &[Value<'c, 'b>],
    condition: &Option<LoopCondition>,
    escape_flag: Option<EscapeFlagSlot>,
    header: BlockId,
    mut emit: F,
) -> Result<(), Error>
where
    M: Memory,
    F: FnMut(&mut TranslationCtx<'c, 'b, '_, M>, T) -> Result<(), Error>,
{
    let before_block = build_block_with(ctx, |ctx| {
        emit(ctx, test_prefix_arg)?;
        let continue_cond =
            compute_loop_continue_cond(ctx, escape_flag_addrs, condition, escape_flag, header)?;
        ctx.writer.insert_scf_condition(continue_cond, &[]);
        Ok(())
    })?;
    let after_block = build_block_with(ctx, |ctx| {
        emit(ctx, body_arg)?;
        ctx.writer.insert_scf_yield(&[]);
        Ok(())
    })?;
    ctx.writer
        .insert_scf_while(&[], &[], before_block, after_block)?;
    Ok(())
}

/// Reads the `Stop` opcode's `return_data` HeapVector and emits
/// `ram.load` ops for each return slot.
pub(super) fn emit_return_data<'c, 'b, M: Memory>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
    expected_output_count: usize,
    return_data: &HeapVector,
) -> Result<Vec<Value<'c, 'b>>, Error> {
    if expected_output_count == 0 {
        return Ok(Vec::new());
    }
    let pointer = require_const(ctx, return_data.pointer, "Stop", "return data")?;
    let mut returns = Vec::with_capacity(expected_output_count);
    for j in 0..expected_output_count {
        let addr = MemoryAddress::Direct((pointer + j) as u32);
        let val = ctx.memory.read(ctx.writer, addr)?;
        returns.push(val);
    }
    Ok(returns)
}

pub(super) fn emit_trap<'c, 'b, M: Memory>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
) -> Result<(), Error> {
    // Unconditional failure: assert(0 == 1).
    let zero = ctx.writer.emit_constant(&FieldElement::from(0u128))?;
    let one = ctx.writer.emit_constant(&FieldElement::from(1u128))?;
    let always_false = ctx.writer.insert_bool_eq(zero, one)?;
    ctx.writer.insert_bool_assert(always_false)?;
    Ok(())
}

pub(super) fn emit_bool_assert<'c, 'b, M: Memory>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
    condition: &MemoryAddress,
) -> Result<(), Error> {
    let cond_felt = ctx.memory.read(ctx.writer, *condition)?;
    let cond_bool = ctx.writer.insert_felt_to_bool(cond_felt)?;
    ctx.writer.insert_bool_assert(cond_bool)?;
    Ok(())
}

pub(super) fn emit_set_flag<'c, 'b, M: Memory>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
    slot: &EscapeFlagSlot,
    escape_flag_addrs: &[Value<'c, 'b>],
) -> Result<(), Error> {
    let one = ctx.writer.emit_constant(&FieldElement::from(1u128))?;
    let addr = escape_flag_addrs[slot.0];
    ctx.writer.insert_ram_store(addr, one);
    Ok(())
}
