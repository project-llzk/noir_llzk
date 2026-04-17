//! Brillig bytecode → LLZK body translator.
//!
//! The main entry point is [`translate_bytecode`], which builds a
//! [`BrilligHandler`](super::opcodes::BrilligHandler) trait object for each
//! opcode via [`build_handler`](super::opcodes::build_handler) and executes
//! it against the shared [`TranslationCtx`].

use acir::brillig::{BinaryFieldOp, BinaryIntOp, BitSize};
use acir::circuit::brillig::BrilligBytecode;
use acir::{AcirField, FieldElement};
use llzk::prelude::melior_dialects::arith::CmpiPredicate;
use llzk::prelude::{Type, Value, ValueLike};

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
    pub(crate) memory: Memory<'c, 'b>,
    pub(crate) calldata: &'r [Value<'c, 'b>],
    pub(crate) expected_output_count: usize,
}

// ── TranslationCtx shared helpers ──────────────────────────────────────

impl<'c, 'b, 'r> TranslationCtx<'c, 'b, 'r> {
    /// Emits a constant op. Field constants become `felt.const`; integer
    /// constants become `arith.constant` with the matching `iN` type.
    pub(crate) fn emit_const(
        &mut self,
        bit_size: &BitSize,
        value: &FieldElement,
    ) -> Result<Value<'c, 'b>, Error> {
        match bit_size {
            BitSize::Field => self.writer.emit_constant(value),
            BitSize::Integer(int_size) => {
                let num_bits = u32::from(*int_size);
                let as_u128 = value.try_into_u128().ok_or(Error::ConstantOutOfRange {
                    value: *value,
                    num_bits,
                })?;
                let max = if num_bits >= 128 {
                    u128::MAX
                } else {
                    (1u128 << num_bits) - 1
                };
                if as_u128 > max {
                    return Err(Error::ConstantOutOfRange {
                        value: *value,
                        num_bits,
                    });
                }
                self.writer.insert_arith_int_constant(num_bits, as_u128)
            }
        }
    }

    /// Emits conversion ops to reinterpret `src` as `target_bit_size`.
    ///
    /// Supports the full matrix of felt ↔ `iN` conversions and integer
    /// width changes (`arith.trunci` / `arith.extui`).
    pub(crate) fn emit_cast(
        &mut self,
        src: Value<'c, 'b>,
        target_bit_size: &BitSize,
    ) -> Result<Value<'c, 'b>, Error> {
        let src_ty = src.r#type();
        let src_is_felt = is_felt_type(src_ty);
        let target_is_felt = matches!(target_bit_size, BitSize::Field);

        match (src_is_felt, target_is_felt, target_bit_size) {
            (true, true, _) => Ok(src),
            (false, false, BitSize::Integer(int_size)) => {
                let dst_bits = u32::from(*int_size);
                let src_bits = integer_width(src_ty).ok_or_else(|| Error::UnsupportedBrillig {
                    reason: format!(
                        "Cast source has non-integer type `{src_ty}`; integer width \
                             conversion requires an integer-typed source"
                    ),
                })?;
                if src_bits == dst_bits {
                    return Ok(src);
                }
                let dst_ty = self.writer.integer_type(dst_bits);
                if dst_bits < src_bits {
                    self.writer.insert_arith_trunci(src, dst_ty)
                } else {
                    self.writer.insert_arith_extui(src, dst_ty)
                }
            }
            (true, false, BitSize::Integer(int_size)) => {
                let as_index = self.writer.insert_cast_to_index(src)?;
                let dst_ty = self.writer.integer_type(u32::from(*int_size));
                self.writer.insert_arith_index_cast(as_index, dst_ty)
            }
            (false, true, _) => {
                let index_ty = self.writer.index_type();
                let as_index = self.writer.insert_arith_index_cast(src, index_ty)?;
                self.writer.insert_cast_to_felt(as_index)
            }
            (_, false, BitSize::Field) => unreachable!("BitSize::Field is target_is_felt=true"),
        }
    }

    /// Emits the LLZK op for a `BinaryFieldOp`.
    pub(crate) fn emit_binary_field_op(
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

    /// Emits the LLZK op for a `BinaryIntOp`.
    pub(crate) fn emit_binary_int_op(
        &self,
        op: &BinaryIntOp,
        lhs: Value<'c, 'b>,
        rhs: Value<'c, 'b>,
    ) -> Result<Value<'c, 'b>, Error> {
        match op {
            BinaryIntOp::Add => self.writer.insert_arith_addi(lhs, rhs),
            BinaryIntOp::Sub => self.writer.insert_arith_subi(lhs, rhs),
            BinaryIntOp::Mul => self.writer.insert_arith_muli(lhs, rhs),
            BinaryIntOp::Div => self.writer.insert_arith_divui(lhs, rhs),
            BinaryIntOp::Equals => self.writer.insert_arith_cmpi(CmpiPredicate::Eq, lhs, rhs),
            BinaryIntOp::LessThan => self.writer.insert_arith_cmpi(CmpiPredicate::Ult, lhs, rhs),
            BinaryIntOp::LessThanEquals => {
                self.writer.insert_arith_cmpi(CmpiPredicate::Ule, lhs, rhs)
            }
            BinaryIntOp::And => self.writer.insert_arith_andi(lhs, rhs),
            BinaryIntOp::Or => self.writer.insert_arith_ori(lhs, rhs),
            BinaryIntOp::Xor => self.writer.insert_arith_xori(lhs, rhs),
            BinaryIntOp::Shl => self.writer.insert_arith_shli(lhs, rhs),
            BinaryIntOp::Shr => self.writer.insert_arith_shrui(lhs, rhs),
        }
    }

    /// Checks that `val` is an integer type with the expected bit width.
    /// Returns an `UnsupportedBrillig` error on mismatch so that
    /// width disagreements between the opcode and the register map are
    /// caught early rather than surfacing as opaque LLZK verification failures.
    pub(crate) fn check_int_width(
        &self,
        val: Value<'c, 'b>,
        expected_bits: u32,
        opcode_index: usize,
    ) -> Result<(), Error> {
        let actual = integer_width(val.r#type()).ok_or_else(|| Error::UnsupportedBrillig {
            reason: format!(
                "BinaryIntOp at bytecode index {opcode_index}: operand has \
                 non-integer type `{}`",
                val.r#type()
            ),
        })?;
        if actual != expected_bits {
            return Err(Error::UnsupportedBrillig {
                reason: format!(
                    "BinaryIntOp at bytecode index {opcode_index}: operand width \
                     is i{actual} but opcode declares {expected_bits}-bit operands"
                ),
            });
        }
        Ok(())
    }

    /// Converts `val` to `index` type for `ram.load`/`ram.store` addresses.
    pub(crate) fn cast_to_index(&mut self, val: Value<'c, 'b>) -> Result<Value<'c, 'b>, Error> {
        let ty = val.r#type();
        if ty == self.writer.index_type() {
            return Ok(val);
        }
        if is_felt_type(ty) {
            return self.writer.insert_cast_to_index(val);
        }
        let index_ty = self.writer.index_type();
        self.writer.insert_arith_index_cast(val, index_ty)
    }

    /// Reads the `Stop` opcode's `return_data` HeapVector and emits
    /// `ram.load` ops for each return slot.
    pub(crate) fn emit_return_data(
        &mut self,
        return_data: &acir::brillig::HeapVector,
        opcode_index: usize,
    ) -> Result<Vec<Value<'c, 'b>>, Error> {
        if self.expected_output_count == 0 {
            return Ok(Vec::new());
        }

        let size = self.memory.get_const(return_data.size)?.ok_or_else(|| {
            Error::UnsupportedBrillig {
                reason: format!(
                    "Stop at bytecode index {opcode_index}: return_data size register {} \
                     is not a known integer constant",
                    return_data.size.to_u32()
                ),
            }
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

        let felt_ty = self.writer.felt_type();
        let mut returns = Vec::with_capacity(size);
        for j in 0..size {
            let addr = self.writer.insert_integer(pointer + j)?;
            let val = self.writer.insert_ram_load(addr, felt_ty)?;
            returns.push(val);
        }
        Ok(returns)
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
pub(crate) fn translate_bytecode<'c, 'b>(
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

// ── Utility functions ──────────────────────────────────────────────────

/// Treats any type whose textual form starts with `!felt.` as a felt type.
fn is_felt_type(ty: Type<'_>) -> bool {
    format!("{ty}").starts_with("!felt.")
}

/// Returns the bit width of an integer-typed `ty`, or `None` if not integer.
fn integer_width(ty: Type<'_>) -> Option<u32> {
    use llzk::prelude::IntegerType;
    IntegerType::try_from(ty).ok().map(|it| it.width())
}
