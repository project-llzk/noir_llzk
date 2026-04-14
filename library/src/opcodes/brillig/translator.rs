//! Brillig bytecode → LLZK body translator.
//!

use acir::brillig::{BinaryFieldOp, BinaryIntOp, BitSize, Opcode as BrilligOpcode};
use acir::circuit::brillig::BrilligBytecode;
use acir::{AcirField, FieldElement};
use llzk::prelude::melior_dialects::arith::CmpiPredicate;
use llzk::prelude::{Type, Value, ValueLike};

use crate::block_writer::BlockWriter;
use crate::error::Error;

use super::regmap::RegMap;

/// Translates `bytecode` into the body of a Brillig sibling function.
///
/// Ops are appended to `writer`'s block in order; on `Stop` (or end-of-bytecode)
/// the translator returns the SSA values the caller should pass to
/// `function.return`. The caller is responsible for appending the terminator.
///
/// Input registers are **not yet populated** — Issue 6 wires `CalldataCopy`
/// up to this layer. For the current milestone the only reachable registers
/// are those written by register-machine ops in the bytecode itself.
pub(crate) fn translate_bytecode<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    bytecode: &BrilligBytecode<FieldElement>,
    expected_output_count: usize,
) -> Result<Vec<Value<'c, 'b>>, Error> {
    let mut regmap: RegMap<'c, 'b> = RegMap::new();

    for (i, op) in bytecode.bytecode.iter().enumerate() {
        match op {
            BrilligOpcode::Const {
                destination,
                bit_size,
                value,
            } => {
                let ssa = emit_const(writer, bit_size, value)?;
                regmap.set(*destination, ssa);
            }
            BrilligOpcode::Mov {
                destination,
                source,
            } => {
                let src = regmap.get(*source, i)?;
                regmap.set(*destination, src);
            }
            BrilligOpcode::Cast {
                destination,
                source,
                bit_size,
            } => {
                let src = regmap.get(*source, i)?;
                let casted = emit_cast(writer, src, bit_size)?;
                regmap.set(*destination, casted);
            }
            BrilligOpcode::BinaryFieldOp {
                destination,
                op,
                lhs,
                rhs,
            } => {
                let lhs_v = regmap.get(*lhs, i)?;
                let rhs_v = regmap.get(*rhs, i)?;
                let result = emit_binary_field_op(writer, op, lhs_v, rhs_v, i)?;
                regmap.set(*destination, result);
            }
            BrilligOpcode::BinaryIntOp {
                destination,
                op,
                bit_size: _,
                lhs,
                rhs,
            } => {
                let lhs_v = regmap.get(*lhs, i)?;
                let rhs_v = regmap.get(*rhs, i)?;
                let result = emit_binary_int_op(writer, op, lhs_v, rhs_v)?;
                regmap.set(*destination, result);
            }
            BrilligOpcode::ConditionalMov { .. } => {
                return Err(Error::UnsupportedBrillig {
                    reason: format!(
                        "Brillig opcode `ConditionalMov` at bytecode index {i} is \
                         control flow and not supported by this milestone"
                    ),
                });
            }
            BrilligOpcode::Stop { .. } => {
                return finish(expected_output_count);
            }
            other => {
                return Err(Error::UnsupportedBrillig {
                    reason: format!(
                        "Brillig opcode `{}` at bytecode index {i} is not supported yet",
                        brillig_op_name(other)
                    ),
                });
            }
        }
    }

    // End-of-bytecode without an explicit `Stop` is treated the same way.
    finish(expected_output_count)
}

/// Emits the constant op for `Const`, returning the SSA value to bind in the
/// register map. Field constants become `felt.const`; integer constants become
/// `arith.constant` with an `iN` integer type matching the declared bit size.
fn emit_const<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    bit_size: &BitSize,
    value: &FieldElement,
) -> Result<Value<'c, 'b>, Error> {
    match bit_size {
        BitSize::Field => writer.emit_constant(value),
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
            writer.insert_arith_int_constant(num_bits, as_u128)
        }
    }
}

/// Emits the conversion op(s) required to reinterpret `src` as `target` type.
///
/// Supports the full matrix of felt ↔ `iN` conversions. `felt` ↔ `iN` goes
/// through `index` because llzk only exposes `cast.tofelt` / `cast.toindex`;
/// integer width changes use `arith.trunci` / `arith.extui` (Brillig integers
/// are unsigned, so zero-extension is always correct).
fn emit_cast<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
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
            let dst_ty = writer.integer_type(dst_bits);
            if dst_bits < src_bits {
                writer.insert_arith_trunci(src, dst_ty)
            } else {
                writer.insert_arith_extui(src, dst_ty)
            }
        }
        (true, false, BitSize::Integer(int_size)) => {
            // felt → iN: cast.toindex, then arith.index_cast into iN.
            let as_index = writer.insert_cast_to_index(src)?;
            let dst_ty = writer.integer_type(u32::from(*int_size));
            writer.insert_arith_index_cast(as_index, dst_ty)
        }
        (false, true, _) => {
            // iN → felt: arith.index_cast to index, then cast.tofelt.
            let index_ty = writer.index_type();
            let as_index = writer.insert_arith_index_cast(src, index_ty)?;
            writer.insert_cast_to_felt(as_index)
        }
        (_, false, BitSize::Field) => unreachable!("BitSize::Field is target_is_felt=true"),
    }
}

/// Emits the LLZK op sequence for a Brillig `BinaryFieldOp`, returning the SSA
/// value bound to the destination register.
fn emit_binary_field_op<'c, 'b>(
    writer: &BlockWriter<'c, 'b>,
    op: &BinaryFieldOp,
    lhs: Value<'c, 'b>,
    rhs: Value<'c, 'b>,
    opcode_index: usize,
) -> Result<Value<'c, 'b>, Error> {
    match op {
        BinaryFieldOp::Add => writer.insert_add(lhs, rhs),
        BinaryFieldOp::Sub => writer.insert_sub(lhs, rhs),
        BinaryFieldOp::Mul => writer.insert_mul(lhs, rhs),
        BinaryFieldOp::Div => writer.insert_div(lhs, rhs),
        BinaryFieldOp::Equals => writer.insert_bool_eq(lhs, rhs),
        BinaryFieldOp::LessThan => writer.insert_bool_lt(lhs, rhs),
        BinaryFieldOp::LessThanEquals => writer.insert_bool_le(lhs, rhs),
        BinaryFieldOp::IntegerDiv => Err(Error::UnsupportedBrillig {
            reason: format!(
                "BinaryFieldOp::IntegerDiv at bytecode index {opcode_index} is not \
                 yet supported — field floor-division requires a range-checked \
                 hint-style witness solve"
            ),
        }),
    }
}

/// Emits the LLZK op for a Brillig `BinaryIntOp`, returning the SSA value
/// bound to the destination register.
///
/// The `bit_size` on the opcode is not consulted directly: the operand types
/// already carry the width (as `iN`) and the result type is inferred from
/// those operands. `arith.cmpi` always returns `i1` regardless.
fn emit_binary_int_op<'c, 'b>(
    writer: &BlockWriter<'c, 'b>,
    op: &BinaryIntOp,
    lhs: Value<'c, 'b>,
    rhs: Value<'c, 'b>,
) -> Result<Value<'c, 'b>, Error> {
    match op {
        BinaryIntOp::Add => writer.insert_arith_addi(lhs, rhs),
        BinaryIntOp::Sub => writer.insert_arith_subi(lhs, rhs),
        BinaryIntOp::Mul => writer.insert_arith_muli(lhs, rhs),
        BinaryIntOp::Div => writer.insert_arith_divui(lhs, rhs),
        BinaryIntOp::Equals => writer.insert_arith_cmpi(CmpiPredicate::Eq, lhs, rhs),
        BinaryIntOp::LessThan => writer.insert_arith_cmpi(CmpiPredicate::Ult, lhs, rhs),
        BinaryIntOp::LessThanEquals => writer.insert_arith_cmpi(CmpiPredicate::Ule, lhs, rhs),
        BinaryIntOp::And => writer.insert_arith_andi(lhs, rhs),
        BinaryIntOp::Or => writer.insert_arith_ori(lhs, rhs),
        BinaryIntOp::Xor => writer.insert_arith_xori(lhs, rhs),
        BinaryIntOp::Shl => writer.insert_arith_shli(lhs, rhs),
        BinaryIntOp::Shr => writer.insert_arith_shrui(lhs, rhs),
    }
}

fn finish<'c, 'b>(expected_output_count: usize) -> Result<Vec<Value<'c, 'b>>, Error> {
    // Output marshalling (reading registers / heap into the return tuple)
    // arrives in Issue 7. Until then, only zero-output brillig functions are
    // supported end-to-end.
    if expected_output_count != 0 {
        return Err(Error::UnsupportedBrillig {
            reason: format!(
                "brillig function declares {expected_output_count} output(s); \
                 output marshalling is implemented in a later milestone-3 issue"
            ),
        });
    }
    Ok(Vec::new())
}

/// Treats any type whose textual form starts with `!felt.` as a felt type.
///
/// `FeltType` instances created in different places may not be pointer-equal,
/// so the textual form is the safest common-denominator check.
fn is_felt_type(ty: Type<'_>) -> bool {
    format!("{ty}").starts_with("!felt.")
}

/// Returns the bit width of an integer-typed `ty`, or `None` if `ty` is not
/// an integer type.
fn integer_width(ty: Type<'_>) -> Option<u32> {
    use llzk::prelude::IntegerType;
    IntegerType::try_from(ty).ok().map(|it| it.width())
}

fn brillig_op_name<F>(op: &BrilligOpcode<F>) -> &'static str {
    match op {
        BrilligOpcode::BinaryFieldOp { .. } => "BinaryFieldOp",
        BrilligOpcode::BinaryIntOp { .. } => "BinaryIntOp",
        BrilligOpcode::Not { .. } => "Not",
        BrilligOpcode::Cast { .. } => "Cast",
        BrilligOpcode::JumpIf { .. } => "JumpIf",
        BrilligOpcode::Jump { .. } => "Jump",
        BrilligOpcode::CalldataCopy { .. } => "CalldataCopy",
        BrilligOpcode::Call { .. } => "Call",
        BrilligOpcode::Const { .. } => "Const",
        BrilligOpcode::IndirectConst { .. } => "IndirectConst",
        BrilligOpcode::Return => "Return",
        BrilligOpcode::ForeignCall { .. } => "ForeignCall",
        BrilligOpcode::Mov { .. } => "Mov",
        BrilligOpcode::ConditionalMov { .. } => "ConditionalMov",
        BrilligOpcode::Load { .. } => "Load",
        BrilligOpcode::Store { .. } => "Store",
        BrilligOpcode::BlackBox(_) => "BlackBox",
        BrilligOpcode::Trap { .. } => "Trap",
        BrilligOpcode::Stop { .. } => "Stop",
    }
}
