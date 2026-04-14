//! Brillig bytecode → LLZK body translator.
//!

use acir::brillig::{BitSize, Opcode as BrilligOpcode};
use acir::circuit::brillig::BrilligBytecode;
use acir::{AcirField, FieldElement};
use llzk::prelude::melior_dialects::arith;
use llzk::prelude::{
    Block, BlockLike, FeltType, IntegerAttribute, LlzkContext, Location, Type, Value, ValueLike,
    dialect,
};

use crate::FIELD_NAME;
use crate::common::field_to_felt_const;
use crate::error::Error;

use super::regmap::RegMap;

/// Translates `bytecode` into the body of a Brillig sibling function.
///
/// Ops are appended to `block` in order; on `Stop` (or end-of-bytecode) the
/// translator returns the SSA values the caller should pass to
/// `function.return`. The caller is responsible for appending the terminator.
///
/// Input registers are **not yet populated** — Issue 6 wires `CalldataCopy`
/// up to this layer. For Issue 3 the only reachable registers are those
/// written by `Const` / `Mov` / `Cast` opcodes.
pub(crate) fn translate_bytecode<'c, 'b>(
    context: &'c LlzkContext,
    block: &'b Block<'c>,
    bytecode: &BrilligBytecode<FieldElement>,
    expected_output_count: usize,
) -> Result<Vec<Value<'c, 'b>>, Error> {
    let location = Location::unknown(context);
    let index_type = Type::index(context);
    let mut regmap: RegMap<'c, 'b> = RegMap::new();

    for (i, op) in bytecode.bytecode.iter().enumerate() {
        match op {
            BrilligOpcode::Const {
                destination,
                bit_size,
                value,
            } => {
                let ssa = emit_const(context, block, location, index_type, bit_size, value)?;
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
                let dest_is_felt = matches!(bit_size, BitSize::Field);
                let src_is_felt = is_felt_type(src.r#type());
                let casted = if dest_is_felt == src_is_felt {
                    // Same type family (field ↔ field or integer ↔ integer):
                    // treat as a Mov regardless of integer bit-width differences.
                    src
                } else if dest_is_felt {
                    let op = dialect::cast::tofelt(
                        location,
                        src,
                        Some(FeltType::with_field(context, FIELD_NAME)),
                    );
                    block.append_operation(op).result(0)?.into()
                } else {
                    let op = dialect::cast::toindex(location, src);
                    block.append_operation(op).result(0)?.into()
                };
                regmap.set(*destination, casted);
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
/// register map. Field constants become `felt.constant`; integer constants
/// become `arith.constant` with `index` type.
fn emit_const<'c, 'b>(
    context: &'c LlzkContext,
    block: &'b Block<'c>,
    location: Location<'c>,
    index_type: Type<'c>,
    bit_size: &BitSize,
    value: &FieldElement,
) -> Result<Value<'c, 'b>, Error> {
    let op = match bit_size {
        BitSize::Field => dialect::felt::constant(location, field_to_felt_const(context, value))?,
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
            let attr = IntegerAttribute::new(index_type, as_u128 as i64).into();
            arith::constant(context, attr, location)
        }
    };
    Ok(block.append_operation(op).result(0)?.into())
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
