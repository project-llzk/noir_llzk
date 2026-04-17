//! Per-opcode handlers for the Brillig bytecode translator.
//!
//! Each handler struct captures the fields of a single `BrilligOpcode` variant
//! and implements [`BrilligHandler`] to translate it into LLZK IR via the
//! shared [`TranslationCtx`].

use crate::error::Error;
use acir::brillig::Opcode as B;
use acir::brillig::{BinaryFieldOp, BinaryIntOp, BitSize, IntegerBitSize, MemoryAddress};
use acir::{AcirField, FieldElement};

use super::translator::{OpcodeAction, TranslationCtx};

/// Trait that each Brillig opcode handler implements.
///
/// Handlers receive the shared [`TranslationCtx`] which provides helper
/// methods for common operations (constant emission, type casts, etc.).
pub(crate) trait BrilligHandler<'a> {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error>;
}

/// Boxed trait object so the translate loop stays uniform.
pub(crate) type TranslatedBrilligOp<'a> = Box<dyn BrilligHandler<'a> + 'a>;

// ── Const ──────────────────────────────────────────────────────────────

pub(crate) struct ConstHandler<'a> {
    pub destination: MemoryAddress,
    pub bit_size: &'a BitSize,
    pub value: &'a FieldElement,
}

impl<'a> BrilligHandler<'a> for ConstHandler<'a> {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        _opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        if let BitSize::Integer(_) = self.bit_size
            && let Some(v) = self.value.try_into_u128()
        {
            ctx.known_constants.insert(self.destination, v as usize);
        }
        let ssa = ctx.emit_const(self.bit_size, self.value)?;
        ctx.regmap.set(self.destination, ssa);
        Ok(OpcodeAction::Continue)
    }
}

// ── IndirectConst ──────────────────────────────────────────────────────

pub(crate) struct IndirectConstHandler<'a> {
    pub destination_pointer: MemoryAddress,
    pub bit_size: &'a BitSize,
    pub value: &'a FieldElement,
}

impl<'a> BrilligHandler<'a> for IndirectConstHandler<'a> {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let ptr = ctx.regmap.get(self.destination_pointer, opcode_index)?;
        let ptr_idx = ctx.cast_to_index(ptr)?;
        let ssa = ctx.emit_const(self.bit_size, self.value)?;
        ctx.writer.insert_ram_store(ptr_idx, ssa);
        Ok(OpcodeAction::Continue)
    }
}

// ── Mov ────────────────────────────────────────────────────────────────

pub(crate) struct MovHandler {
    pub destination: MemoryAddress,
    pub source: MemoryAddress,
}

impl BrilligHandler<'_> for MovHandler {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let src = ctx.regmap.get(self.source, opcode_index)?;
        ctx.regmap.set(self.destination, src);
        Ok(OpcodeAction::Continue)
    }
}

// ── Cast ───────────────────────────────────────────────────────────────

pub(crate) struct CastHandler<'a> {
    pub destination: MemoryAddress,
    pub source: MemoryAddress,
    pub bit_size: &'a BitSize,
}

impl<'a> BrilligHandler<'a> for CastHandler<'a> {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let src = ctx.regmap.get(self.source, opcode_index)?;
        let casted = ctx.emit_cast(src, self.bit_size)?;
        ctx.regmap.set(self.destination, casted);
        Ok(OpcodeAction::Continue)
    }
}

// ── BinaryFieldOp ──────────────────────────────────────────────────────

pub(crate) struct BinaryFieldOpHandler<'a> {
    pub destination: MemoryAddress,
    pub op: &'a BinaryFieldOp,
    pub lhs: MemoryAddress,
    pub rhs: MemoryAddress,
}

impl<'a> BrilligHandler<'a> for BinaryFieldOpHandler<'a> {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let lhs_v = ctx.regmap.get(self.lhs, opcode_index)?;
        let rhs_v = ctx.regmap.get(self.rhs, opcode_index)?;
        let result = ctx.emit_binary_field_op(self.op, lhs_v, rhs_v)?;
        ctx.regmap.set(self.destination, result);
        Ok(OpcodeAction::Continue)
    }
}

// ── BinaryIntOp ────────────────────────────────────────────────────────

pub(crate) struct BinaryIntOpHandler<'a> {
    pub destination: MemoryAddress,
    pub op: &'a BinaryIntOp,
    pub bit_size: IntegerBitSize,
    pub lhs: MemoryAddress,
    pub rhs: MemoryAddress,
}

impl<'a> BrilligHandler<'a> for BinaryIntOpHandler<'a> {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let lhs_v = ctx.regmap.get(self.lhs, opcode_index)?;
        let rhs_v = ctx.regmap.get(self.rhs, opcode_index)?;
        let expected_bits = u32::from(self.bit_size);
        ctx.check_int_width(lhs_v, expected_bits, opcode_index)?;
        ctx.check_int_width(rhs_v, expected_bits, opcode_index)?;
        let result = ctx.emit_binary_int_op(self.op, lhs_v, rhs_v)?;
        ctx.regmap.set(self.destination, result);
        Ok(OpcodeAction::Continue)
    }
}

// ── Not ────────────────────────────────────────────────────────────────

pub(crate) struct NotHandler {
    pub destination: MemoryAddress,
    pub source: MemoryAddress,
    pub bit_size: IntegerBitSize,
}

impl BrilligHandler<'_> for NotHandler {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let src = ctx.regmap.get(self.source, opcode_index)?;
        let num_bits = u32::from(self.bit_size);
        let mask = if num_bits >= 128 {
            u128::MAX
        } else {
            (1u128 << num_bits) - 1
        };
        let all_ones = ctx.writer.insert_arith_int_constant(num_bits, mask)?;
        let result = ctx.writer.insert_arith_xori(src, all_ones)?;
        ctx.regmap.set(self.destination, result);
        Ok(OpcodeAction::Continue)
    }
}

// ── Load ───────────────────────────────────────────────────────────────

pub(crate) struct LoadHandler {
    pub destination: MemoryAddress,
    pub source_pointer: MemoryAddress,
}

impl BrilligHandler<'_> for LoadHandler {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let ptr = ctx.regmap.get(self.source_pointer, opcode_index)?;
        let ptr_idx = ctx.cast_to_index(ptr)?;
        let felt_ty = ctx.writer.felt_type();
        let val = ctx.writer.insert_ram_load(ptr_idx, felt_ty)?;
        ctx.regmap.set(self.destination, val);
        Ok(OpcodeAction::Continue)
    }
}

// ── Store ──────────────────────────────────────────────────────────────

pub(crate) struct StoreHandler {
    pub destination_pointer: MemoryAddress,
    pub source: MemoryAddress,
}

impl BrilligHandler<'_> for StoreHandler {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let ptr = ctx.regmap.get(self.destination_pointer, opcode_index)?;
        let ptr_idx = ctx.cast_to_index(ptr)?;
        let val = ctx.regmap.get(self.source, opcode_index)?;
        ctx.writer.insert_ram_store(ptr_idx, val);
        Ok(OpcodeAction::Continue)
    }
}

// ── CalldataCopy ───────────────────────────────────────────────────────

pub(crate) struct CalldataCopyHandler {
    pub destination_address: MemoryAddress,
    pub size_address: MemoryAddress,
    pub offset_address: MemoryAddress,
}

impl BrilligHandler<'_> for CalldataCopyHandler {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        i: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let size = *ctx.known_constants.get(&self.size_address).ok_or_else(|| {
            Error::UnsupportedBrillig {
                reason: format!(
                    "CalldataCopy at bytecode index {i}: size register {} \
                     is not a known integer constant",
                    self.size_address.to_u32()
                ),
            }
        })?;
        let offset = *ctx
            .known_constants
            .get(&self.offset_address)
            .ok_or_else(|| Error::UnsupportedBrillig {
                reason: format!(
                    "CalldataCopy at bytecode index {i}: offset register {} \
                         is not a known integer constant",
                    self.offset_address.to_u32()
                ),
            })?;
        if offset + size > ctx.calldata.len() {
            return Err(Error::UnsupportedBrillig {
                reason: format!(
                    "CalldataCopy at bytecode index {i}: calldata range \
                     [{offset}..{}] exceeds calldata length {}",
                    offset + size,
                    ctx.calldata.len()
                ),
            });
        }
        let dst_base = self.destination_address.to_u32();
        for j in 0..size {
            let addr = MemoryAddress::Direct(dst_base + j as u32);
            let val = ctx.calldata[offset + j];
            ctx.regmap.set(addr, val);
            let idx = ctx.writer.insert_integer(dst_base as usize + j)?;
            ctx.writer.insert_ram_store(idx, val);
        }
        Ok(OpcodeAction::Continue)
    }
}

// ── Stop ───────────────────────────────────────────────────────────────

pub(crate) struct StopHandler<'a> {
    pub return_data: &'a acir::brillig::HeapVector,
}

impl<'a> BrilligHandler<'a> for StopHandler<'a> {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let returns = ctx.emit_return_data(self.return_data, opcode_index)?;
        Ok(OpcodeAction::Return(returns))
    }
}

// ── Dispatch ───────────────────────────────────────────────────────────

/// Converts a single `BrilligOpcode` into a boxed handler, mirroring the
/// `build_handler` → `Box<dyn OpcodeEmitter>` pattern used for ACIR opcodes.
pub(crate) fn build_handler<'a>(
    index: usize,
    op: &'a acir::brillig::Opcode<FieldElement>,
) -> Result<TranslatedBrilligOp<'a>, Error> {
    match op {
        B::Const {
            destination,
            bit_size,
            value,
        } => Ok(Box::new(ConstHandler {
            destination: *destination,
            bit_size,
            value,
        })),

        B::Mov {
            destination,
            source,
        } => Ok(Box::new(MovHandler {
            destination: *destination,
            source: *source,
        })),

        B::Cast {
            destination,
            source,
            bit_size,
        } => Ok(Box::new(CastHandler {
            destination: *destination,
            source: *source,
            bit_size,
        })),

        B::BinaryFieldOp {
            destination,
            op,
            lhs,
            rhs,
        } => Ok(Box::new(BinaryFieldOpHandler {
            destination: *destination,
            op,
            lhs: *lhs,
            rhs: *rhs,
        })),

        B::BinaryIntOp {
            destination,
            op,
            bit_size,
            lhs,
            rhs,
        } => Ok(Box::new(BinaryIntOpHandler {
            destination: *destination,
            op,
            bit_size: *bit_size,
            lhs: *lhs,
            rhs: *rhs,
        })),

        B::Load {
            destination,
            source_pointer,
        } => Ok(Box::new(LoadHandler {
            destination: *destination,
            source_pointer: *source_pointer,
        })),

        B::Store {
            destination_pointer,
            source,
        } => Ok(Box::new(StoreHandler {
            destination_pointer: *destination_pointer,
            source: *source,
        })),

        B::CalldataCopy {
            destination_address,
            size_address,
            offset_address,
        } => Ok(Box::new(CalldataCopyHandler {
            destination_address: *destination_address,
            size_address: *size_address,
            offset_address: *offset_address,
        })),

        B::Not {
            destination,
            source,
            bit_size,
        } => Ok(Box::new(NotHandler {
            destination: *destination,
            source: *source,
            bit_size: *bit_size,
        })),

        B::IndirectConst {
            destination_pointer,
            bit_size,
            value,
        } => Ok(Box::new(IndirectConstHandler {
            destination_pointer: *destination_pointer,
            bit_size,
            value,
        })),

        B::Stop { return_data } => Ok(Box::new(StopHandler { return_data })),

        B::ConditionalMov { .. } => Err(Error::UnsupportedBrillig {
            reason: format!(
                "Brillig opcode `ConditionalMov` at bytecode index {index} is \
                 control flow and not supported by this milestone"
            ),
        }),

        other => Err(Error::UnsupportedBrillig {
            reason: format!(
                "Brillig opcode `{}` at bytecode index {index} is not supported yet",
                brillig_op_name(other)
            ),
        }),
    }
}

fn brillig_op_name<F>(op: &acir::brillig::Opcode<F>) -> &'static str {
    match op {
        B::BinaryFieldOp { .. } => "BinaryFieldOp",
        B::BinaryIntOp { .. } => "BinaryIntOp",
        B::Not { .. } => "Not",
        B::Cast { .. } => "Cast",
        B::JumpIf { .. } => "JumpIf",
        B::Jump { .. } => "Jump",
        B::CalldataCopy { .. } => "CalldataCopy",
        B::Call { .. } => "Call",
        B::Const { .. } => "Const",
        B::IndirectConst { .. } => "IndirectConst",
        B::Return => "Return",
        B::ForeignCall { .. } => "ForeignCall",
        B::Mov { .. } => "Mov",
        B::ConditionalMov { .. } => "ConditionalMov",
        B::Load { .. } => "Load",
        B::Store { .. } => "Store",
        B::BlackBox(_) => "BlackBox",
        B::Trap { .. } => "Trap",
        B::Stop { .. } => "Stop",
    }
}
