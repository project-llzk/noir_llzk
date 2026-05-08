//! Per-opcode handlers for the Brillig bytecode translator.
//!
//! Each `BrilligOpcode` variant has its own module under this folder, holding
//! a handler struct that captures the variant's fields and implements
//! [`BrilligHandler`]. The dispatch function [`build_handler`] boxes the
//! right handler for an opcode, mirroring the `build_handler` →
//! `Box<dyn OpcodeEmitter>` pattern used for ACIR opcodes.

use acir::FieldElement;
use acir::brillig::{MemoryAddress, Opcode as B};
use llzk::prelude::Value;

use crate::error::Error;

use super::memory::Memory;
use super::translator::TranslationCtx;

mod binary_field_op;
mod binary_int_op;
mod black_box;
mod calldata_copy;
mod cast;
mod conditional_mov;
mod const_op;
mod foreign_call;
mod indirect_const;
mod load;
mod mov;
mod not;
mod store;
#[cfg(test)]
mod tests;

use self::binary_field_op::BinaryFieldOpHandler;
use self::binary_int_op::BinaryIntOpHandler;
use self::black_box::BlackBoxOpHandler;
use self::calldata_copy::CalldataCopyHandler;
use self::cast::CastHandler;
use self::conditional_mov::ConditionalMovHandler;
use self::const_op::ConstHandler;
use self::foreign_call::ForeignCallHandler;
use self::indirect_const::IndirectConstHandler;
use self::load::LoadHandler;
use self::mov::MovHandler;
use self::not::NotHandler;
use self::store::StoreHandler;

/// Trait that each Brillig opcode handler implements.
///
/// Handlers receive the shared [`TranslationCtx`] which provides helper
/// methods for common operations (constant emission, type casts, etc.).
pub(super) trait BrilligHandler<'a, M: Memory> {
    fn execute(
        &self,
        ctx: &mut TranslationCtx<'_, '_, '_, M>,
        opcode_index: usize,
    ) -> Result<(), Error>;
}

/// Boxed trait object so the translate loop stays uniform.
pub(super) type TranslatedBrilligOp<'a, M> = Box<dyn BrilligHandler<'a, M> + 'a>;

/// Returns the boxed handler for `op`, or `None` when `op` has no
/// per-opcode emission. `None` covers terminator opcodes (`Jump`,
/// `JumpIf`, `Call`, `Return`, `Trap`, `TrapReturn`, `Stop`) — the
/// structured emitter translates those via region nodes — plus any
/// opcode the translator doesn't yet know how to lower; the caller
/// (`translate_block_body`) skips both equivalently.
pub(super) fn build_handler<'a, M: Memory + 'a>(
    op: &'a acir::brillig::Opcode<FieldElement>,
) -> Option<TranslatedBrilligOp<'a, M>> {
    match op {
        B::Const {
            destination,
            bit_size,
            value,
        } => Some(Box::new(ConstHandler {
            destination: *destination,
            bit_size,
            value,
        })),

        B::Mov {
            destination,
            source,
        } => Some(Box::new(MovHandler {
            destination: *destination,
            source: *source,
        })),

        B::Cast {
            destination,
            source,
            bit_size,
        } => Some(Box::new(CastHandler {
            destination: *destination,
            source: *source,
            bit_size,
        })),

        B::BinaryFieldOp {
            destination,
            op,
            lhs,
            rhs,
        } => Some(Box::new(BinaryFieldOpHandler {
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
        } => Some(Box::new(BinaryIntOpHandler {
            destination: *destination,
            op,
            bit_size: *bit_size,
            lhs: *lhs,
            rhs: *rhs,
        })),

        B::Load {
            destination,
            source_pointer,
        } => Some(Box::new(LoadHandler {
            destination: *destination,
            source_pointer: *source_pointer,
        })),

        B::Store {
            destination_pointer,
            source,
        } => Some(Box::new(StoreHandler {
            destination_pointer: *destination_pointer,
            source: *source,
        })),

        B::CalldataCopy {
            destination_address,
            size_address,
            offset_address,
        } => Some(Box::new(CalldataCopyHandler {
            destination_address: *destination_address,
            size_address: *size_address,
            offset_address: *offset_address,
        })),

        B::Not {
            destination,
            source,
            bit_size,
        } => Some(Box::new(NotHandler {
            destination: *destination,
            source: *source,
            bit_size: *bit_size,
        })),

        B::IndirectConst {
            destination_pointer,
            bit_size: _,
            value,
        } => Some(Box::new(IndirectConstHandler {
            destination_pointer: *destination_pointer,
            value,
        })),

        B::ConditionalMov {
            destination,
            source_a,
            source_b,
            condition,
        } => Some(Box::new(ConditionalMovHandler {
            destination: *destination,
            source_a: *source_a,
            source_b: *source_b,
            condition: *condition,
        })),

        B::ForeignCall {
            destinations,
            destination_value_types,
            ..
        } => Some(Box::new(ForeignCallHandler {
            destinations,
            destination_value_types,
        })),

        B::BlackBox(op) => Some(Box::new(BlackBoxOpHandler { op })),

        _ => None,
    }
}

pub(super) fn require_const<M: Memory>(
    ctx: &mut TranslationCtx<'_, '_, '_, M>,
    addr: MemoryAddress,
    op_name: &str,
    field_name: &str,
) -> Result<usize, Error> {
    ctx.memory
        .get_const(addr)?
        .ok_or_else(|| Error::UnsupportedBrillig {
            reason: format!(
                "{op_name}: {field_name} register {} is expected to be a \
                 known integer constant",
                addr.to_u32()
            ),
        })
}

/// Returns `base` itself when `offset == 0`; otherwise `base +
/// arith.constant offset` as an `index`-typed value.
pub(super) fn slot_at_offset<'c, 'b, M: Memory>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
    base: Value<'c, 'b>,
    offset: usize,
) -> Result<Value<'c, 'b>, Error> {
    if offset == 0 {
        return Ok(base);
    }
    let off = ctx.writer.insert_integer(offset)?;
    ctx.writer.insert_index_add(base, off)
}

/// Reads the felt held at `addr` (a register or RAM slot tracked by
/// `ctx.memory`) and casts it to the `index`-typed SSA value used as a
/// base address for `ram.load` / `ram.store`.
pub(super) fn read_pointer_as_index<'c, 'b, M: Memory>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
    addr: MemoryAddress,
) -> Result<Value<'c, 'b>, Error> {
    let ptr_felt = ctx.memory.read(ctx.writer, addr)?;
    ctx.writer.cast_to_index(ptr_felt)
}
