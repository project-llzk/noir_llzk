//! Per-opcode handlers for the Brillig bytecode translator.
//!
//! Each `BrilligOpcode` variant has its own module under this folder, holding
//! a handler struct that captures the variant's fields and implements
//! [`BrilligHandler`]. The dispatch function [`build_handler`] boxes the
//! right handler for an opcode, mirroring the `build_handler` →
//! `Box<dyn OpcodeEmitter>` pattern used for ACIR opcodes.

use acir::FieldElement;
use acir::brillig::Opcode as B;

use crate::error::Error;

use super::translator::{OpcodeAction, TranslationCtx};

mod binary_field_op;
mod binary_int_op;
mod calldata_copy;
mod cast;
mod conditional_mov;
mod const_op;
mod indirect_const;
mod load;
mod mov;
mod not;
mod stop;
mod store;

use self::binary_field_op::BinaryFieldOpHandler;
use self::binary_int_op::BinaryIntOpHandler;
use self::calldata_copy::CalldataCopyHandler;
use self::cast::CastHandler;
use self::conditional_mov::ConditionalMovHandler;
use self::const_op::ConstHandler;
use self::indirect_const::IndirectConstHandler;
use self::load::LoadHandler;
use self::mov::MovHandler;
use self::not::NotHandler;
use self::stop::StopHandler;
use self::store::StoreHandler;

/// Trait that each Brillig opcode handler implements.
///
/// Handlers receive the shared [`TranslationCtx`] which provides helper
/// methods for common operations (constant emission, type casts, etc.).
pub(super) trait BrilligHandler<'a> {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error>;
}

/// Boxed trait object so the translate loop stays uniform.
pub(super) type TranslatedBrilligOp<'a> = Box<dyn BrilligHandler<'a> + 'a>;

/// Converts a single `BrilligOpcode` into a boxed handler.
pub(super) fn build_handler<'a>(
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
            bit_size: _,
            value,
        } => Ok(Box::new(IndirectConstHandler {
            destination_pointer: *destination_pointer,
            value,
        })),

        B::Stop { return_data } => Ok(Box::new(StopHandler { return_data })),

        B::ConditionalMov {
            destination,
            source_a,
            source_b,
            condition,
        } => Ok(Box::new(ConditionalMovHandler {
            destination: *destination,
            source_a: *source_a,
            source_b: *source_b,
            condition: *condition,
        })),

        other => Err(Error::UnsupportedBrillig {
            reason: format!(
                "Brillig opcode `{other:?}` at bytecode index {index} is not supported yet"
            ),
        }),
    }
}
