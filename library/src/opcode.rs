use acir::{FieldElement, circuit::Opcode, native_types::Expression};
use llzk::prelude::{LlzkContext, StructDefOp};

use crate::{
    common::opcode_name,
    compute::ComputeWriter,
    constrain::ConstraintWriter,
    error::Error,
};

/// An ACIR opcode translated into our internal representation.
///
/// All circuit-level metadata (struct member names, target circuit names for
/// `Call`) is pre-computed during [`CircuitTranslator::build_handlers`] so
/// that each emission phase can be a simple, stateless iteration.
pub(crate) enum TranslatedOpcode<'a> {
    AssertZero {
        expr: &'a Expression<FieldElement>,
        /// Position in the opcode list; used for error reporting.
        index: usize,
    },
}

impl<'a> TranslatedOpcode<'a> {
    /// Converts an ACIR opcode into its translated form, pre-computing any
    /// circuit-level metadata (e.g. target struct name for `Call`).
    ///
    /// Returns [`Error::UnsupportedOpcode`] for opcodes not yet implemented.
    pub(crate) fn from_acir(opcode: &'a Opcode<FieldElement>, index: usize) -> Result<Self, Error> {
        match opcode {
            Opcode::AssertZero(expr) => Ok(Self::AssertZero { expr, index }),
            other => Err(Error::UnsupportedOpcode(opcode_name(other))),
        }
    }

    /// Emits any `struct.member` declarations required by this opcode.
    ///
    /// `AssertZero` is a no-op here. `Call` (future) will add a subcomponent
    /// member of type `!struct.type<@CircuitN>`.
    pub(crate) fn emit_member<'c>(
        &self,
        _context: &'c LlzkContext,
        _struct_def: &StructDefOp<'c>,
    ) -> Result<(), Error> {
        match self {
            Self::AssertZero { .. } => Ok(()),
        }
    }

    /// Emits witness-solving operations into the `@compute` function body.
    pub(crate) fn emit_compute<'c, 'b>(
        &self,
        writer: &mut ComputeWriter<'c, 'b>,
    ) -> Result<(), Error> {
        match self {
            Self::AssertZero { expr, index } => writer.emit_assert_zero(expr, *index),
        }
    }

    /// Emits constraint assertions into the `@constrain` function body.
    pub(crate) fn emit_constrain<'c, 'b>(
        &self,
        writer: &mut ConstraintWriter<'c, 'b>,
    ) -> Result<(), Error> {
        match self {
            Self::AssertZero { expr, .. } => Ok(writer.emit_assert_zero(expr)?),
        }
    }
}
