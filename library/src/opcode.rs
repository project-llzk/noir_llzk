use acir::{FieldElement, native_types::Expression};
use llzk::prelude::{LlzkContext, StructDefOp};

use crate::{
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
