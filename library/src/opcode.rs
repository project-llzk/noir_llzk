use acir::{FieldElement, circuit::Opcode};
use llzk::prelude::{LlzkContext, StructDefOp};

use crate::{compute::ComputeWriter, constrain::ConstraintWriter, error::Error};

use crate::opcodes::assert_zero::AssertZero;

/// Trait implemented by each ACIR opcode's translator.
///
/// Default no-op implementations are provided for phases that not all opcodes
/// participate in:
/// - [`emit_member`]: only `Call` adds a subcomponent struct member.
/// - [`emit_constrain`]: Brillig opcodes are unconstrained.
///
/// To add a new opcode: create a struct, implement this trait (only the
/// relevant methods), and add a match arm to the [`TryFrom`] impl below.
pub(crate) trait OpcodeEmitter {
    /// Emits any `struct.member` declaration required by this opcode.
    ///
    /// Default: no-op. Only `Call` needs to override this.
    fn emit_member<'c>(
        &self,
        _context: &'c LlzkContext,
        _struct_def: &StructDefOp<'c>,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Emits witness-solving operations into the `@compute` function body.
    ///
    /// Default: no-op.
    fn emit_compute<'c, 'b>(&self, _writer: &mut ComputeWriter<'c, 'b>) -> Result<(), Error> {
        Ok(())
    }

    /// Emits constraint assertions into the `@constrain` function body.
    ///
    /// Default: no-op. Brillig opcodes do not emit constraints.
    fn emit_constrain<'c, 'b>(&self, _writer: &mut ConstraintWriter<'c, 'b>) -> Result<(), Error> {
        Ok(())
    }
}

/// Trait object so the three emission loops in `circuit.rs` stay uniform without matching on an enum.
pub(crate) type TranslatedOpcode<'a> = Box<dyn OpcodeEmitter + 'a>;

/// Converts `(index, opcode)` into a [`TranslatedOpcode`].
///
/// `index` is the opcode's position in the circuit's opcode list and is used
/// for error reporting. Returns [`Error::UnsupportedOpcode`] for opcodes not
/// yet implemented.
impl<'a> TryFrom<(usize, &'a Opcode<FieldElement>)> for TranslatedOpcode<'a> {
    type Error = Error;

    fn try_from((index, opcode): (usize, &'a Opcode<FieldElement>)) -> Result<Self, Error> {
        match opcode {
            Opcode::AssertZero(expr) => Ok(Box::new(AssertZero { expr, index })),
            other => Err(Error::UnsupportedOpcode(other.to_string())),
        }
    }
}
