pub(crate) mod assert_zero;
pub(crate) mod call;

use std::collections::BTreeSet;

use llzk::prelude::{LlzkContext, StructDefOp};

use crate::{block_writer::BlockWriter, error::Error};

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
    /// Returns all witness indices referenced by this opcode.
    fn get_witnesses(&self) -> BTreeSet<u32>;

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
    fn emit_compute<'c, 'b>(&self, _writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        Ok(())
    }

    /// Emits constraint assertions into the `@constrain` function body.
    ///
    /// Default: no-op. Brillig opcodes do not emit constraints.
    fn emit_constrain<'c, 'b>(&self, _writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        Ok(())
    }
}

/// Trait object so the three emission loops in `circuit.rs` stay uniform without matching on an enum.
pub(crate) type TranslatedOpcode<'a> = Box<dyn OpcodeEmitter + 'a>;
