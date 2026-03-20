pub(crate) mod assert_zero;
pub(crate) mod bitwise;
pub(crate) mod call;
pub(crate) mod memory_init;
pub(crate) mod memory_op;

use std::collections::{BTreeSet, HashMap};

use acir::{FieldElement, circuit::Program};
use llzk::prelude::{LlzkContext, StructDefOp};

use crate::{block_writer::BlockWriter, error::Error};

/// Shared mutable state accumulated while converting ACIR opcodes into
/// [`TranslatedOpcode`]s.  Threaded through each opcode's `from_opcode`
/// constructor so that cross-opcode bookkeeping (block sizes, read/write
/// counters) stays out of the top-level dispatcher.
pub(crate) struct BuildContext<'p> {
    /// Full program — needed by `Call` to resolve callee circuits by index.
    pub(crate) program: &'p Program<FieldElement>,
    /// Maps `block_id` → array length, populated by `MemoryInit` and read by
    /// `MemoryOp`.
    pub(crate) block_sizes: HashMap<u32, usize>,
    /// Running counter of `MemoryRead` subcomponents (for unique member names).
    pub(crate) read_count: usize,
    /// Running counter of `MemoryWrite` subcomponents (for unique member names).
    pub(crate) write_count: usize,
    /// Distinct array sizes that need a `MemRead_{N}` struct def.
    pub(crate) read_sizes: BTreeSet<usize>,
    /// Distinct array sizes that need a `MemWrite_{N}` struct def.
    pub(crate) write_sizes: BTreeSet<usize>,
}

impl<'p> BuildContext<'p> {
    pub(crate) fn new(program: &'p Program<FieldElement>) -> Self {
        Self {
            program,
            block_sizes: HashMap::new(),
            read_count: 0,
            write_count: 0,
            read_sizes: BTreeSet::new(),
            write_sizes: BTreeSet::new(),
        }
    }
}

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
