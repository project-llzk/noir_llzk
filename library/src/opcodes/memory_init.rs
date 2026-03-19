use std::collections::BTreeSet;

use acir::native_types::Witness;
use llzk::dialect::array::ArrayType;
use llzk::prelude::{BlockLike, StructDefOpLike};
use llzk::prelude::{FeltType, LlzkContext, Location, StructDefOp, Type, dialect};

use crate::{FIELD_NAME, block_writer::BlockWriter, error::Error, opcodes::OpcodeEmitter};

/// Translates an ACIR `MemoryInit` opcode.
///
/// Each memory block becomes an `!array.type<!felt.type, N>` struct member named
/// `@mem{block_id}`. In both `@compute` and `@constrain`, the array is allocated
/// with `array.new`, each initial witness value is written via `array.write`, and
/// the completed array is stored via `struct.writem`.
///
/// The `@constrain` phase must rebuild the array so that subsequent `MemoryOp`
/// constrain calls can read and replay the memory trace against the correct
/// initial state.
pub(crate) struct MemoryInit<'p> {
    pub(crate) block_id: u32,
    pub(crate) init: &'p [Witness],
}

impl<'p> OpcodeEmitter for MemoryInit<'p> {
    fn get_witnesses(&self) -> BTreeSet<u32> {
        self.init.iter().map(|w| w.0).collect()
    }

    /// Emits `struct.member @mem{block_id} : !array.type<!felt.type, N>`.
    fn emit_member<'c>(
        &self,
        context: &'c LlzkContext,
        struct_def: &StructDefOp<'c>,
    ) -> Result<(), Error> {
        let location = Location::unknown(context);
        let felt_type: Type<'c> = FeltType::with_field(context, FIELD_NAME).into();
        let array_type = ArrayType::new_with_dims(felt_type, &[self.init.len() as i64]);
        let member = dialect::r#struct::member(
            location,
            &format!("mem{}", self.block_id),
            array_type,
            false,
            false,
        )?;
        struct_def.body().append_operation(member.into());
        Ok(())
    }

    /// In `@compute`:
    /// 1. Allocates an uninitialized `array.new` of the correct type.
    /// 2. Writes each initial witness value at its slot index via `array.write`.
    /// 3. Persists the populated array via `struct.writem @mem{block_id}`.
    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        // Create an uninitialized array of the required type.
        let arr = writer.insert_new_array(self.init.len())?;

        // Write each initial witness value into the array at its constant index.
        for (i, witness) in self.init.iter().enumerate() {
            let val = writer.read_witness(witness.0)?;
            let idx = writer.insert_index(i)?;
            writer.insert_array_write(arr, &[idx], val);
        }

        // Store the completed array to the struct member.
        writer.write_member(&format!("mem{}", self.block_id), arr)?;
        Ok(())
    }
}
