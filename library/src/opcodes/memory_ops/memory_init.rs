use std::collections::BTreeSet;

use acir::native_types::Witness;
use llzk::dialect::array::ArrayType;
use llzk::prelude::{BlockLike, StructDefOpLike};
use llzk::prelude::{FeltType, LlzkContext, Location, StructDefOp, Type, Value, dialect};

use crate::{FIELD_NAME, block_writer::BlockWriter, error::Error, opcodes::OpcodeEmitter};

/// Translates an ACIR `MemoryInit` opcode.
///
/// Emits `@mem{block_id} : !array.type<!felt.type, N>` as a struct member.
///
/// In `@compute` the array is built from witnesses and stored to the struct member.
/// In `@constrain` the array is rebuilt fresh from witnesses so that subsequent
/// memory operations can reference it.
pub(crate) struct MemoryInit<'p> {
    pub(crate) block_id: u32,
    pub(crate) init: &'p [Witness],
}

impl<'p> MemoryInit<'p> {
    /// Allocates a new array and populates it from the initial witness values,
    /// then registers it as the current live array in `mem_versions`.
    fn init_memory<'c, 'b>(
        &self,
        writer: &mut BlockWriter<'c, 'b>,
    ) -> Result<Value<'c, 'b>, Error> {
        let arr = writer.insert_new_array(self.init.len())?;
        for (i, witness) in self.init.iter().enumerate() {
            let val = writer.read_witness(witness.0)?;
            let idx = writer.insert_integer(i)?;
            writer.insert_array_write(arr, &[idx], val);
        }
        writer.set_memory(self.block_id, arr);
        Ok(arr)
    }
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

    /// Builds the initial array from witnesses and stores it to the struct member.
    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let arr = self.init_memory(writer)?;
        writer.write_member(&format!("mem{}", self.block_id), arr)?;
        Ok(())
    }

    /// Rebuilds the initial array from witnesses for subsequent memory op constraints.
    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        self.init_memory(writer)?;
        Ok(())
    }
}
