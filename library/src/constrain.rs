use llzk::prelude::{
    BlockLike, LlzkContext, LlzkError, OperationLike, RegionLike, StructDefOp, StructDefOpLike,
    Value,
};

use crate::block_writer::BlockWriter;

/// LLZK-side constraint writer that manages witness reads and emits
/// constraint operations into the `@constrain` function body.
///
/// Witnesses are read lazily from `%self` via `struct.readm` on first use
/// and cached for reuse across opcodes.
pub(crate) struct ConstraintWriter<'c, 'a> {
    pub(crate) inner: BlockWriter<'c, 'a>,
}

impl<'c, 'a> ConstraintWriter<'c, 'a> {
    /// Creates a new writer targeting the `@constrain` function of the given struct.
    ///
    /// Seeds `witness_cache` from block arguments so that input witnesses are
    /// resolved from parameters rather than emitting `struct.readm`.
    pub(crate) fn new(
        context: &'c LlzkContext,
        struct_def: &StructDefOp<'c>,
        input_witnesses: &[u32],
    ) -> Result<ConstraintWriter<'c, 'a>, LlzkError> {
        let constrain = struct_def
            .get_constrain_func()
            .expect("Struct should have @constrain");
        let block = constrain.region(0)?.first_block().unwrap();

        // @constrain argument 0 is %self — inputs start at argument 1.
        let self_value: Value = block.argument(0)?.into();

        Ok(ConstraintWriter {
            inner: BlockWriter::from_block(context, block, self_value, input_witnesses, 1)?,
        })
    }
}
