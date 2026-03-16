use llzk::prelude::{
    BlockLike, LlzkContext, OperationLike, RegionLike, StructDefOp, StructDefOpLike, Value,
};

use crate::block_writer::BlockWriter;
use crate::error::Error;

/// LLZK-side constraint writer that manages witness reads and emits
/// constraint operations into the `@constrain` function body.
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
    ) -> Result<ConstraintWriter<'c, 'a>, Error> {
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
