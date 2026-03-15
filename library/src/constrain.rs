use llzk::prelude::{
    BlockLike, LlzkContext, LlzkError, Location, OperationLike, RegionLike, StructDefOp,
    StructDefOpLike, Value,
};

use crate::common::BlockWriter;

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
        let location = Location::unknown(context);

        let constrain = struct_def
            .get_constrain_func()
            .expect("Struct should have @constrain");
        let block = constrain.region(0)?.first_block().unwrap();
        let ret_op = block.terminator().unwrap();
        let self_value: Value = block.argument(0)?.into();

        let mut witness_cache = std::collections::HashMap::new();

        // Seed cache from input parameters (argument 0 is %self, inputs start at 1).
        for (arg_idx, &w_idx) in input_witnesses.iter().enumerate() {
            // Block argument 0 is %self, so inputs start at index 1.
            let arg_val: Value = block.argument(arg_idx + 1)?.into();
            witness_cache.insert(w_idx, arg_val);
        }

        Ok(ConstraintWriter {
            inner: BlockWriter {
                context,
                block,
                ret_op,
                location,
                self_value,
                witness_cache,
            },
        })
    }
}
