use std::collections::HashSet;

use llzk::prelude::{
    BlockLike, LlzkContext, OperationLike, RegionLike, StructDefOp, StructDefOpLike, Value,
};

use crate::block_writer::BlockWriter;
use crate::error::Error;

/// LLZK-side compute writer that manages witness solving and emits
/// operations into the `@compute` function body.
pub(crate) struct ComputeWriter<'c, 'a> {
    pub(crate) inner: BlockWriter<'c, 'a>,
    /// Set of witness indices that are currently known (solved or input).
    known: HashSet<u32>,
}

impl<'c, 'a> ComputeWriter<'c, 'a> {
    /// Creates a new writer targeting the `@compute` function of the given struct.
    pub(crate) fn new(
        context: &'c LlzkContext,
        struct_def: &StructDefOp<'c>,
        input_witnesses: &[u32],
    ) -> Result<ComputeWriter<'c, 'a>, Error> {
        let compute = struct_def
            .get_compute_func()
            .expect("Struct should have @compute");
        let block = compute.region(0)?.first_block().unwrap();

        // The first operation in compute is `struct.new`, its result is %self.
        // @compute has no %self arg — inputs start at argument 0.
        let self_value: Value = block.first_operation().unwrap().result(0)?.into();
        let known = input_witnesses.iter().copied().collect();

        Ok(ComputeWriter {
            inner: BlockWriter::from_block(context, block, self_value, input_witnesses, 0)?,
            known,
        })
    }

    /// Returns a reference to the LLZK context.
    pub(crate) fn context(&self) -> &'c LlzkContext {
        self.inner.context
    }

    /// Returns whether the given witness index has been solved.
    pub(crate) fn is_known(&self, w_idx: u32) -> bool {
        self.known.contains(&w_idx)
    }

    /// Records a solved witness value, updating both the known set and the cache.
    pub(crate) fn mark_known(&mut self, w_idx: u32, val: Value<'c, 'a>) {
        self.known.insert(w_idx);
        self.inner.witness_cache.insert(w_idx, val);
    }
}
