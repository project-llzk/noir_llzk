use std::collections::HashSet;

use llzk::prelude::{
    BlockLike, LlzkContext, LlzkError, OperationLike, RegionLike, StructDefOp, StructDefOpLike,
    Value,
};

use crate::block_writer::BlockWriter;

/// LLZK-side compute writer that manages witness solving and emits
/// operations into the `@compute` function body.
///
/// Input witnesses are written to the struct from function parameters.
/// Intermediate witnesses are solved from `AssertZero` expressions and
/// written to the struct as they are computed.
pub(crate) struct ComputeWriter<'c, 'a> {
    pub(crate) inner: BlockWriter<'c, 'a>,
    /// Set of witness indices that are currently known (solved or input).
    pub(crate) known: HashSet<u32>,
}

impl<'c, 'a> ComputeWriter<'c, 'a> {
    /// Creates a new writer targeting the `@compute` function of the given struct.
    ///
    /// Writes all input parameters (private then public) to the struct as initial
    /// known witnesses.
    pub(crate) fn new(
        context: &'c LlzkContext,
        struct_def: &StructDefOp<'c>,
        input_witnesses: &[u32],
    ) -> Result<ComputeWriter<'c, 'a>, LlzkError> {
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
}
