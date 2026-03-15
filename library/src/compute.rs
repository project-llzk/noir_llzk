use std::collections::HashSet;

use llzk::prelude::{
    BlockLike, LlzkContext, LlzkError, Location, OperationLike, RegionLike, StructDefOp,
    StructDefOpLike, Value,
};

use crate::common::BlockWriter;

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
        let location = Location::unknown(context);

        let compute = struct_def
            .get_compute_func()
            .expect("Struct should have @compute");
        let block = compute.region(0)?.first_block().unwrap();
        let ret_op = block.terminator().unwrap();

        // The first operation in compute is `struct.new`, its result is %self.
        let first_op = block.first_operation().unwrap();
        let self_value: Value = first_op.result(0)?.into();

        let mut writer = ComputeWriter {
            inner: BlockWriter {
                context,
                block,
                ret_op,
                location,
                self_value,
                witness_cache: Default::default(),
            },
            known: HashSet::new(),
        };

        // Populate known set and witness cache from input parameters.
        // Inputs are available as function arguments — no struct.writem needed.
        for (arg_idx, &w_idx) in input_witnesses.iter().enumerate() {
            // Block argument 0 is the first input param (compute has no %self arg).
            let arg_val: Value = block.argument(arg_idx)?.into();
            writer.known.insert(w_idx);
            writer.inner.witness_cache.insert(w_idx, arg_val);
        }
        Ok(writer)
    }
}
