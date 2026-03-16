use std::collections::{HashMap, HashSet};

use llzk::builder::OpBuilder;
use llzk::dialect::felt::FeltConstAttribute;
use llzk::prelude::{
    BlockLike, BlockRef, FeltType, LlzkContext, Location, Operation, OperationLike, OperationRef,
    RegionLike, StructDefOp, StructDefOpLike, SymbolRefAttribute, Type, Value, dialect,
};

use crate::FIELD_NAME;
use crate::error::Error;

/// Shared LLZK block writer that manages witness reads and emits operations
/// into a single block (either `@compute` or `@constrain`).
///
/// Use [`BlockWriter::for_compute`] or [`BlockWriter::for_constrain`] to
/// construct a writer for the appropriate phase.
pub(crate) struct BlockWriter<'c, 'a> {
    pub(crate) context: &'c LlzkContext,
    block: BlockRef<'c, 'a>,
    ret_op: OperationRef<'c, 'a>,
    pub(crate) location: Location<'c>,
    pub(crate) self_value: Value<'c, 'a>,
    /// Cache of SSA values for witnesses that have been read from the struct.
    witness_cache: HashMap<u32, Value<'c, 'a>>,
    /// Witnesses that have been solved (compute phase only).
    known: Option<HashSet<u32>>,
    /// Cached `felt.constant 0` — emitted at most once per block.
    zero_cache: Option<Value<'c, 'a>>,
}

impl<'c, 'a> BlockWriter<'c, 'a> {
    fn new(
        context: &'c LlzkContext,
        block: BlockRef<'c, 'a>,
        ret_op: OperationRef<'c, 'a>,
        self_value: Value<'c, 'a>,
        witness_cache: HashMap<u32, Value<'c, 'a>>,
        known: Option<HashSet<u32>>,
    ) -> Self {
        Self {
            context,
            block,
            ret_op,
            location: Location::unknown(context),
            self_value,
            witness_cache,
            known,
            zero_cache: None,
        }
    }

    /// Builds a `BlockWriter` from an already-resolved `block` and `self_value`.
    ///
    /// Seeds the witness cache from block arguments starting at `arg_offset`
    /// (`0` for `@compute`, `1` for `@constrain`).
    fn from_block(
        context: &'c LlzkContext,
        block: BlockRef<'c, 'a>,
        self_value: Value<'c, 'a>,
        input_witnesses: &[u32],
        arg_offset: usize,
        known: Option<HashSet<u32>>,
    ) -> Result<Self, Error> {
        let ret_op = block.terminator().unwrap();
        let mut witness_cache = HashMap::new();
        for (i, &w_idx) in input_witnesses.iter().enumerate() {
            let val: Value = block.argument(i + arg_offset)?.into();
            witness_cache.insert(w_idx, val);
        }
        Ok(Self::new(
            context,
            block,
            ret_op,
            self_value,
            witness_cache,
            known,
        ))
    }

    /// Creates a writer targeting the `@compute` function of the given struct.
    pub(crate) fn for_compute(
        context: &'c LlzkContext,
        struct_def: &StructDefOp<'c>,
        input_witnesses: &[u32],
    ) -> Result<Self, Error> {
        let compute = struct_def
            .get_compute_func()
            .expect("Struct should have @compute");
        let block = compute.region(0)?.first_block().unwrap();

        // The first operation in compute is `struct.new`, its result is %self.
        // @compute has no %self arg — inputs start at argument 0.
        let self_value: Value = block.first_operation().unwrap().result(0)?.into();
        let known = Some(input_witnesses.iter().copied().collect());

        Self::from_block(context, block, self_value, input_witnesses, 0, known)
    }

    /// Creates a writer targeting the `@constrain` function of the given struct.
    pub(crate) fn for_constrain(
        context: &'c LlzkContext,
        struct_def: &StructDefOp<'c>,
        input_witnesses: &[u32],
    ) -> Result<Self, Error> {
        let constrain = struct_def
            .get_constrain_func()
            .expect("Struct should have @constrain");
        let block = constrain.region(0)?.first_block().unwrap();

        // @constrain argument 0 is %self — inputs start at argument 1.
        let self_value: Value = block.argument(0)?.into();

        Self::from_block(context, block, self_value, input_witnesses, 1, None)
    }

    // ── Core IR operations ──────────────────────────────────────────────

    /// Inserts `op` into the block immediately before the return terminator.
    pub(crate) fn insert_op(&self, op: Operation<'c>) -> OperationRef<'c, 'a> {
        self.block.insert_operation_before(self.ret_op, op)
    }

    /// Writes `val` into the `name` member of `%self` before the return terminator.
    pub(crate) fn write_member(&self, name: &str, val: Value<'c, 'a>) -> Result<(), Error> {
        self.insert_op(dialect::r#struct::writem(
            self.location,
            self.self_value,
            name,
            val,
        )?);
        Ok(())
    }

    /// Calls `@parent::@func(args)` returning `result_types` before the return terminator.
    pub(crate) fn call_function(
        &self,
        parent: &str,
        func: &str,
        args: &[Value<'c, 'a>],
        result_types: &[Type<'c>],
    ) -> Result<OperationRef<'c, 'a>, Error> {
        Ok(self.insert_op(
            dialect::function::call(
                &OpBuilder::new(self.context),
                self.location,
                SymbolRefAttribute::new(self.context, parent, &[func]),
                args,
                result_types,
            )?
            .into(),
        ))
    }

    /// Reads the `name` member of `from` (typed `ty`) before the return terminator.
    pub(crate) fn read_member(
        &self,
        ty: Type<'c>,
        from: Value<'c, 'a>,
        name: &str,
    ) -> Result<Value<'c, 'a>, Error> {
        Ok(self
            .insert_op(dialect::r#struct::readm(
                &OpBuilder::new(self.context),
                self.location,
                ty,
                from,
                name,
            )?)
            .result(0)?
            .into())
    }

    // ── Witness management ──────────────────────────────────────────────

    /// Returns the LLZK value for witness `w_idx`, reading it from `%self`
    /// on first access and caching the result.
    pub(crate) fn read_witness(&mut self, w_idx: u32) -> Result<Value<'c, 'a>, Error> {
        if let Some(&val) = self.witness_cache.get(&w_idx) {
            return Ok(val);
        }

        let felt_type: Type = FeltType::with_field(self.context, FIELD_NAME).into();
        let val = self.read_member(felt_type, self.self_value, &format!("w{w_idx}"))?;
        self.witness_cache.insert(w_idx, val);
        Ok(val)
    }

    /// Returns whether the given witness index has been solved.
    ///
    /// Only valid during the compute phase.
    pub(crate) fn is_known(&self, w_idx: u32) -> bool {
        debug_assert!(
            self.known.is_some(),
            "is_known called outside compute phase"
        );
        self.known.as_ref().is_some_and(|s| s.contains(&w_idx))
    }

    /// Records a solved witness value, updating both the known set and the cache.
    ///
    /// Only valid during the compute phase.
    pub(crate) fn mark_known(&mut self, w_idx: u32, val: Value<'c, 'a>) {
        debug_assert!(
            self.known.is_some(),
            "mark_known called outside compute phase"
        );
        if let Some(ref mut known) = self.known {
            known.insert(w_idx);
        }
        self.witness_cache.insert(w_idx, val);
    }

    // ── Caching helpers ─────────────────────────────────────────────────

    /// Returns a `felt.constant 0` value, emitting the operation at most once per block.
    pub(crate) fn emit_zero(&mut self) -> Result<Value<'c, 'a>, Error> {
        if let Some(zero) = self.zero_cache {
            return Ok(zero);
        }
        let zero_attr = FeltConstAttribute::new(self.context, 0, Some(FIELD_NAME));
        let zero_op = self.block.insert_operation_before(
            self.ret_op,
            dialect::felt::constant(self.location, zero_attr)?,
        );
        let zero: Value = zero_op.result(0)?.into();
        self.zero_cache = Some(zero);
        Ok(zero)
    }
}
