use std::collections::{HashMap, HashSet};

use acir::FieldElement;
use llzk::builder::OpBuilder;
use llzk::dialect::array::{ArrayCtor, ArrayType};
use llzk::prelude::melior_dialects::arith::{self, CmpiPredicate};
use llzk::prelude::{
    Block, BlockLike, BlockRef, FeltType, FlatSymbolRefAttribute, IntegerAttribute, IntegerType,
    LlzkContext, Location, Operation, OperationLike, OperationRef, RegionLike, StructDefOp,
    StructDefOpLike, StructType, SymbolRefAttrLike, SymbolRefAttribute, Type, Value, dialect,
};

use crate::FIELD_NAME;
use crate::common::field_to_felt_const;
use crate::error::Error;

/// Shared LLZK block writer that manages witness reads and emits operations
/// into a single block (either `@compute` or `@constrain`).
///
/// Use [`BlockWriter::for_compute`] or [`BlockWriter::for_constrain`] to
/// construct a writer for the appropriate phase.
pub(crate) struct BlockWriter<'c, 'a> {
    context: &'c LlzkContext,
    block: BlockRef<'c, 'a>,
    /// When `Some`, every op is inserted before this terminator (compute / constrain).
    /// When `None`, ops are appended to the end of the block (function-body mode
    /// for module-level Brillig sibling functions, which have no terminator
    /// until after translation).
    ret_op: Option<OperationRef<'c, 'a>>,
    location: Location<'c>,
    /// `%self` of the enclosing struct, when the writer targets `@compute` or
    /// `@constrain`. `None` for module-level function bodies.
    self_value: Option<Value<'c, 'a>>,
    /// Cache of SSA values for witnesses that have been read from the struct.
    witness_cache: HashMap<u32, Value<'c, 'a>>,
    /// Witnesses that have been solved (compute phase only).
    known: Option<HashSet<u32>>,
    /// Cache of `felt.constant` values — each distinct field element is emitted at most once.
    constant_cache: HashMap<FieldElement, Value<'c, 'a>>,
    /// Cache of `arith.constant` index values — each distinct integer is emitted at most once.
    integer_cache: HashMap<usize, Value<'c, 'a>>,
    /// Current array value for each memory block, threaded through operations in order.
    memories: HashMap<u32, Value<'c, 'a>>,
}

impl<'c, 'a> BlockWriter<'c, 'a> {
    fn new(
        context: &'c LlzkContext,
        block: BlockRef<'c, 'a>,
        ret_op: Option<OperationRef<'c, 'a>>,
        self_value: Option<Value<'c, 'a>>,
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
            constant_cache: HashMap::new(),
            integer_cache: HashMap::new(),
            memories: HashMap::new(),
        }
    }

    /// Creates a writer targeting a function body that has no terminator yet.
    ///
    /// Used for module-level Brillig sibling functions: operations are
    /// appended to the block; there is no `%self` and no witness cache.
    pub(crate) fn for_function_body(context: &'c LlzkContext, block: &'a Block<'c>) -> Self {
        let block_ref = unsafe { BlockRef::from_raw(block.to_raw()) };
        Self::new(context, block_ref, None, None, HashMap::new(), None)
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
            Some(ret_op),
            Some(self_value),
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

    /// Returns the `%self` value; panics in function-body mode where none exists.
    fn expect_self(&self) -> Value<'c, 'a> {
        self.self_value
            .expect("self_value is only available in @compute / @constrain mode")
    }

    /// Reads the `name` member of `%self` (typed `ty`) before the return terminator.
    pub(crate) fn read_self_member(
        &self,
        ty: Type<'c>,
        name: &str,
    ) -> Result<Value<'c, 'a>, Error> {
        self.read_member(ty, self.expect_self(), name)
    }

    // ── Felt arithmetic ────────────────────────────────────────────────

    /// Emits `felt.add lhs, rhs`.
    pub(crate) fn insert_add(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::felt::add(self.location, lhs, rhs)?)
    }

    /// Emits `felt.mul lhs, rhs`.
    pub(crate) fn insert_mul(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::felt::mul(self.location, lhs, rhs)?)
    }

    /// Emits `felt.div lhs, rhs`.
    pub(crate) fn insert_div(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::felt::div(self.location, lhs, rhs)?)
    }

    /// Emits `felt.sub lhs, rhs`.
    pub(crate) fn insert_sub(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::felt::sub(self.location, lhs, rhs)?)
    }

    /// Emits `felt.uintdiv lhs, rhs` (unsigned integer division over felt).
    pub(crate) fn insert_uintdiv(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::felt::uintdiv(self.location, lhs, rhs)?)
    }

    /// Emits `felt.neg value`.
    pub(crate) fn insert_neg(&self, value: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::felt::neg(self.location, value)?)
    }

    /// Emits `felt.bit_and lhs, rhs`.
    pub(crate) fn insert_bit_and(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::felt::bit_and(self.location, lhs, rhs)?)
    }

    /// Emits `felt.bit_xor lhs, rhs`.
    pub(crate) fn insert_bit_xor(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::felt::bit_xor(self.location, lhs, rhs)?)
    }

    /// Emits `bool.cmp lt(lhs, rhs)`.
    pub(crate) fn insert_bool_lt(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::bool::lt(self.location, lhs, rhs)?)
    }

    /// Emits `bool.cmp le(lhs, rhs)`.
    pub(crate) fn insert_bool_le(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::bool::le(self.location, lhs, rhs)?)
    }

    /// Emits `bool.cmp eq(lhs, rhs)`.
    pub(crate) fn insert_bool_eq(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::bool::eq(self.location, lhs, rhs)?)
    }

    /// Emits `bool.assert cond`.
    pub(crate) fn insert_bool_assert(&self, cond: Value<'c, 'a>) -> Result<(), Error> {
        self.insert_op(dialect::bool::assert(self.location, cond, None)?);
        Ok(())
    }

    /// Emits `constrain.eq lhs, rhs`.
    pub(crate) fn insert_constrain_eq(&self, lhs: Value<'c, 'a>, rhs: Value<'c, 'a>) {
        self.insert_op(dialect::constrain::eq(self.location, lhs, rhs));
    }

    /// Writes `val` into the `name` member of `%self` before the return terminator.
    pub(crate) fn write_member(&self, name: &str, val: Value<'c, 'a>) -> Result<(), Error> {
        self.insert_op(dialect::r#struct::writem(
            self.location,
            self.expect_self(),
            name,
            val,
        )?);
        Ok(())
    }

    /// Returns the struct type for the given name.
    pub(crate) fn struct_type(&self, name: &str) -> Type<'c> {
        StructType::from_str(self.context, name).into()
    }

    /// Calls `@name(args)` (flat symbol reference) before the return terminator.
    ///
    /// Used to invoke module-level sibling functions. For calls into another
    /// struct's `@compute` / `@constrain`, use [`call_function`](Self::call_function)
    /// instead.
    pub(crate) fn call_top_level_function(
        &self,
        name: &str,
        args: &[Value<'c, 'a>],
        result_types: &[Type<'c>],
    ) -> Result<OperationRef<'c, 'a>, Error> {
        self.insert_call(
            FlatSymbolRefAttribute::new(self.context, name),
            args,
            result_types,
        )
    }

    /// Returns the canonical felt type for this circuit's field.
    pub(crate) fn felt_type(&self) -> Type<'c> {
        FeltType::with_field(self.context, FIELD_NAME).into()
    }

    // ── Array operations ──────────────────────────────────────────────

    /// Creates a new empty `!array.type<!felt.type, len>`.
    pub(crate) fn insert_new_array(&self, len: usize) -> Result<Value<'c, 'a>, Error> {
        let array_type = ArrayType::new_with_dims(self.felt_type(), &[len as i64]);
        let builder = OpBuilder::new(self.context);
        self.insert_op_with_result(dialect::array::new(
            &builder,
            self.location,
            array_type,
            ArrayCtor::Empty,
        ))
    }

    /// Returns an `arith.constant` index value for `i`, emitting the operation
    /// at most once per distinct value per block.
    pub(crate) fn insert_integer(&mut self, i: usize) -> Result<Value<'c, 'a>, Error> {
        if let Some(&val) = self.integer_cache.get(&i) {
            return Ok(val);
        }
        let val = self.insert_integer_op(i)?;
        self.integer_cache.insert(i, val);
        Ok(val)
    }

    /// Emits an `arith.constant` producing an index value.
    fn insert_integer_op(&self, i: usize) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(arith::constant(
            self.context,
            IntegerAttribute::new(Type::index(self.context), i as i64).into(),
            self.location,
        ))
    }

    /// Emits `array.write array[indices] = value`.
    pub(crate) fn insert_array_write(
        &self,
        array: Value<'c, 'a>,
        indices: &[Value<'c, 'a>],
        value: Value<'c, 'a>,
    ) {
        self.insert_op(dialect::array::write(self.location, array, indices, value));
    }

    /// Emits `cast.toindex val`, converting a felt circuit value to the index type
    /// required by `array.read` / `array.write`.
    pub(crate) fn insert_cast_to_index(&self, val: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::cast::toindex(self.location, val))
    }

    /// Emits `cast.tofelt val`, converting an index-typed value into a felt.
    pub(crate) fn insert_cast_to_felt(&self, val: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        let felt_ty = FeltType::with_field(self.context, FIELD_NAME);
        self.insert_op_with_result(dialect::cast::tofelt(self.location, val, Some(felt_ty)))
    }

    /// Returns the MLIR `index` type for this context.
    pub(crate) fn index_type(&self) -> Type<'c> {
        Type::index(self.context)
    }

    /// Emits `array.read array[idx]`, returning the felt-typed element.
    ///
    /// `idx` must be index-typed; pass a felt value through
    /// [`insert_cast_to_index`](Self::insert_cast_to_index) first.
    pub(crate) fn insert_array_read(
        &self,
        array: Value<'c, 'a>,
        idx: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::array::read(
            self.location,
            self.felt_type(),
            array,
            &[idx],
        ))
    }

    /// Records `arr` as the current live array for `block_id`.
    pub(crate) fn set_memory(&mut self, block_id: u32, arr: Value<'c, 'a>) {
        self.memories.insert(block_id, arr);
    }

    /// Returns the current live array for `block_id`, or `None` if not yet initialised.
    pub(crate) fn get_memory(&self, block_id: u32) -> Option<Value<'c, 'a>> {
        self.memories.get(&block_id).copied()
    }

    // ── RAM operations ─────────────────────────────────────────────────

    /// Emits `ram.load %addr : result_ty`, returning the loaded value.
    ///
    /// `addr` must be index-typed.
    pub(crate) fn insert_ram_load(
        &self,
        addr: Value<'c, 'a>,
        result_ty: Type<'c>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::ram::load(self.location, result_ty, addr))
    }

    /// Emits `ram.store %addr, %val : type(val)`.
    ///
    /// `addr` must be index-typed.
    pub(crate) fn insert_ram_store(&self, addr: Value<'c, 'a>, val: Value<'c, 'a>) {
        self.insert_op(dialect::ram::store(self.location, addr, val));
    }

    // ── Integer arithmetic (arith dialect) ─────────────────────────────
    //
    // These helpers wrap `arith.*` ops for use by the Brillig translator's
    // `BinaryIntOp` lowering. Operand types must match (both `iN` of the same
    // width); result type is inferred from operands for arithmetic/bitwise ops
    // and is `i1` for `cmpi`.

    /// Returns the canonical signless integer type of the given bit width.
    pub(crate) fn integer_type(&self, bits: u32) -> Type<'c> {
        IntegerType::new(self.context, bits).into()
    }

    /// Emits `arith.constant` producing an `iN` value for the given bit width.
    pub(crate) fn insert_arith_int_constant(
        &self,
        bits: u32,
        value: u128,
    ) -> Result<Value<'c, 'a>, Error> {
        let ty = self.integer_type(bits);
        self.insert_op_with_result(arith::constant(
            self.context,
            IntegerAttribute::new(ty, value as i64).into(),
            self.location,
        ))
    }

    /// Emits `arith.index_cast val : target_ty`, bridging `index` ↔ `iN`.
    pub(crate) fn insert_arith_index_cast(
        &self,
        val: Value<'c, 'a>,
        target_ty: Type<'c>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(arith::index_cast(val, target_ty, self.location))
    }

    /// Emits `arith.trunci val : target_ty` (narrowing integer truncation).
    pub(crate) fn insert_arith_trunci(
        &self,
        val: Value<'c, 'a>,
        target_ty: Type<'c>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(arith::trunci(val, target_ty, self.location))
    }

    /// Emits `arith.extui val : target_ty` (zero-extending integer widening).
    pub(crate) fn insert_arith_extui(
        &self,
        val: Value<'c, 'a>,
        target_ty: Type<'c>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(arith::extui(val, target_ty, self.location))
    }

    /// Emits `arith.addi lhs, rhs`.
    pub(crate) fn insert_arith_addi(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(arith::addi(lhs, rhs, self.location))
    }

    /// Emits `arith.subi lhs, rhs`.
    pub(crate) fn insert_arith_subi(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(arith::subi(lhs, rhs, self.location))
    }

    /// Emits `arith.muli lhs, rhs`.
    pub(crate) fn insert_arith_muli(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(arith::muli(lhs, rhs, self.location))
    }

    /// Emits `arith.divui lhs, rhs` (unsigned division; Brillig integers are unsigned).
    pub(crate) fn insert_arith_divui(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(arith::divui(lhs, rhs, self.location))
    }

    /// Emits `arith.andi lhs, rhs`.
    pub(crate) fn insert_arith_andi(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(arith::andi(lhs, rhs, self.location))
    }

    /// Emits `arith.ori lhs, rhs`.
    pub(crate) fn insert_arith_ori(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(arith::ori(lhs, rhs, self.location))
    }

    /// Emits `arith.xori lhs, rhs`.
    pub(crate) fn insert_arith_xori(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(arith::xori(lhs, rhs, self.location))
    }

    /// Emits `arith.shli lhs, rhs` (logical left shift).
    pub(crate) fn insert_arith_shli(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(arith::shli(lhs, rhs, self.location))
    }

    /// Emits `arith.shrui lhs, rhs` (logical right shift; Brillig integers are unsigned).
    pub(crate) fn insert_arith_shrui(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(arith::shrui(lhs, rhs, self.location))
    }

    /// Emits `arith.cmpi predicate, lhs, rhs`, returning an `i1` result.
    pub(crate) fn insert_arith_cmpi(
        &self,
        predicate: CmpiPredicate,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(arith::cmpi(
            self.context,
            predicate,
            lhs,
            rhs,
            self.location,
        ))
    }

    /// Calls `@parent::@func(args)` returning `result_types` before the return terminator.
    pub(crate) fn call_function(
        &self,
        parent: &str,
        func: &str,
        args: &[Value<'c, 'a>],
        result_types: &[Type<'c>],
    ) -> Result<OperationRef<'c, 'a>, Error> {
        self.insert_call(
            SymbolRefAttribute::new_from_str(self.context, parent, &[func]),
            args,
            result_types,
        )
    }

    /// Emits `function.call` with the given symbol reference before the return terminator.
    fn insert_call(
        &self,
        symbol: impl SymbolRefAttrLike<'c>,
        args: &[Value<'c, 'a>],
        result_types: &[Type<'c>],
    ) -> Result<OperationRef<'c, 'a>, Error> {
        Ok(self.insert_op(
            dialect::function::call(
                &OpBuilder::new(self.context),
                self.location,
                symbol,
                args,
                result_types,
            )?
            .into(),
        ))
    }

    /// Reads a felt-typed member of `from` by `name`.
    ///
    /// Convenience wrapper around [`read_member`](Self::read_member) that uses
    /// the canonical felt type.
    pub(crate) fn read_field_member(
        &self,
        from: Value<'c, 'a>,
        name: &str,
    ) -> Result<Value<'c, 'a>, Error> {
        let felt_type: Type<'c> = FeltType::with_field(self.context, FIELD_NAME).into();
        self.read_member(felt_type, from, name)
    }

    /// Reads the `name` member of `from` (typed `ty`) before the return terminator.
    fn read_member(
        &self,
        ty: Type<'c>,
        from: Value<'c, 'a>,
        name: &str,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::r#struct::readm(
            &OpBuilder::new(self.context),
            self.location,
            ty,
            from,
            name,
        )?)
    }
    // ── Core IR operations ──────────────────────────────────────────────

    /// Inserts a single-result `op` and returns its first result as a `Value`.
    fn insert_op_with_result(&self, op: Operation<'c>) -> Result<Value<'c, 'a>, Error> {
        Ok(self.insert_op(op).result(0)?.into())
    }
    /// Inserts `op` into the block immediately before the return terminator.
    fn insert_op(&self, op: Operation<'c>) -> OperationRef<'c, 'a> {
        match self.ret_op {
            Some(ret) => self.block.insert_operation_before(ret, op),
            None => self.block.append_operation(op),
        }
    }

    // ── Witness management ──────────────────────────────────────────────

    /// Returns the LLZK value for witness `w_idx`, reading it from `%self`
    /// on first access and caching the result.
    pub(crate) fn read_witness(&mut self, w_idx: u32) -> Result<Value<'c, 'a>, Error> {
        if let Some(&val) = self.witness_cache.get(&w_idx) {
            return Ok(val);
        }

        let val = self.read_field_member(self.expect_self(), &format!("w{w_idx}"))?;
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

    /// Returns a `felt.constant` value for the given field element, emitting
    /// the operation at most once per distinct value per block.
    pub(crate) fn emit_constant(&mut self, fe: &FieldElement) -> Result<Value<'c, 'a>, Error> {
        if let Some(&val) = self.constant_cache.get(fe) {
            return Ok(val);
        }
        let val = self.emit_constant_op(fe)?;
        self.constant_cache.insert(*fe, val);
        Ok(val)
    }

    /// Emits a `felt.constant` operation for the given field element.
    fn emit_constant_op(&self, fe: &FieldElement) -> Result<Value<'c, 'a>, Error> {
        let attr = field_to_felt_const(self.context, fe);
        self.insert_op_with_result(dialect::felt::constant(self.location, attr)?)
    }
}
