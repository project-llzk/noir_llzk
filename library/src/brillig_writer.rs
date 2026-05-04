//! LLZK block writer for module-level Brillig function bodies.
//!
//! Unlike [`BlockWriter`](crate::block_writer::BlockWriter), which targets
//! `@compute` / `@constrain` inside a struct, `BrilligWriter` appends
//! operations to a bare function body block — there is no `%self`, no witness
//! cache, and no return terminator until after translation.

use std::collections::HashMap;

use acir::FieldElement;
use llzk::prelude::melior_dialects::{arith, scf};
use llzk::prelude::{
    Block, BlockLike, BlockRef, FeltType, IntegerAttribute, LlzkContext, Location, Operation,
    OperationRef, Region, RegionLike, Type, Value, ValueLike, dialect,
};

use crate::FIELD_NAME;
use crate::common::field_to_felt_const;
use crate::error::Error;

/// Treats any type whose textual form starts with `!felt.` as a felt type.
pub(crate) fn is_felt_type(ty: Type<'_>) -> bool {
    format!("{ty}").starts_with("!felt.")
}

/// Block writer for module-level Brillig sibling functions.
///
/// Ordinary ops are appended to `current_block`. Constant ops
/// (`felt.constant`, `arith.constant`) are appended to `constants_block`,
///
/// The caller is responsible for appending the `function.return`
/// terminator after translation.
pub(crate) struct BrilligWriter<'c, 'a> {
    context: &'c LlzkContext,
    /// Where ordinary ops are appended.
    current_block: BlockRef<'c, 'a>,
    /// Where `felt.constant` and `arith.constant` ops are appended.
    constants_block: BlockRef<'c, 'a>,
    location: Location<'c>,
    /// Cache of `felt.constant` values — each distinct field element is
    /// emitted at most once per function. Safe to share across regions
    /// because every cached `Value` lives in `constants_block`.
    constant_cache: HashMap<FieldElement, Value<'c, 'a>>,
    /// Cache of `arith.constant` index values — same dominance argument
    /// as [`Self::constant_cache`].
    integer_cache: HashMap<usize, Value<'c, 'a>>,
}

impl<'c, 'a> BrilligWriter<'c, 'a> {
    pub(crate) fn new(context: &'c LlzkContext, block: &'a Block<'c>) -> Self {
        let block_ref = unsafe { BlockRef::from_raw(block.to_raw()) };
        Self {
            context,
            current_block: block_ref,
            constants_block: block_ref,
            location: Location::unknown(context),
            constant_cache: HashMap::new(),
            integer_cache: HashMap::new(),
        }
    }

    /// Redirects this writer's `current_block` to `block` and returns a
    /// [`BlockSaved`] handle that the caller passes to
    /// [`Self::leave_block`] to restore the previous insertion target.
    /// `constants_block` is unaffected — see the type docs.
    ///
    /// On the error path callers typically discard the writer, so missing
    /// a `leave_block` is benign.
    pub(crate) fn enter_block(&mut self, block: &Block<'c>) -> BlockRef<'c, 'a> {
        let saved = self.current_block;
        self.current_block = unsafe { BlockRef::from_raw(block.to_raw()) };
        saved
    }

    /// Restores the writer to the state captured by
    /// [`Self::enter_block`].
    pub(crate) fn leave_block(&mut self, saved: BlockRef<'c, 'a>) {
        self.current_block = saved;
    }

    // ── Type helpers ────────────────────────────────────────────────────

    /// Returns the MLIR `index` type for this context.
    pub(crate) fn index_type(&self) -> Type<'c> {
        Type::index(self.context)
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

    /// Emits `felt.sub lhs, rhs`.
    pub(crate) fn insert_sub(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::felt::sub(self.location, lhs, rhs)?)
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

    /// Emits `felt.uintdiv lhs, rhs` (unsigned integer division over felt).
    pub(crate) fn insert_uintdiv(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::felt::uintdiv(self.location, lhs, rhs)?)
    }

    // ── Felt bitwise / shifts ──────────────────────────────────────────
    //
    // Operate on the integer representation of the felt. Marked
    // `NotFieldNative` in the felt dialect — used in the brillig
    // (unconstrained) context to mirror Brillig VM bit-level semantics.

    /// Emits `felt.bit_and lhs, rhs`.
    pub(crate) fn insert_felt_bit_and(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::felt::bit_and(self.location, lhs, rhs)?)
    }

    /// Emits `felt.bit_or lhs, rhs`.
    pub(crate) fn insert_felt_bit_or(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::felt::bit_or(self.location, lhs, rhs)?)
    }

    /// Emits `felt.bit_xor lhs, rhs`.
    pub(crate) fn insert_felt_bit_xor(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::felt::bit_xor(self.location, lhs, rhs)?)
    }

    /// Emits `felt.shl lhs, rhs`.
    pub(crate) fn insert_felt_shl(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::felt::shl(self.location, lhs, rhs)?)
    }

    /// Emits `felt.shr lhs, rhs`.
    pub(crate) fn insert_felt_shr(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::felt::shr(self.location, lhs, rhs)?)
    }

    // ── Bool comparisons ───────────────────────────────────────────────

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

    /// Emits `bool.cmp gt(lhs, rhs)`.
    pub(crate) fn insert_bool_gt(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::bool::gt(self.location, lhs, rhs)?)
    }

    /// Emits `bool.assert cond` (no failure message).
    pub(crate) fn insert_bool_assert(&self, cond: Value<'c, 'a>) -> Result<(), Error> {
        self.insert_op(dialect::bool::assert(self.location, cond, None)?);
        Ok(())
    }

    /// Emits `bool.not cond`.
    pub(crate) fn insert_bool_not(&self, cond: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::bool::not(self.location, cond)?)
    }

    /// Emits `bool.and lhs, rhs`.
    pub(crate) fn insert_bool_and(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::bool::and(self.location, lhs, rhs)?)
    }

    /// Materialises `val` (a felt holding `0` or `1`) as an `i1` via
    /// `bool.cmp eq(val, 1)`.
    pub(crate) fn insert_felt_to_bool(
        &mut self,
        val: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        let one = self.emit_constant(&FieldElement::from(1u128))?;
        self.insert_bool_eq(val, one)
    }

    // ── Cast operations ────────────────────────────────────────────────

    /// Emits `cast.toindex val`, converting a felt value to the index type.
    pub(crate) fn insert_cast_to_index(&self, val: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::cast::toindex(self.location, val))
    }

    /// Emits `cast.tofelt val`, widening an integer value (e.g. the `i1`
    /// result of `bool.cmp`) to the circuit's felt type.
    pub(crate) fn insert_cast_to_felt(&self, val: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        let felt_ty = FeltType::with_field(self.context, FIELD_NAME);
        self.insert_op_with_result(dialect::cast::tofelt(self.location, val, Some(felt_ty)))
    }

    /// Converts `val` to `index` type for `ram.load` / `ram.store` addresses.
    ///
    /// Index-typed inputs pass through; felt inputs go via `cast.toindex`.
    pub(crate) fn cast_to_index(&self, val: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        let ty = val.r#type();
        if ty == self.index_type() {
            return Ok(val);
        }
        debug_assert!(
            is_felt_type(ty),
            "cast_to_index expected felt or index, got {ty}"
        );
        self.insert_cast_to_index(val)
    }

    // ── Index arithmetic ───────────────────────────────────────────────

    /// Emits `arith.addi lhs, rhs`. Both operands must share an integer
    /// (or `index`) type; the result is the same type.
    pub(crate) fn insert_index_add(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(arith::addi(lhs, rhs, self.location))
    }

    // ── RAM operations ─────────────────────────────────────────────────

    /// Emits `ram.load %addr`, returning a value of the circuit's felt type.
    ///
    /// `addr` must be index-typed. RAM cells always hold felts.
    pub(crate) fn insert_ram_load(&self, addr: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        let felt_ty = FeltType::with_field(self.context, FIELD_NAME);
        self.insert_op_with_result(dialect::ram::load(self.location, addr, Some(felt_ty)))
    }

    /// Emits `ram.store %addr, %val : type(val)`.
    ///
    /// `addr` must be index-typed.
    pub(crate) fn insert_ram_store(&self, addr: Value<'c, 'a>, val: Value<'c, 'a>) {
        self.insert_op(dialect::ram::store(self.location, addr, val));
    }

    // ── Structured control flow ────────────────────────────────────────

    /// Wraps `then_block` and `else_block` (already populated with their
    /// region bodies) in a no-result `scf.if` and appends it to
    /// `current_block`. Each region's `scf.yield` terminator is emitted
    /// here so callers don't need access to the writer's location.
    ///
    /// Used by the structured emitter for `RegionNode::IfThenElse`: the
    /// caller builds an empty `Block` per arm, drives recursive emission
    /// against it via [`Self::enter_block`] / [`Self::leave_block`], then
    /// hands both blocks to this method.
    pub(crate) fn insert_scf_if(
        &self,
        cond: Value<'c, 'a>,
        then_block: Block<'c>,
        else_block: Block<'c>,
    ) -> Result<(), Error> {
        then_block.append_operation(scf::r#yield(&[], self.location));
        else_block.append_operation(scf::r#yield(&[], self.location));

        let then_region = Region::new();
        then_region.append_block(then_block);
        let else_region = Region::new();
        else_region.append_block(else_block);

        self.insert_op(scf::r#if(
            cond,
            &[],
            then_region,
            else_region,
            self.location,
        ));
        Ok(())
    }

    /// Appends `scf.condition cond` (no carried args) to `current_block`.
    /// Used to terminate the before-region of an `scf.while`. The caller
    /// is responsible for being inside the before-block when this is
    /// called (e.g. via `enter_block`).
    pub(crate) fn insert_scf_condition(&self, cond: Value<'c, 'a>) {
        self.insert_op(scf::condition(cond, &[], self.location));
    }

    /// Appends `scf.yield` (no values) to `current_block`. Used to
    /// terminate the after-region of an `scf.while` (and any other
    /// scf-region whose body carries no result values).
    pub(crate) fn insert_scf_yield(&self) {
        self.insert_op(scf::r#yield(&[], self.location));
    }

    /// Wraps `before_block` and `after_block` (each already terminated
    /// with `scf.condition` / `scf.yield` by the caller) in a no-result
    /// `scf.while` and appends it to `current_block`.
    pub(crate) fn insert_scf_while(
        &self,
        before_block: Block<'c>,
        after_block: Block<'c>,
    ) -> Result<(), Error> {
        let before_region = Region::new();
        before_region.append_block(before_block);
        let after_region = Region::new();
        after_region.append_block(after_block);

        self.insert_op(scf::r#while(
            &[],
            &[],
            before_region,
            after_region,
            self.location,
        ));
        Ok(())
    }

    /// Emits `scf.if` as a branchless select: yields `then_val` when `cond`
    /// (an `i1`) is true, otherwise `else_val`. Both values must share
    /// `result_ty`, which is also the type of the returned SSA value.
    pub(crate) fn insert_scf_if_select(
        &self,
        cond: Value<'c, 'a>,
        then_val: Value<'c, 'a>,
        else_val: Value<'c, 'a>,
        result_ty: Type<'c>,
    ) -> Result<Value<'c, 'a>, Error> {
        let then_region = Region::new();
        let then_block = Block::new(&[]);
        then_block.append_operation(scf::r#yield(&[then_val], self.location));
        then_region.append_block(then_block);

        let else_region = Region::new();
        let else_block = Block::new(&[]);
        else_block.append_operation(scf::r#yield(&[else_val], self.location));
        else_region.append_block(else_block);

        self.insert_op_with_result(scf::r#if(
            cond,
            &[result_ty],
            then_region,
            else_region,
            self.location,
        ))
    }

    // ── Caching helpers ─────────────────────────────────────────────────

    /// Returns a `felt.constant` value for the given field element,
    /// emitting the operation into `constants_block` at most once per
    /// distinct value per function.
    pub(crate) fn emit_constant(&mut self, fe: &FieldElement) -> Result<Value<'c, 'a>, Error> {
        if let Some(&val) = self.constant_cache.get(fe) {
            return Ok(val);
        }
        let attr = field_to_felt_const(self.context, fe);
        let op = self
            .constants_block
            .append_operation(dialect::felt::constant(self.location, attr)?);
        let val: Value<'c, 'a> = op.result(0)?.into();
        self.constant_cache.insert(*fe, val);
        Ok(val)
    }

    /// Returns an `arith.constant` index value for `i`, emitting the
    /// operation into `constants_block` at most once per distinct value
    /// per function.
    pub(crate) fn insert_integer(&mut self, i: usize) -> Result<Value<'c, 'a>, Error> {
        if let Some(&val) = self.integer_cache.get(&i) {
            return Ok(val);
        }
        let op = self.constants_block.append_operation(arith::constant(
            self.context,
            IntegerAttribute::new(Type::index(self.context), i as i64).into(),
            self.location,
        ));
        let val: Value<'c, 'a> = op.result(0)?.into();
        self.integer_cache.insert(i, val);
        Ok(val)
    }

    // ── Core IR operations ──────────────────────────────────────────────

    /// Inserts a single-result `op` and returns its first result as a `Value`.
    fn insert_op_with_result(&self, op: Operation<'c>) -> Result<Value<'c, 'a>, Error> {
        Ok(self.insert_op(op).result(0)?.into())
    }

    /// Appends `op` to the end of `current_block`.
    fn insert_op(&self, op: Operation<'c>) -> OperationRef<'c, 'a> {
        self.current_block.append_operation(op)
    }
}
