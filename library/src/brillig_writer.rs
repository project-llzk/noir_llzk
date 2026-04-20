//! LLZK block writer for module-level Brillig function bodies.
//!
//! Unlike [`BlockWriter`](crate::block_writer::BlockWriter), which targets
//! `@compute` / `@constrain` inside a struct, `BrilligWriter` appends
//! operations to a bare function body block — there is no `%self`, no witness
//! cache, and no return terminator until after translation.

use std::collections::HashMap;

use acir::FieldElement;
use llzk::prelude::melior_dialects::arith::{self, CmpiPredicate};
use llzk::prelude::{
    Block, BlockLike, BlockRef, FeltType, IntegerAttribute, IntegerType, LlzkContext, Location,
    Operation, OperationRef, Type, Value, ValueLike, dialect,
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
/// Operations are appended to the end of the block. The caller is responsible
/// for appending the `function.return` terminator after translation.
pub(crate) struct BrilligWriter<'c, 'a> {
    context: &'c LlzkContext,
    block: BlockRef<'c, 'a>,
    location: Location<'c>,
    /// Cache of `felt.constant` values — each distinct field element is emitted at most once.
    constant_cache: HashMap<FieldElement, Value<'c, 'a>>,
    /// Cache of `arith.constant` index values — each distinct integer is emitted at most once.
    integer_cache: HashMap<usize, Value<'c, 'a>>,
}

impl<'c, 'a> BrilligWriter<'c, 'a> {
    pub(crate) fn new(context: &'c LlzkContext, block: &'a Block<'c>) -> Self {
        let block_ref = unsafe { BlockRef::from_raw(block.to_raw()) };
        Self {
            context,
            block: block_ref,
            location: Location::unknown(context),
            constant_cache: HashMap::new(),
            integer_cache: HashMap::new(),
        }
    }

    // ── Type helpers ────────────────────────────────────────────────────

    /// Returns the MLIR `index` type for this context.
    pub(crate) fn index_type(&self) -> Type<'c> {
        Type::index(self.context)
    }

    /// Returns the canonical signless integer type of the given bit width.
    pub(crate) fn integer_type(&self, bits: u32) -> Type<'c> {
        IntegerType::new(self.context, bits).into()
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

    // ── Cast operations ────────────────────────────────────────────────

    /// Emits `cast.toindex val`, converting a felt value to the index type.
    pub(crate) fn insert_cast_to_index(&self, val: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::cast::toindex(self.location, val))
    }

    /// Emits `cast.tofelt val`, converting an index-typed value into a felt.
    pub(crate) fn insert_cast_to_felt(&self, val: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        let felt_ty = FeltType::with_field(self.context, FIELD_NAME);
        self.insert_op_with_result(dialect::cast::tofelt(self.location, val, Some(felt_ty)))
    }

    /// Converts `val` to `index` type for `ram.load` / `ram.store` addresses.
    ///
    /// Index-typed inputs pass through. Felt inputs go via `cast.toindex`;
    /// everything else (including `iN`) goes via `arith.index_cast`.
    pub(crate) fn cast_to_index(&self, val: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        let ty = val.r#type();
        if ty == self.index_type() {
            return Ok(val);
        }
        if is_felt_type(ty) {
            return self.insert_cast_to_index(val);
        }
        self.insert_arith_index_cast(val, self.index_type())
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

    // ── Integer arithmetic (arith dialect) ─────────────────────────────

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

    // ── Caching helpers ─────────────────────────────────────────────────

    /// Returns a `felt.constant` value for the given field element, emitting
    /// the operation at most once per distinct value per block.
    pub(crate) fn emit_constant(&mut self, fe: &FieldElement) -> Result<Value<'c, 'a>, Error> {
        if let Some(&val) = self.constant_cache.get(fe) {
            return Ok(val);
        }
        let attr = field_to_felt_const(self.context, fe);
        let val = self.insert_op_with_result(dialect::felt::constant(self.location, attr)?)?;
        self.constant_cache.insert(*fe, val);
        Ok(val)
    }

    /// Returns an `arith.constant` index value for `i`, emitting the operation
    /// at most once per distinct value per block.
    pub(crate) fn insert_integer(&mut self, i: usize) -> Result<Value<'c, 'a>, Error> {
        if let Some(&val) = self.integer_cache.get(&i) {
            return Ok(val);
        }
        let val = self.insert_op_with_result(arith::constant(
            self.context,
            IntegerAttribute::new(Type::index(self.context), i as i64).into(),
            self.location,
        ))?;
        self.integer_cache.insert(i, val);
        Ok(val)
    }

    // ── Core IR operations ──────────────────────────────────────────────

    /// Inserts a single-result `op` and returns its first result as a `Value`.
    fn insert_op_with_result(&self, op: Operation<'c>) -> Result<Value<'c, 'a>, Error> {
        Ok(self.insert_op(op).result(0)?.into())
    }

    /// Appends `op` to the end of the block.
    fn insert_op(&self, op: Operation<'c>) -> OperationRef<'c, 'a> {
        self.block.append_operation(op)
    }
}
