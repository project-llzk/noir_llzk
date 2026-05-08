//! Shared writer trait factoring out the common dialect-emission helpers
//! used by both [`BlockWriter`](crate::block_writer::BlockWriter) and
//! [`BrilligWriter`](crate::brillig_writer::BrilligWriter).
//!
//! Implementors provide the polymorphic insertion strategy via
//! [`Writer::insert_op`] (e.g. "before terminator" vs "append at end"); the
//! trait supplies thin wrappers for `felt`, `bool`, `cast`, and
//! `function.call` ops so each writer doesn't redefine them.

use llzk::builder::OpBuilder;
use llzk::prelude::{
    FeltType, FlatSymbolRefAttribute, LlzkContext, Location, Operation, OperationRef, Type, Value,
    dialect,
};

use crate::FIELD_NAME;
use crate::blackboxes::registry::BlackboxFunction;
use crate::error::Error;

pub(crate) trait Writer<'c, 'a>
where
    'c: 'a,
{
    fn context(&self) -> &'c LlzkContext;

    fn location(&self) -> Location<'c>;

    /// Polymorphic insertion: BlockWriter inserts before its return
    /// terminator; BrilligWriter appends to the end of its current block.
    fn insert_op(&self, op: Operation<'c>) -> OperationRef<'c, 'a>;

    fn insert_op_with_result(&self, op: Operation<'c>) -> Result<Value<'c, 'a>, Error> {
        Ok(self.insert_op(op).result(0)?.into())
    }

    fn felt_type(&self) -> Type<'c> {
        FeltType::with_field(self.context(), FIELD_NAME).into()
    }

    // ── Felt arithmetic ────────────────────────────────────────────────

    fn insert_add(&self, lhs: Value<'c, 'a>, rhs: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::felt::add(self.location(), lhs, rhs)?)
    }

    fn insert_mul(&self, lhs: Value<'c, 'a>, rhs: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::felt::mul(self.location(), lhs, rhs)?)
    }

    fn insert_div(&self, lhs: Value<'c, 'a>, rhs: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::felt::div(self.location(), lhs, rhs)?)
    }

    /// `felt.uintdiv` — unsigned integer division over the felt's integer
    /// representation. `NotFieldNative`; valid in compute / brillig bodies
    /// only, never inside `@constrain`.
    fn insert_uintdiv(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::felt::uintdiv(self.location(), lhs, rhs)?)
    }

    /// `felt.umod` — same constraints as [`Self::insert_uintdiv`].
    fn insert_umod(&self, lhs: Value<'c, 'a>, rhs: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::felt::umod(self.location(), lhs, rhs)?)
    }

    // ── Felt bitwise ───────────────────────────────────────────────────
    //
    // Operate on the integer representation of the felt; `NotFieldNative`.

    fn insert_felt_bit_and(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::felt::bit_and(self.location(), lhs, rhs)?)
    }

    fn insert_felt_bit_xor(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::felt::bit_xor(self.location(), lhs, rhs)?)
    }

    // ── Bool comparisons ───────────────────────────────────────────────

    fn insert_bool_lt(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::bool::lt(self.location(), lhs, rhs)?)
    }

    fn insert_bool_eq(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::bool::eq(self.location(), lhs, rhs)?)
    }

    fn insert_bool_assert(&self, cond: Value<'c, 'a>) -> Result<(), Error> {
        self.insert_op(dialect::bool::assert(self.location(), cond, None)?);
        Ok(())
    }

    // ── Misc ───────────────────────────────────────────────────────────

    fn insert_nondet(&self, result_type: Type<'c>) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::llzk::nondet(self.location(), result_type))
    }

    fn insert_cast_to_index(&self, val: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        self.insert_op_with_result(dialect::cast::toindex(self.location(), val))
    }

    /// Calls `@name(args)` (flat symbol reference). For struct-scoped
    /// two-level calls into another struct's `@compute` / `@constrain`,
    /// use [`BlockWriter::call_function`](crate::block_writer::BlockWriter::call_function).
    fn call_top_level_function(
        &self,
        name: &str,
        args: &[Value<'c, 'a>],
        result_types: &[Type<'c>],
    ) -> Result<OperationRef<'c, 'a>, Error> {
        let call_op = dialect::function::call(
            &OpBuilder::new(self.context()),
            self.location(),
            FlatSymbolRefAttribute::new(self.context(), name),
            args,
            result_types,
        )?;
        Ok(self.insert_op(call_op.into()))
    }

    fn call_blackbox_function(
        &self,
        func: BlackboxFunction,
        args: &[Value<'c, 'a>],
    ) -> Result<OperationRef<'c, 'a>, Error> {
        let result_types = func.result_types(self.context());
        self.call_top_level_function(&func.symbol_name(), args, &result_types)
    }
}
