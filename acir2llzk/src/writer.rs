//! Shared writer trait factoring out the common dialect-emission helpers
//! used by both [`BlockWriter`](crate::block_writer::BlockWriter) and
//! [`BrilligWriter`](crate::brillig_writer::BrilligWriter).
//!
//! Implementors provide the polymorphic insertion strategy via
//! [`Writer::insert_op`] (e.g. "before terminator" vs "append at end"); the
//! trait supplies thin wrappers for `felt`, `bool`, `cast`, and
//! `function.call` ops so each writer doesn't redefine them.

use ::llzk::{
    builder::{EntryPoint, OpBuilder},
    prelude::{
        FlatSymbolRefAttribute, LlzkContext, Location, Operation, OperationRef, Type, Value,
        dialect::*,
    },
};

use crate::{blackboxes::registry::BlackboxFunction, common::as_value, error::Error};

pub(crate) trait Writer<'c, 'a>
where
    'c: 'a,
{
    fn context(&self) -> &'c LlzkContext;

    fn location(&self) -> Location<'c>;

    /// Polymorphic insertion: BlockWriter inserts before its return
    /// terminator; BrilligWriter appends to the end of its current block.
    fn insert_op(&self, op: Operation<'c>) -> OperationRef<'c, 'a>;

    /// Insertion point matching [`Self::insert_op`]'s placement, used to
    /// construct [`OpBuilder`]s.
    fn insertion_point(&self) -> EntryPoint<'c, 'a>;

    fn insert_op_with_result(&self, op: Operation<'c>) -> Result<Value<'c, 'a>, Error> {
        Ok(self.insert_op(op).result(0)?.into())
    }

    fn felt_type(&self) -> Type<'c> {
        self.context().felt_type().into()
    }

    fn builder(&self) -> OpBuilder<'c, '_> {
        OpBuilder::new(self.context(), self.insertion_point())
    }

    // ── Felt arithmetic ────────────────────────────────────────────────

    fn insert_add(&self, lhs: Value<'c, 'a>, rhs: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        as_value(felt::add(&self.builder(), self.location(), lhs, rhs)?)
    }

    fn insert_mul(&self, lhs: Value<'c, 'a>, rhs: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        as_value(felt::mul(&self.builder(), self.location(), lhs, rhs)?)
    }

    fn insert_div(&self, lhs: Value<'c, 'a>, rhs: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        as_value(felt::div(&self.builder(), self.location(), lhs, rhs)?)
    }

    /// `felt.uintdiv` — unsigned integer division over the felt's integer
    /// representation. `NotFieldNative`; valid in compute / brillig bodies
    /// only, never inside `@constrain`.
    fn insert_uintdiv(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        as_value(felt::uintdiv(&self.builder(), self.location(), lhs, rhs)?)
    }

    /// `felt.umod` — same constraints as [`Self::insert_uintdiv`].
    fn insert_umod(&self, lhs: Value<'c, 'a>, rhs: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        as_value(felt::umod(&self.builder(), self.location(), lhs, rhs)?)
    }

    // ── Felt bitwise ───────────────────────────────────────────────────
    //
    // Operate on the integer representation of the felt; `NotFieldNative`.

    fn insert_felt_bit_and(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        as_value(felt::bit_and(&self.builder(), self.location(), lhs, rhs)?)
    }

    fn insert_felt_bit_xor(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        as_value(felt::bit_xor(&self.builder(), self.location(), lhs, rhs)?)
    }

    // ── Bool comparisons ───────────────────────────────────────────────

    fn insert_bool_lt(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        as_value(bool::lt(&self.builder(), self.location(), lhs, rhs)?)
    }

    fn insert_bool_eq(
        &self,
        lhs: Value<'c, 'a>,
        rhs: Value<'c, 'a>,
    ) -> Result<Value<'c, 'a>, Error> {
        as_value(bool::eq(&self.builder(), self.location(), lhs, rhs)?)
    }

    fn insert_bool_assert(&self, cond: Value<'c, 'a>) -> Result<(), Error> {
        bool::assert(&self.builder(), self.location(), cond, None)?;
        Ok(())
    }

    // ── Misc ───────────────────────────────────────────────────────────

    fn insert_nondet(&self, result_type: Type<'c>) -> Result<Value<'c, 'a>, Error> {
        as_value(llzk::nondet(&self.builder(), self.location(), result_type))
    }

    fn insert_cast_to_index(&self, val: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        as_value(cast::toindex(
            &self.builder(),
            self.location(),
            val,
            None, // TODO: What are the overflow semantics of Noir?
        ))
    }

    fn insert_cast_to_felt(&self, val: Value<'c, 'a>) -> Result<Value<'c, 'a>, Error> {
        as_value(cast::tofelt(
            &self.builder(),
            self.location(),
            val,
            Some(self.felt_type().try_into().unwrap()),
        ))
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
        let call_op = function::call(
            &OpBuilder::new(self.context(), self.insertion_point()),
            self.location(),
            FlatSymbolRefAttribute::new(self.context(), name),
            args,
            result_types,
        )?;
        Ok(call_op.into())
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
