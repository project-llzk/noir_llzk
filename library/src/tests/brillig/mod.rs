//! Tests for Milestone 3 Brillig translation, split by issue:
//!
//! - [`dispatch_tests`] — Issue 2 (BrilligCall handler skeleton, dispatch,
//!   predicate gating, input-marshalling stubs, module-level dedup).
//! - [`register_tests`] — Issue 3 (register-machine opcodes: Const / Mov /
//!   Cast / CMov).
//! - [`binary_op_tests`] — Issue 4 (BinaryFieldOp and BinaryIntOp).
//!
//! Shared test helpers (bytecode/opcode constructors, body translation,
//! `@brillig_{id}` lookup) live in this module so every sibling test file
//! imports them via `super::`.

use acir::FieldElement;
use acir::brillig::{
    BinaryFieldOp, BinaryIntOp, BitSize, HeapVector, IntegerBitSize, MemoryAddress,
    Opcode as BrilligOpcode,
};
use acir::circuit::Opcode;
use acir::circuit::brillig::{BrilligBytecode, BrilligFunctionId, BrilligInputs, BrilligOutputs};
use acir::native_types::{Expression, Witness};
use llzk::prelude::{FuncDefOpRef, LlzkContext, Module, OperationLike, OperationRef, RegionLike};

use super::{iter_block_ops, make_circuit_with_opcodes, make_program_with_brillig};
use crate::Error;
use crate::program::translate_program;

mod binary_op_tests;
mod dispatch_tests;
mod heap_tests;
mod register_tests;
mod relative_addressing_tests;

// ── Bytecode / opcode constructors ─────────────────────────────────────

/// Builds a `BrilligOpcode::Stop` with an empty return-data vector.
pub(super) fn brillig_stop() -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Stop {
        return_data: HeapVector {
            pointer: MemoryAddress::Direct(0),
            size: MemoryAddress::Direct(0),
        },
    }
}

pub(super) fn bytecode(ops: Vec<BrilligOpcode<FieldElement>>) -> BrilligBytecode<FieldElement> {
    BrilligBytecode {
        function_name: String::from("test_brillig"),
        bytecode: ops,
    }
}

/// Builds a `BrilligCall` opcode with a trivially-true predicate (always execute).
pub(super) fn brillig_call_opcode(
    id: u32,
    inputs: Vec<BrilligInputs<FieldElement>>,
    outputs: Vec<BrilligOutputs>,
) -> Opcode<FieldElement> {
    Opcode::BrilligCall {
        id: BrilligFunctionId(id),
        inputs,
        outputs,
        predicate: Expression::one(),
    }
}

pub(super) fn single_witness(w: u32) -> BrilligInputs<FieldElement> {
    BrilligInputs::Single(Expression::from(Witness(w)))
}

pub(super) fn addr(i: u32) -> MemoryAddress {
    MemoryAddress::Direct(i)
}

pub(super) fn rel(offset: u32) -> MemoryAddress {
    MemoryAddress::Relative(offset)
}

pub(super) fn const_field(dst: u32, value: u128) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Const {
        destination: addr(dst),
        bit_size: BitSize::Field,
        value: FieldElement::from(value),
    }
}

pub(super) fn const_int(
    dst: u32,
    bit_size: IntegerBitSize,
    value: u128,
) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Const {
        destination: addr(dst),
        bit_size: BitSize::Integer(bit_size),
        value: FieldElement::from(value),
    }
}

pub(super) fn mov(dst: u32, src: u32) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Mov {
        destination: addr(dst),
        source: addr(src),
    }
}

pub(super) fn cast(dst: u32, src: u32, bit_size: BitSize) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Cast {
        destination: addr(dst),
        source: addr(src),
        bit_size,
    }
}

pub(super) fn binary_field_op(
    dst: u32,
    op: BinaryFieldOp,
    lhs: u32,
    rhs: u32,
) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::BinaryFieldOp {
        destination: addr(dst),
        op,
        lhs: addr(lhs),
        rhs: addr(rhs),
    }
}

pub(super) fn binary_int_op(
    dst: u32,
    op: BinaryIntOp,
    bit_size: IntegerBitSize,
    lhs: u32,
    rhs: u32,
) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::BinaryIntOp {
        destination: addr(dst),
        op,
        bit_size,
        lhs: addr(lhs),
        rhs: addr(rhs),
    }
}

pub(super) fn load(dst: u32, ptr: u32) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Load {
        destination: addr(dst),
        source_pointer: addr(ptr),
    }
}

pub(super) fn store(ptr: u32, src: u32) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Store {
        destination_pointer: addr(ptr),
        source: addr(src),
    }
}

// ── Module / brillig-body lookup helpers ───────────────────────────────

/// Locates the module-level `@brillig_{id}` function, if present.
pub(super) fn find_brillig_fn<'c, 'a>(
    module: &'a Module<'c>,
    id: u32,
) -> Option<OperationRef<'c, 'a>> {
    let expected = format!("brillig_{id}");
    let body = module.body();
    for op in iter_block_ops(body) {
        if FuncDefOpRef::try_from(op).is_ok() {
            let attr = op.attribute("sym_name").ok()?;
            if attr.to_string().contains(&expected) {
                return Some(op);
            }
        }
    }
    None
}

/// Counts module-level Brillig functions (those whose `sym_name` starts with
/// `brillig_`).
pub(super) fn count_brillig_fns(module: &Module) -> usize {
    let body = module.body();
    iter_block_ops(body)
        .filter(|op| {
            FuncDefOpRef::try_from(*op).is_ok()
                && op
                    .attribute("sym_name")
                    .ok()
                    .is_some_and(|a| a.to_string().contains("brillig_"))
        })
        .count()
}

/// Translates a zero-input / zero-output `BrilligCall` with the given body,
/// returning the emitted module on success.
pub(super) fn translate_body(
    context: &LlzkContext,
    ops: Vec<BrilligOpcode<FieldElement>>,
) -> Result<Module<'_>, Error> {
    let circuit = make_circuit_with_opcodes(
        0,
        &[],
        &[],
        &[],
        vec![brillig_call_opcode(0, vec![], vec![])],
    );
    let program = make_program_with_brillig(vec![circuit], vec![bytecode(ops)]);
    translate_program(context, &program)
}

/// Counts ops in the body of `@brillig_{id}` that match `predicate`.
pub(super) fn count_brillig_body_ops<F>(module: &Module, id: u32, predicate: F) -> usize
where
    F: Fn(OperationRef<'_, '_>) -> bool,
{
    let brillig_op = find_brillig_fn(module, id).expect("module should contain @brillig_{id}");
    let body = brillig_op.region(0).unwrap().first_block().unwrap();
    iter_block_ops(body).filter(|op| predicate(*op)).count()
}
