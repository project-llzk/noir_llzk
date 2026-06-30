//! Shared helpers for the Brillig submodules' unit tests.
//!
//! Bytecode constructors for hand-written fixtures, plus module / `@compute`
//! / `@brillig_*` lookup helpers used across multiple test files.

use acir::brillig::{
    BinaryFieldOp, BinaryIntOp, BitSize, HeapVector, IntegerBitSize, MemoryAddress,
    Opcode as BrilligOpcode,
};
use acir::circuit::Opcode;
use acir::circuit::brillig::{BrilligBytecode, BrilligFunctionId, BrilligInputs, BrilligOutputs};
use acir::native_types::{Expression, Witness};
use acir::{AcirField, FieldElement};
use llzk::prelude::dialect::function::is_func_call;
use llzk::prelude::{
    BlockRef, FuncDefOpRef, LlzkContext, Module, OperationLike, OperationRef, RegionLike,
    StructDefOpLike,
};

use crate::Error;
use crate::program::translate_program;
use crate::tests::{
    first_struct_def, iter_block_ops, make_circuit_with_opcodes, make_program_with_brillig,
};

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

pub(super) fn conditional_mov(
    dst: u32,
    source_a: u32,
    source_b: u32,
    condition: u32,
) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::ConditionalMov {
        destination: addr(dst),
        source_a: addr(source_a),
        source_b: addr(source_b),
        condition: addr(condition),
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

// ── @compute lookup helpers ────────────────────────────────────────────

/// Returns the first block of `@compute` on the first struct in the module.
pub(super) fn get_compute_block<'c, 'a>(module: &'a Module<'c>) -> BlockRef<'c, 'a> {
    let struct_def = first_struct_def(module);
    let compute_fn = struct_def
        .compute_func()
        .expect("Circuit0 should have @compute");
    compute_fn.region(0).unwrap().first_block().unwrap()
}

/// Counts ops in `@compute` whose op name equals `name`.
pub(super) fn count_compute_op(module: &Module, name: &str) -> usize {
    iter_block_ops(get_compute_block(module))
        .filter(|op| op.name().as_string_ref().as_str() == Ok(name))
        .count()
}

/// Counts `function.call` ops in `@compute`.
pub(super) fn count_compute_calls(module: &Module) -> usize {
    iter_block_ops(get_compute_block(module))
        .filter(is_func_call)
        .count()
}

/// Returns the first `function.call` op in `@compute`, if any.
pub(super) fn first_compute_call<'c, 'a>(module: &'a Module<'c>) -> Option<OperationRef<'c, 'a>> {
    iter_block_ops(get_compute_block(module)).find(is_func_call)
}

/// Builds a non-trivial predicate `Expression` whose value equals witness `w`.
pub(super) fn witness_predicate(w: u32) -> Expression<FieldElement> {
    Expression {
        mul_terms: vec![],
        linear_combinations: vec![(FieldElement::one(), Witness(w))],
        q_c: FieldElement::zero(),
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
/// Adds a copyCallData premable as program translation expects compile time
/// calldata copying for every brillig program.
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
    let program = make_program_with_brillig(vec![circuit], vec![bytecode_no_calldata(ops)]);
    translate_program(context, &program)
}

/// Counts ops in the body of `@brillig_{id}` that match `predicate`.
fn count_brillig_body_ops<F>(module: &Module, id: u32, predicate: F) -> usize
where
    F: Fn(OperationRef<'_, '_>) -> bool,
{
    let brillig_op = find_brillig_fn(module, id).expect("module should contain @brillig_{id}");
    let body = brillig_op.region(0).unwrap().first_block().unwrap();
    iter_block_ops(body).filter(|op| predicate(*op)).count()
}

/// Counts ops in the body of `@brillig_{id}` whose op name equals `name`.
pub(super) fn count_op(module: &Module, id: u32, name: &str) -> usize {
    count_brillig_body_ops(module, id, |op| {
        op.name().as_string_ref().as_str() == Ok(name)
    })
}

/// Returns the first op in the body of `@brillig_{id}` whose op name
/// equals `name`, if any.
pub(super) fn find_op<'c, 'a>(
    module: &'a Module<'c>,
    id: u32,
    name: &str,
) -> Option<OperationRef<'c, 'a>> {
    let brillig_op = find_brillig_fn(module, id)?;
    let body = brillig_op.region(0).unwrap().first_block().unwrap();
    iter_block_ops(body).find(|op| op.name().as_string_ref().as_str() == Ok(name))
}

/// Counts `ram.load` ops in the body of `@brillig_{id}`.
pub(super) fn count_loads(module: &Module, id: u32) -> usize {
    count_op(module, id, "ram.load")
}

/// Counts `ram.store` ops in the body of `@brillig_{id}`.
pub(super) fn count_stores(module: &Module, id: u32) -> usize {
    count_op(module, id, "ram.store")
}

/// Appends a call data copying to a test brillig snippet
pub(super) fn bytecode_no_calldata(
    ops: Vec<BrilligOpcode<FieldElement>>,
) -> BrilligBytecode<FieldElement> {
    let mut prefixed = Vec::with_capacity(ops.len() + 2);
    prefixed.push(const_int(0, IntegerBitSize::U32, 0));
    prefixed.push(BrilligOpcode::CalldataCopy {
        destination_address: addr(0),
        size_address: addr(0),
        offset_address: addr(0),
    });
    prefixed.extend(ops);
    bytecode(prefixed)
}
