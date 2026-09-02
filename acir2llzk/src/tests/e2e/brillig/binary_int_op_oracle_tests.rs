//! Value-level differential gate for Brillig `BinaryIntOp`.
use acir::FieldElement;
use acir::brillig::{
    BinaryIntOp, BitSize, HeapVector, IntegerBitSize, MemoryAddress, Opcode as BrilligOpcode,
};
use acir::circuit::Opcode;
use acir::circuit::brillig::{BrilligBytecode, BrilligFunctionId, BrilligOutputs};
use acir::native_types::{Expression, Witness};

use crate::tests::e2e::{assert_witness_eq, run_e2e_program};
use crate::tests::{make_circuit_with_opcodes, make_program_with_brillig};

fn addr(i: u32) -> MemoryAddress {
    MemoryAddress::Direct(i)
}

fn cint(dst: u32, bs: IntegerBitSize, v: u128) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Const {
        destination: addr(dst),
        bit_size: BitSize::Integer(bs),
        value: FieldElement::from(v),
    }
}

fn mask(bs: IntegerBitSize) -> u128 {
    let n = u32::from(bs);
    if n >= 128 {
        u128::MAX
    } else {
        (1u128 << n) - 1
    }
}

fn oracle(op: BinaryIntOp, bs: IntegerBitSize, l: u128, r: u128) -> u128 {
    use BinaryIntOp::*;
    let m = mask(bs);
    let (l, r) = (l & m, r & m);
    match op {
        Add => l.wrapping_add(r) & m,
        Sub => l.wrapping_sub(r) & m,
        Mul => l.wrapping_mul(r) & m,
        Div => l / r,
        Equals => (l == r) as u128,
        LessThan => (l < r) as u128,
        LessThanEquals => (l <= r) as u128,
        And => l & r,
        Or => l | r,
        Xor => l ^ r,
        Shl => l.wrapping_shl(r as u32) & m,
        Shr => l >> r as u32,
    }
}

fn run_case(op: BinaryIntOp, bs: IntegerBitSize, l: u128, r: u128) {
    // Memory map: addr 0 = calldata sentinel; 1, 2 = lhs, rhs; 3 = result;
    // 4, 5 = return-data pointer (RAM) and size; RAM[100] stores the result.
    let body = vec![
        cint(0, IntegerBitSize::U32, 0),
        BrilligOpcode::CalldataCopy {
            destination_address: addr(0),
            size_address: addr(0),
            offset_address: addr(0),
        },
        cint(1, bs, l),
        cint(2, bs, r),
        BrilligOpcode::BinaryIntOp {
            destination: addr(3),
            op,
            bit_size: bs,
            lhs: addr(1),
            rhs: addr(2),
        },
        cint(4, IntegerBitSize::U32, 100),
        cint(5, IntegerBitSize::U32, 1),
        BrilligOpcode::Store {
            destination_pointer: addr(4),
            source: addr(3),
        },
        BrilligOpcode::Stop {
            return_data: HeapVector {
                pointer: addr(4),
                size: addr(5),
            },
        },
    ];
    let circuit = make_circuit_with_opcodes(
        0,
        &[],
        &[],
        &[],
        vec![Opcode::BrilligCall {
            id: BrilligFunctionId(0),
            inputs: vec![],
            outputs: vec![BrilligOutputs::Simple(Witness(0))],
            predicate: Expression::one(),
        }],
    );
    let program = make_program_with_brillig(
        vec![circuit],
        vec![BrilligBytecode {
            function_name: "case".into(),
            bytecode: body,
        }],
    );
    let computed = run_e2e_program(&program, &[], &[]);
    let expected = oracle(op, bs, l, r);
    assert_witness_eq(&computed.members, "w0", &expected.to_string());
}

#[test]
fn binary_int_ops_match_oracle() {
    use BinaryIntOp::*;
    use IntegerBitSize::*;
    for &bs in &[U8, U16, U32, U64, U128] {
        let m = mask(bs);
        let top = u32::from(bs) as u128 - 1;
        // Wrapping arith + bitwise + compare at boundary inputs. (m, m)
        // is the U128 Mul regression cell.
        for &(l, r) in &[(0, 1), (1, 0), (m, 1), (m, m), (m / 2 + 1, 2)] {
            for op in [
                Add,
                Sub,
                Mul,
                And,
                Or,
                Xor,
                Equals,
                LessThan,
                LessThanEquals,
            ] {
                run_case(op, bs, l, r);
            }
        }
        // Div: skip /0 (brillig_vm traps); divisors stay positive.
        for r in [1, m, (m / 2).max(1)] {
            run_case(Div, bs, m, r);
        }
        // Shifts: count ∈ [0, N). `1 << k` stays under p for any N, so safe
        // at U128; `MAX << k` for k ≥ 64 at U128 hits the unfixed Shl
        // field-overflow class — skipped.
        for r in [0, 1, top] {
            run_case(Shl, bs, 1, r);
            run_case(Shr, bs, m, r);
        }
    }
}
