use acir::circuit::Opcode;
use acir::native_types::{Expression, Witness};
use acir::{AcirField, FieldElement};
use llzk::prelude::{LlzkContext, OperationLike, RegionLike, StructDefOpLike};

use super::{
    make_circuit_with_opcodes, mul_constraint, print_and_verify_module, translate_single_circuit,
    verify_struct_in_module,
};
use crate::program::translate_program;

/// Count `struct.writem` operations in the compute function.
fn count_writem_ops(struct_def: &llzk::prelude::StructDefOp) -> usize {
    let compute = struct_def.compute_func().expect("Should have @compute");
    let block = compute.region(0).unwrap().first_block().unwrap();
    super::iter_block_ops(block)
        .filter(llzk::prelude::dialect::r#struct::is_struct_writem)
        .count()
}

/// `x * y - z = 0` where x, y are inputs and z is intermediate → compute solves z = x * y
#[test]
fn solve_mul_term() {
    let context = LlzkContext::new();
    // w0=x (private), w1=y (private), w2=z (intermediate)
    // expr: 1*w0*w1 + (-1)*w2 + 0 = 0  →  z = x * y
    let circuit = make_circuit_with_opcodes(2, &[0, 1], &[], &[], vec![mul_constraint(0, 1, 2)]);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();

    // 1 solved witness write (inputs no longer written to struct)
    assert_eq!(count_writem_ops(&struct_def), 1);

    verify_struct_in_module(&context, struct_def, "solve_mul_term");
}

/// Linear solve: `x + y - z = 0` where x, y known → z = x + y
#[test]
fn solve_linear() {
    let context = LlzkContext::new();
    // w0=x (private), w1=y (private), w2=z (intermediate)
    // expr: 1*w0 + 1*w1 + (-1)*w2 = 0
    let expr = Expression {
        mul_terms: vec![],
        linear_combinations: vec![
            (FieldElement::one(), Witness(0)),
            (FieldElement::one(), Witness(1)),
            (-FieldElement::one(), Witness(2)),
        ],
        q_c: FieldElement::zero(),
    };
    let circuit = make_circuit_with_opcodes(2, &[0, 1], &[], &[], vec![Opcode::AssertZero(expr)]);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();

    // 1 solved witness write (inputs no longer written to struct)
    assert_eq!(count_writem_ops(&struct_def), 1);

    verify_struct_in_module(&context, struct_def, "solve_linear");
}

/// Chain of solves: opcode 1 solves z from x,y; opcode 2 uses z to solve w
#[test]
fn chain_of_solves() {
    let context = LlzkContext::new();
    // w0=x, w1=y (inputs), w2=z (intermediate), w3=w (intermediate)
    // opcode 1: x * y - z = 0  →  z = x * y
    let expr1 = mul_constraint(0, 1, 2);
    // opcode 2: z + x - w = 0  →  w = z + x
    let expr2 = Expression {
        mul_terms: vec![],
        linear_combinations: vec![
            (FieldElement::one(), Witness(2)),
            (FieldElement::one(), Witness(0)),
            (-FieldElement::one(), Witness(3)),
        ],
        q_c: FieldElement::zero(),
    };
    let circuit =
        make_circuit_with_opcodes(3, &[0, 1], &[], &[], vec![expr1, Opcode::AssertZero(expr2)]);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();

    // 2 solved witness writes (inputs no longer written to struct)
    assert_eq!(count_writem_ops(&struct_def), 2);

    verify_struct_in_module(&context, struct_def, "chain_of_solves");
}

/// Two unknowns in one opcode → error diagnostic
#[test]
fn two_unknowns_error() {
    let context = LlzkContext::new();
    // w0=x (input), w1=y (unknown), w2=z (unknown)
    // expr: x + y - z = 0 — both y and z are unknown
    let expr = Expression {
        mul_terms: vec![],
        linear_combinations: vec![
            (FieldElement::one(), Witness(0)),
            (FieldElement::one(), Witness(1)),
            (-FieldElement::one(), Witness(2)),
        ],
        q_c: FieldElement::zero(),
    };
    let circuit = make_circuit_with_opcodes(2, &[0], &[], &[], vec![Opcode::AssertZero(expr)]);
    let result = translate_single_circuit(&context, circuit);

    assert!(result.is_err());
    let err = result.unwrap_err();
    match err {
        crate::Error::UnsolvableWitness {
            num_unknowns,
            opcode_index,
            ..
        } => {
            assert_eq!(num_unknowns, 2);
            assert_eq!(opcode_index, 0);
        }
        other => panic!("Expected UnsolvableWitness, got: {other}"),
    }
}

/// Full module (compute + constrain) verifies for a circuit with solving
#[test]
fn full_module_compute_and_constrain_verifies() {
    let context = LlzkContext::new();
    // w0=x (private), w1=y (public), w2=z (intermediate, returned)
    // expr: x * y - z = 0
    let circuit = make_circuit_with_opcodes(2, &[0], &[1], &[2], vec![mul_constraint(0, 1, 2)]);
    let program = acir::circuit::Program {
        functions: vec![circuit],
        unconstrained_functions: vec![],
    };
    let module = translate_program(&context, &program).unwrap();
    print_and_verify_module(&module, "full_module_compute_and_constrain_verifies");
}

/// Mixed: solve with non-unit coefficients — 2*x*y + 3*z = 0, solve z
#[test]
fn solve_with_coefficients() {
    let context = LlzkContext::new();
    // w0=x, w1=y (inputs), w2=z (intermediate)
    // expr: 2*w0*w1 + 3*w2 = 0  →  z = -(2*x*y) / 3
    let expr = Expression {
        mul_terms: vec![(FieldElement::from(2u128), Witness(0), Witness(1))],
        linear_combinations: vec![(FieldElement::from(3u128), Witness(2))],
        q_c: FieldElement::zero(),
    };
    let circuit = make_circuit_with_opcodes(2, &[0, 1], &[], &[], vec![Opcode::AssertZero(expr)]);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();

    // 1 solved witness write (inputs no longer written to struct)
    assert_eq!(count_writem_ops(&struct_def), 1);

    verify_struct_in_module(&context, struct_def, "solve_with_coefficients");
}
