use acir::circuit::Opcode;
use acir::native_types::{Expression, Witness};
use acir::{AcirField, FieldElement};
use llzk::prelude::{BlockLike, LlzkContext, OperationLike, RegionLike, StructDefOpLike};

use super::{make_circuit_with_opcodes, translate_single_circuit, verify_struct_in_module};

/// Count the number of `constrain.eq` operations in the constrain function.
fn count_constrain_eq_ops(struct_def: &llzk::prelude::StructDefOp) -> usize {
    let constrain = struct_def
        .get_constrain_func()
        .expect("Should have @constrain");
    let block = constrain.region(0).unwrap().first_block().unwrap();

    let mut count = 0;
    let mut op = block.first_operation();
    while let Some(current) = op {
        if llzk::prelude::dialect::constrain::is_constrain_eq(&current) {
            count += 1;
        }
        op = current.next_in_block();
    }
    count
}

/// `x + y - 10 = 0` → no mul terms, two linear terms with coeff 1, constant -10
#[test]
fn assert_zero_linear_only() {
    let context = LlzkContext::new();
    let expr = Expression {
        mul_terms: vec![],
        linear_combinations: vec![
            (FieldElement::one(), Witness(0)),
            (FieldElement::one(), Witness(1)),
        ],
        q_c: -FieldElement::from(10u128),
    };
    let circuit = make_circuit_with_opcodes(1, &[0, 1], &[], &[], vec![Opcode::AssertZero(expr)]);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();

    assert_eq!(count_constrain_eq_ops(&struct_def), 1);

    verify_struct_in_module(&context, struct_def, "assert_zero_linear_only");
}

/// `x * x - 9 = 0` → mul term with same witness both sides (squaring)
#[test]
fn assert_zero_squaring() {
    let context = LlzkContext::new();
    let expr = Expression {
        mul_terms: vec![(FieldElement::one(), Witness(0), Witness(0))],
        linear_combinations: vec![],
        q_c: -FieldElement::from(9u128),
    };
    let circuit = make_circuit_with_opcodes(0, &[0], &[], &[], vec![Opcode::AssertZero(expr)]);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();

    assert_eq!(count_constrain_eq_ops(&struct_def), 1);

    verify_struct_in_module(&context, struct_def, "assert_zero_squaring");
}

/// `2*x*y + 3*x - 7 = 0` → mixed mul and linear with non-unit coefficients
#[test]
fn assert_zero_mixed_coefficients() {
    let context = LlzkContext::new();
    let expr = Expression {
        mul_terms: vec![(FieldElement::from(2u128), Witness(0), Witness(1))],
        linear_combinations: vec![(FieldElement::from(3u128), Witness(0))],
        q_c: -FieldElement::from(7u128),
    };
    let circuit = make_circuit_with_opcodes(1, &[0, 1], &[], &[], vec![Opcode::AssertZero(expr)]);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();

    assert_eq!(count_constrain_eq_ops(&struct_def), 1);

    verify_struct_in_module(&context, struct_def, "assert_zero_mixed_coefficients");
}

/// Multiple `AssertZero` opcodes → multiple constraint sequences in the same @constrain body
#[test]
fn multiple_assert_zero_opcodes() {
    let context = LlzkContext::new();
    let expr1 = Expression {
        mul_terms: vec![(FieldElement::one(), Witness(0), Witness(1))],
        linear_combinations: vec![],
        q_c: -FieldElement::from(6u128),
    };
    let expr2 = Expression {
        mul_terms: vec![],
        linear_combinations: vec![
            (FieldElement::one(), Witness(0)),
            (FieldElement::one(), Witness(1)),
        ],
        q_c: -FieldElement::from(5u128),
    };
    let circuit = make_circuit_with_opcodes(
        1,
        &[0, 1],
        &[],
        &[],
        vec![Opcode::AssertZero(expr1), Opcode::AssertZero(expr2)],
    );
    let struct_def = translate_single_circuit(&context, circuit).unwrap();

    assert_eq!(count_constrain_eq_ops(&struct_def), 2);

    verify_struct_in_module(&context, struct_def, "multiple_assert_zero_opcodes");
}

/// Coefficient of -1 uses felt.neg optimization
#[test]
fn assert_zero_neg_one_coefficient() {
    let context = LlzkContext::new();
    let expr = Expression {
        mul_terms: vec![],
        linear_combinations: vec![
            (-FieldElement::one(), Witness(0)),
            (FieldElement::one(), Witness(1)),
        ],
        q_c: FieldElement::zero(),
    };
    let circuit = make_circuit_with_opcodes(1, &[0, 1], &[], &[], vec![Opcode::AssertZero(expr)]);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();

    let module = super::wrap_struct_in_module(&context, struct_def);
    let ir = format!("{}", module.as_operation());
    println!("neg_one_coefficient:\n{ir}");
    assert!(
        ir.contains("felt.neg"),
        "Should use felt.neg for -1 coefficient"
    );
    assert!(module.as_operation().verify(), "Module should verify");
}
