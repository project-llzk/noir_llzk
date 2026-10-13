use acir::{
    AcirField, FieldElement,
    circuit::Opcode,
    native_types::{Expression, Witness},
};
use llzk::prelude::{
    LlzkContext, LlzkModuleBuilder, OperationLike, RegionLike, StructDefOpLike, StructDefOpRef,
    StructType,
    dialect::{constrain, r#struct},
};

use crate::{FIELD_NAME, tests::print_and_verify_module};

use super::{make_circuit_with_opcodes, translate_single_circuit, with_public_constant_output};

/// Count the number of `constrain.eq` operations in the constrain function.
fn count_constrain_eq_ops(struct_def: &StructDefOpRef) -> usize {
    let constrain = struct_def.constrain_func().expect("Should have @constrain");
    let block = constrain.region(0).unwrap().first_block().unwrap();
    super::iter_block_ops(block)
        .filter(constrain::is_eq_op)
        .count()
}

/// The original constraints use only known inputs, so only the independent
/// public constant should require a witness write in compute.
fn assert_constraint_and_output_counts(struct_def: &StructDefOpRef, original_constraints: usize) {
    assert_eq!(
        count_constrain_eq_ops(struct_def),
        original_constraints + 1,
        "original constraints plus the independent public constant constraint",
    );
    let compute = struct_def.compute_func().unwrap();
    let block = compute.region(0).unwrap().first_block().unwrap();
    assert_eq!(
        super::iter_block_ops(block)
            .filter(r#struct::is_writem_op)
            .count(),
        1,
        "only the independent public constant should be solved and written",
    );
}

/// `x + y - 10 = 0` → no mul terms, two linear terms with coeff 1, constant -10
#[test]
fn assert_zero_linear_only() {
    let mut context = LlzkContext::new();
    context.set_field(FIELD_NAME);
    let module = LlzkModuleBuilder::new(&context)
        .with_language("Noir")
        .with_main(StructType::from_str(&context, "Circuit0"))
        .build();
    let expr = Expression {
        mul_terms: vec![],
        linear_combinations: vec![
            (FieldElement::one(), Witness(0)),
            (FieldElement::one(), Witness(1)),
        ],
        q_c: -FieldElement::from(10u128),
    };
    let circuit = make_circuit_with_opcodes(1, &[0, 1], &[], &[], vec![Opcode::AssertZero(expr)]);
    let circuit = with_public_constant_output(circuit);
    let struct_def = translate_single_circuit(&context, circuit, module.body()).unwrap();

    assert_constraint_and_output_counts(&struct_def, 1);

    print_and_verify_module(&module, "assert_zero_linear_only");
}

/// `x * x - 9 = 0` → mul term with same witness both sides (squaring)
#[test]
fn assert_zero_squaring() {
    let mut context = LlzkContext::new();
    context.set_field(FIELD_NAME);
    let module = LlzkModuleBuilder::new(&context)
        .with_language("Noir")
        .with_main(StructType::from_str(&context, "Circuit0"))
        .build();
    let expr = Expression {
        mul_terms: vec![(FieldElement::one(), Witness(0), Witness(0))],
        linear_combinations: vec![],
        q_c: -FieldElement::from(9u128),
    };
    let circuit = make_circuit_with_opcodes(0, &[0], &[], &[], vec![Opcode::AssertZero(expr)]);
    let circuit = with_public_constant_output(circuit);
    let struct_def = translate_single_circuit(&context, circuit, module.body()).unwrap();

    assert_constraint_and_output_counts(&struct_def, 1);

    print_and_verify_module(&module, "assert_zero_squaring");
}

/// `2*x*y + 3*x - 7 = 0` → mixed mul and linear with non-unit coefficients
#[test]
fn assert_zero_mixed_coefficients() {
    let mut context = LlzkContext::new();
    context.set_field(FIELD_NAME);
    let module = LlzkModuleBuilder::new(&context)
        .with_language("Noir")
        .with_main(StructType::from_str(&context, "Circuit0"))
        .build();
    let expr = Expression {
        mul_terms: vec![(FieldElement::from(2u128), Witness(0), Witness(1))],
        linear_combinations: vec![(FieldElement::from(3u128), Witness(0))],
        q_c: -FieldElement::from(7u128),
    };
    let circuit = make_circuit_with_opcodes(1, &[0, 1], &[], &[], vec![Opcode::AssertZero(expr)]);
    let circuit = with_public_constant_output(circuit);
    let struct_def = translate_single_circuit(&context, circuit, module.body()).unwrap();

    assert_constraint_and_output_counts(&struct_def, 1);

    print_and_verify_module(&module, "assert_zero_mixed_coefficients");
}

/// Multiple `AssertZero` opcodes → multiple constraint sequences in the same @constrain body
#[test]
fn multiple_assert_zero_opcodes() {
    let mut context = LlzkContext::new();
    context.set_field(FIELD_NAME);
    let module = LlzkModuleBuilder::new(&context)
        .with_language("Noir")
        .with_main(StructType::from_str(&context, "Circuit0"))
        .build();
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
    let circuit = with_public_constant_output(circuit);
    let struct_def = translate_single_circuit(&context, circuit, module.body()).unwrap();

    assert_constraint_and_output_counts(&struct_def, 2);

    print_and_verify_module(&module, "multiple_assert_zero_opcodes");
}

/// Coefficient of -1 uses felt.neg optimization
#[test]
fn assert_zero_neg_one_coefficient() {
    let mut context = LlzkContext::new();
    context.set_field(FIELD_NAME);
    let module = LlzkModuleBuilder::new(&context)
        .with_language("Noir")
        .with_main(StructType::from_str(&context, "Circuit0"))
        .build();
    let expr = Expression {
        mul_terms: vec![],
        linear_combinations: vec![
            (-FieldElement::one(), Witness(0)),
            (FieldElement::one(), Witness(1)),
        ],
        q_c: FieldElement::zero(),
    };
    let circuit = make_circuit_with_opcodes(1, &[0, 1], &[], &[], vec![Opcode::AssertZero(expr)]);
    translate_single_circuit(&context, circuit, module.body()).unwrap();

    let ir = format!("{}", module.as_operation());
    println!("neg_one_coefficient:\n{ir}");
    assert!(
        ir.contains("felt.neg"),
        "Should use felt.neg for -1 coefficient"
    );
    assert!(module.as_operation().verify(), "Module should verify");
}
