use acir::{
    FieldElement,
    circuit::Opcode,
    native_types::{Expression, Witness},
};

use crate::{
    Driver,
    tests::{TestConfig, make_circuit_with_opcodes, make_program, print_and_verify_module},
};

/// The synthetic output is fixed, and the original private-input constraint
/// remains enforced rather than being replaced by the unit constraint.
#[test]
fn output_free_entry_preserves_constraints() {
    use acir::AcirField;
    use llzk_interpreter::{Felt, Interpreter, Value};

    let driver = Driver::new(&TestConfig);
    let circuit = make_circuit_with_opcodes(
        0,
        &[0],
        &[],
        &[],
        vec![Opcode::AssertZero(Expression {
            mul_terms: vec![],
            linear_combinations: vec![(FieldElement::one(), Witness(0))],
            q_c: -FieldElement::from(7u128),
        })],
    );
    let module = driver.translate(&make_program(vec![circuit])).unwrap();
    print_and_verify_module(&module, "output_free_entry_preserves_constraints");
    let mut interpreter = Interpreter::new(&module);
    let inputs = [Value::Felt(Felt::from_u64(7))];
    let computed = interpreter.run_compute("Circuit0", &inputs).unwrap();
    assert_eq!(
        computed.members.len(),
        1,
        "private input must not be exposed"
    );
    assert_eq!(
        computed.members["__pcl_unit"],
        Value::Felt(Felt::from_u64(0))
    );
    interpreter
        .run_constrain("Circuit0", computed.clone(), &inputs)
        .unwrap();

    let mut corrupted = computed.clone();
    corrupted
        .members
        .insert("__pcl_unit".into(), Value::Felt(Felt::from_u64(1)));
    assert!(
        interpreter
            .run_constrain("Circuit0", corrupted, &inputs)
            .is_err()
    );
    assert!(
        interpreter
            .run_constrain("Circuit0", computed, &[Value::Felt(Felt::from_u64(8))])
            .is_err()
    );
}
