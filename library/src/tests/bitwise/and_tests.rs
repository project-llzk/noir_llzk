use acir::FieldElement;
use acir::circuit::Opcode;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::native_types::Witness;
use llzk::prelude::{LlzkContext, OperationLike};

use super::super::{
    and_blackbox, make_circuit_with_opcodes, translate_single_circuit, wrap_struct_in_module,
};
use super::count_occurrences;

/// Witness-to-witness AND emits bitwise ops and equality constraints.
#[test]
fn and_witness_inputs_emits_correct_ops_and_verifies() {
    let context = LlzkContext::new();
    let circuit = make_circuit_with_opcodes(2, &[0, 1], &[], &[], vec![and_blackbox(0, 1, 8, 2)]);
    let struct_def =
        translate_single_circuit(&context, circuit).expect("translation should succeed");
    let module = wrap_struct_in_module(&context, struct_def);
    let ir = format!("{}", module.as_operation());

    println!("and_witness_inputs:\n{ir}");

    assert!(ir.contains("felt.bit_and"), "should lower to felt.bit_and");
    assert!(
        ir.contains("constrain.eq"),
        "should emit equality constraints"
    );
    // Compute: 2 bit_and ops (raw AND + mask).
    // Constrain: 2 input-mask bit_and ops + 2 input eq + 1 AND + 1 output eq.
    assert_eq!(
        count_occurrences(&ir, "felt.bit_and"),
        5,
        "expected 5 bit_and ops total"
    );
    assert_eq!(
        count_occurrences(&ir, "constrain.eq"),
        3,
        "expected 3 constrain.eq ops total"
    );
    assert_eq!(
        count_occurrences(&ir, "felt.const"),
        2,
        "expected one shared mask constant per phase"
    );

    assert!(module.as_operation().verify(), "module should verify");
}

/// Constant AND still emits the final equality, but skips tautological range constraints.
#[test]
fn and_constant_inputs_emits_felt_constants_and_verifies() {
    let context = LlzkContext::new();

    let opcode = Opcode::BlackBoxFuncCall(BlackBoxFuncCall::AND {
        lhs: FunctionInput::Constant(FieldElement::from(0xFFu128)),
        rhs: FunctionInput::Constant(FieldElement::from(0x0Fu128)),
        num_bits: 8,
        output: Witness(0),
    });
    let circuit = make_circuit_with_opcodes(0, &[], &[], &[], vec![opcode]);
    let struct_def =
        translate_single_circuit(&context, circuit).expect("translation should succeed");
    let module = wrap_struct_in_module(&context, struct_def);
    let ir = format!("{}", module.as_operation());

    println!("and_constant_inputs:\n{ir}");

    // Compute: 2 bit_and ops (raw AND + mask). Constrain: 1 AND + 1 output eq.
    assert_eq!(
        count_occurrences(&ir, "felt.bit_and"),
        3,
        "expected 3 bit_and ops total"
    );
    assert_eq!(
        count_occurrences(&ir, "constrain.eq"),
        1,
        "no bit-width constraints needed for constants that fit"
    );
    assert!(module.as_operation().verify(), "module should verify");
}

/// Mixed witness/constant AND only constrains the witness input's bit-width.
#[test]
fn and_mixed_witness_and_constant_verifies() {
    let context = LlzkContext::new();

    let opcode = Opcode::BlackBoxFuncCall(BlackBoxFuncCall::AND {
        lhs: FunctionInput::Witness(Witness(0)),
        rhs: FunctionInput::Constant(FieldElement::from(0x0Fu128)),
        num_bits: 8,
        output: Witness(1),
    });
    let circuit = make_circuit_with_opcodes(1, &[0], &[], &[], vec![opcode]);
    let struct_def =
        translate_single_circuit(&context, circuit).expect("translation should succeed");
    let module = wrap_struct_in_module(&context, struct_def);
    let ir = format!("{}", module.as_operation());

    println!("and_mixed:\n{ir}");

    // Compute: 2 bit_and ops. Constrain: 1 input-mask bit_and + 1 input eq + 1 AND + 1 output eq.
    assert_eq!(
        count_occurrences(&ir, "felt.bit_and"),
        4,
        "expected 4 bit_and ops total"
    );
    assert_eq!(
        count_occurrences(&ir, "constrain.eq"),
        2,
        "expected 2 constrain.eq ops total"
    );
    assert!(module.as_operation().verify(), "module should verify");
}

/// Zero-bit AND uses a zero mask.
#[test]
fn and_zero_bits_verifies() {
    let context = LlzkContext::new();
    let circuit = make_circuit_with_opcodes(2, &[0, 1], &[], &[], vec![and_blackbox(0, 1, 0, 2)]);
    let struct_def =
        translate_single_circuit(&context, circuit).expect("translation should succeed");
    let module = wrap_struct_in_module(&context, struct_def);
    let ir = format!("{}", module.as_operation());

    println!("and_zero_bits:\n{ir}");

    assert!(
        ir.contains("felt.const  0"),
        "zero-bit mask should be constant 0"
    );
    assert!(module.as_operation().verify(), "module should verify");
}

/// AND verifies across several bit widths.
#[test]
fn and_various_bit_widths_verify() {
    for num_bits in [1, 4, 16, 32, 64, 128] {
        let context = LlzkContext::new();
        let circuit =
            make_circuit_with_opcodes(2, &[0, 1], &[], &[], vec![and_blackbox(0, 1, num_bits, 2)]);
        let struct_def = translate_single_circuit(&context, circuit)
            .unwrap_or_else(|e| panic!("translation failed for {num_bits} bits: {e}"));
        let module = wrap_struct_in_module(&context, struct_def);
        assert!(
            module.as_operation().verify(),
            "module should verify for {num_bits}-bit AND"
        );
    }
}
