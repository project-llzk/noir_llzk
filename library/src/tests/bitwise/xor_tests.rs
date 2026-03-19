use acir::FieldElement;
use acir::circuit::Opcode;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::native_types::Witness;
use llzk::prelude::{LlzkContext, OperationLike};

use super::super::{
    make_circuit_with_opcodes, translate_single_circuit, wrap_struct_in_module, xor_blackbox,
};
use super::count_occurrences;

/// Witness-to-witness XOR emits bitwise ops and equality constraints.
#[test]
fn xor_witness_inputs_emits_correct_ops_and_verifies() {
    let context = LlzkContext::new();
    let circuit = make_circuit_with_opcodes(2, &[0, 1], &[], &[], vec![xor_blackbox(0, 1, 8, 2)]);
    let struct_def =
        translate_single_circuit(&context, circuit).expect("translation should succeed");
    let module = wrap_struct_in_module(&context, struct_def);
    let ir = format!("{}", module.as_operation());

    println!("xor_witness_inputs:\n{ir}");

    assert!(ir.contains("felt.bit_xor"), "should lower to felt.bit_xor");
    assert!(
        ir.contains("constrain.eq"),
        "should emit equality constraints"
    );
    // Compute: 1 XOR.
    // Constrain: 1 XOR + 1 output eq (inputs trusted via prior RANGE).
    assert_eq!(
        count_occurrences(&ir, "felt.bit_xor"),
        2,
        "expected 2 bit_xor ops total"
    );
    assert_eq!(
        count_occurrences(&ir, "felt.bit_and"),
        0,
        "expected no bit_and ops"
    );
    assert_eq!(
        count_occurrences(&ir, "constrain.eq"),
        1,
        "expected 1 constrain.eq op total"
    );
    assert_eq!(
        count_occurrences(&ir, "felt.const"),
        0,
        "expected no constants for witness inputs"
    );

    assert!(module.as_operation().verify(), "module should verify");
}

/// Constant XOR emits the expected compute and constrain ops.
#[test]
fn xor_constant_inputs_emits_felt_constants_and_verifies() {
    let context = LlzkContext::new();

    let opcode = Opcode::BlackBoxFuncCall(BlackBoxFuncCall::XOR {
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

    println!("xor_constant_inputs:\n{ir}");

    // Compute: 1 XOR.
    // Constrain: 1 XOR + 1 output eq (inputs trusted via prior RANGE).
    assert_eq!(
        count_occurrences(&ir, "felt.bit_xor"),
        2,
        "expected 2 bit_xor ops total"
    );
    assert_eq!(
        count_occurrences(&ir, "felt.bit_and"),
        0,
        "expected no bit_and ops"
    );
    assert_eq!(
        count_occurrences(&ir, "constrain.eq"),
        1,
        "no bit-width constraints needed for constants that fit"
    );
    assert!(module.as_operation().verify(), "module should verify");
}

/// Mixed witness/constant XOR trusts prior RANGE constraints.
#[test]
fn xor_mixed_witness_and_constant_verifies() {
    let context = LlzkContext::new();

    let opcode = Opcode::BlackBoxFuncCall(BlackBoxFuncCall::XOR {
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

    println!("xor_mixed:\n{ir}");

    // Compute: 1 XOR.
    // Constrain: 1 XOR + 1 output eq (inputs trusted via prior RANGE).
    assert_eq!(
        count_occurrences(&ir, "felt.bit_xor"),
        2,
        "expected 2 bit_xor ops total"
    );
    assert_eq!(
        count_occurrences(&ir, "felt.bit_and"),
        0,
        "expected no bit_and ops"
    );
    assert_eq!(
        count_occurrences(&ir, "constrain.eq"),
        1,
        "expected 1 constrain.eq op total"
    );
    assert!(module.as_operation().verify(), "module should verify");
}

/// Zero-bit XOR still verifies.
#[test]
fn xor_zero_bits_verifies() {
    let context = LlzkContext::new();
    let circuit = make_circuit_with_opcodes(2, &[0, 1], &[], &[], vec![xor_blackbox(0, 1, 0, 2)]);
    let struct_def =
        translate_single_circuit(&context, circuit).expect("translation should succeed");
    let module = wrap_struct_in_module(&context, struct_def);
    let ir = format!("{}", module.as_operation());

    println!("xor_zero_bits:\n{ir}");

    assert!(module.as_operation().verify(), "module should verify");
}

/// XOR verifies across several bit widths.
#[test]
fn xor_various_bit_widths_verify() {
    for num_bits in [1, 4, 16, 32, 64, 128] {
        let context = LlzkContext::new();
        let circuit =
            make_circuit_with_opcodes(2, &[0, 1], &[], &[], vec![xor_blackbox(0, 1, num_bits, 2)]);
        let struct_def = translate_single_circuit(&context, circuit)
            .unwrap_or_else(|e| panic!("translation failed for {num_bits} bits: {e}"));
        let module = wrap_struct_in_module(&context, struct_def);
        assert!(
            module.as_operation().verify(),
            "module should verify for {num_bits}-bit XOR"
        );
    }
}
