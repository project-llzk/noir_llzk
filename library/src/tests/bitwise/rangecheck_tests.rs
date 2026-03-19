use acir::FieldElement;
use acir::circuit::Opcode;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use llzk::prelude::{LlzkContext, OperationLike};

use super::super::{
    make_circuit_with_opcodes, range_blackbox, translate_single_circuit, wrap_struct_in_module,
};
use super::count_occurrences;

/// Witness rangecheck emits one mask and one equality constraint.
#[test]
fn rangecheck_witness_input_emits_constraint_and_verifies() {
    let context = LlzkContext::new();
    let circuit = make_circuit_with_opcodes(0, &[0], &[], &[], vec![range_blackbox(0, 8)]);
    let struct_def =
        translate_single_circuit(&context, circuit).expect("translation should succeed");
    let module = wrap_struct_in_module(&context, struct_def);
    let ir = format!("{}", module.as_operation());

    println!("rangecheck_witness_input:\n{ir}");

    assert_eq!(
        count_occurrences(&ir, "felt.bit_and"),
        1,
        "expected 1 bit_and op total"
    );
    assert_eq!(
        count_occurrences(&ir, "constrain.eq"),
        1,
        "expected 1 constrain.eq op total"
    );
    assert_eq!(
        count_occurrences(&ir, "felt.const"),
        1,
        "expected 1 mask constant"
    );
    assert!(module.as_operation().verify(), "module should verify");
}

/// A constant that already fits in the target bit-width emits no IR in @constrain.
#[test]
fn rangecheck_constant_input_that_fits_emits_no_constraints() {
    let context = LlzkContext::new();
    let opcode = Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
        input: FunctionInput::Constant(FieldElement::from(15u128)),
        num_bits: 8,
    });
    let circuit = make_circuit_with_opcodes(0, &[], &[], &[], vec![opcode]);
    let struct_def =
        translate_single_circuit(&context, circuit).expect("translation should succeed");
    let module = wrap_struct_in_module(&context, struct_def);
    let ir = format!("{}", module.as_operation());

    println!("rangecheck_constant_fit:\n{ir}");

    assert_eq!(
        count_occurrences(&ir, "felt.bit_and"),
        0,
        "expected no bit_and ops"
    );
    assert_eq!(
        count_occurrences(&ir, "constrain.eq"),
        0,
        "expected no constrain.eq ops"
    );
    assert_eq!(
        count_occurrences(&ir, "felt.const"),
        0,
        "expected no constants"
    );
    assert!(module.as_operation().verify(), "module should verify");
}

/// An oversized constant is rejected at translation time.
#[test]
fn rangecheck_constant_input_that_does_not_fit_is_rejected() {
    let context = LlzkContext::new();
    let opcode = Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
        input: FunctionInput::Constant(FieldElement::from(256u128)),
        num_bits: 8,
    });
    let circuit = make_circuit_with_opcodes(0, &[], &[], &[], vec![opcode]);
    let err =
        translate_single_circuit(&context, circuit).expect_err("should reject oversized constant");
    let msg = format!("{err}");
    assert!(
        msg.contains("does not fit"),
        "error should mention 'does not fit', got: {msg}"
    );
}

/// Zero-bit rangecheck uses a zero mask.
#[test]
fn rangecheck_zero_bits_verifies() {
    let context = LlzkContext::new();
    let circuit = make_circuit_with_opcodes(0, &[0], &[], &[], vec![range_blackbox(0, 0)]);
    let struct_def =
        translate_single_circuit(&context, circuit).expect("translation should succeed");
    let module = wrap_struct_in_module(&context, struct_def);
    let ir = format!("{}", module.as_operation());

    println!("rangecheck_zero_bits:\n{ir}");

    assert!(
        ir.contains("felt.const  0"),
        "zero-bit mask should be constant 0"
    );
    assert!(module.as_operation().verify(), "module should verify");
}
