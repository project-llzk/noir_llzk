use acir::FieldElement;
use acir::brillig::{BlackBoxOp, HeapVector, IntegerBitSize, MemoryAddress, Opcode as BOp};
use acir::circuit::Opcode;
use acir::circuit::brillig::{BrilligBytecode, BrilligFunctionId, BrilligInputs, BrilligOutputs};
use acir::native_types::{Expression, Witness};

use super::{assert_witness_eq, felt_u64, run_e2e_with_brillig};
use crate::program::translate_program;
use crate::tests::make_circuit_with_opcodes;
use crate::tests::make_program_with_brillig;

fn to_radix_bytecode(radix: u128, num_limbs: u128) -> BrilligBytecode<FieldElement> {
    let input_slot = 1u32;
    let radix_slot = 2u32;
    let num_limbs_slot = 3u32;
    let output_bits_slot = 4u32;
    let output_ptr_slot = 5u32;
    let calldata_size_slot = 6u32;
    let calldata_offset_slot = 7u32;
    let return_size_slot = 8u32;
    let return_ptr_slot = 9u32;
    let ram_base: u128 = 100;

    let ops = vec![
        BOp::Const {
            destination: MemoryAddress::Direct(calldata_size_slot),
            bit_size: acir::brillig::BitSize::Integer(IntegerBitSize::U32),
            value: FieldElement::from(1u128),
        },
        BOp::Const {
            destination: MemoryAddress::Direct(calldata_offset_slot),
            bit_size: acir::brillig::BitSize::Integer(IntegerBitSize::U32),
            value: FieldElement::from(0u128),
        },
        BOp::CalldataCopy {
            destination_address: MemoryAddress::Direct(input_slot),
            size_address: MemoryAddress::Direct(calldata_size_slot),
            offset_address: MemoryAddress::Direct(calldata_offset_slot),
        },
        BOp::Const {
            destination: MemoryAddress::Direct(radix_slot),
            bit_size: acir::brillig::BitSize::Integer(IntegerBitSize::U32),
            value: FieldElement::from(radix),
        },
        BOp::Const {
            destination: MemoryAddress::Direct(num_limbs_slot),
            bit_size: acir::brillig::BitSize::Integer(IntegerBitSize::U32),
            value: FieldElement::from(num_limbs),
        },
        BOp::Const {
            destination: MemoryAddress::Direct(output_bits_slot),
            bit_size: acir::brillig::BitSize::Integer(IntegerBitSize::U1),
            value: FieldElement::from(0u128),
        },
        BOp::Const {
            destination: MemoryAddress::Direct(output_ptr_slot),
            bit_size: acir::brillig::BitSize::Field,
            value: FieldElement::from(ram_base),
        },
        BOp::BlackBox(BlackBoxOp::ToRadix {
            input: MemoryAddress::Direct(input_slot),
            radix: MemoryAddress::Direct(radix_slot),
            output_pointer: MemoryAddress::Direct(output_ptr_slot),
            num_limbs: MemoryAddress::Direct(num_limbs_slot),
            output_bits: MemoryAddress::Direct(output_bits_slot),
        }),
        BOp::Const {
            destination: MemoryAddress::Direct(return_size_slot),
            bit_size: acir::brillig::BitSize::Integer(IntegerBitSize::U32),
            value: FieldElement::from(num_limbs),
        },
        BOp::Const {
            destination: MemoryAddress::Direct(return_ptr_slot),
            bit_size: acir::brillig::BitSize::Integer(IntegerBitSize::U32),
            value: FieldElement::from(ram_base),
        },
        BOp::Stop {
            return_data: HeapVector {
                pointer: MemoryAddress::Direct(return_ptr_slot),
                size: MemoryAddress::Direct(return_size_slot),
            },
        },
    ];

    BrilligBytecode {
        function_name: String::from("to_radix_test"),
        bytecode: ops,
    }
}

fn to_radix_circuit(num_limbs: u128) -> acir::circuit::Circuit<FieldElement> {
    let input_witness = 0u32;
    let out_witnesses: Vec<u32> = (1..=(num_limbs as u32)).collect();

    make_circuit_with_opcodes(
        num_limbs as u32,
        &[input_witness],
        &[],
        &out_witnesses,
        vec![Opcode::BrilligCall {
            id: BrilligFunctionId(0),
            inputs: vec![BrilligInputs::Single(Expression::from(Witness(
                input_witness,
            )))],
            outputs: out_witnesses
                .iter()
                .map(|w| BrilligOutputs::Simple(Witness(*w)))
                .collect(),
            predicate: Expression::one(),
        }],
    )
}

fn expect_to_radix_compute_error(input: u64, radix: u128, num_limbs: u128) {
    let circuit = to_radix_circuit(num_limbs);
    let program =
        make_program_with_brillig(vec![circuit], vec![to_radix_bytecode(radix, num_limbs)]);
    let context = llzk::prelude::LlzkContext::new();
    let module = translate_program(&context, &program).expect("translation should succeed");
    let mut interpreter = super::Interpreter::new(&module);
    let err = interpreter
        .run_compute("Circuit0", &[felt_u64(input)])
        .expect_err("ToRadix should reject values that do not fit");
    assert!(
        err.to_string().contains("assert"),
        "expected bool.assert failure, got: {err}"
    );
}

#[test]
fn to_radix_base10_two_limbs_decomposes_13() {
    let num_limbs = 2u128;
    let circuit = to_radix_circuit(num_limbs);

    let inputs = vec![felt_u64(13)];
    let computed = run_e2e_with_brillig(circuit, vec![to_radix_bytecode(10, num_limbs)], &inputs);

    assert_witness_eq(&computed.members, "w1", "1");
    assert_witness_eq(&computed.members, "w2", "3");
}

#[test]
fn to_radix_base2_four_bits_decomposes_13() {
    let num_limbs = 4u128;
    let circuit = to_radix_circuit(num_limbs);

    let inputs = vec![felt_u64(13)];
    let computed = run_e2e_with_brillig(circuit, vec![to_radix_bytecode(2, num_limbs)], &inputs);

    assert_witness_eq(&computed.members, "w1", "1");
    assert_witness_eq(&computed.members, "w2", "1");
    assert_witness_eq(&computed.members, "w3", "0");
    assert_witness_eq(&computed.members, "w4", "1");
}

#[test]
fn to_radix_base256_three_bytes_decomposes_0x010203() {
    let num_limbs = 3u128;
    let circuit = to_radix_circuit(num_limbs);

    let inputs = vec![felt_u64(0x010203)];
    let computed = run_e2e_with_brillig(circuit, vec![to_radix_bytecode(256, num_limbs)], &inputs);

    assert_witness_eq(&computed.members, "w1", "1");
    assert_witness_eq(&computed.members, "w2", "2");
    assert_witness_eq(&computed.members, "w3", "3");
}

#[test]
fn to_radix_rejects_truncated_decomposition() {
    expect_to_radix_compute_error(100, 10, 1);
}

#[test]
fn to_radix_zero_limbs_accepts_zero() {
    let num_limbs = 0u128;
    let circuit = to_radix_circuit(num_limbs);
    let inputs = vec![felt_u64(0)];

    let computed = run_e2e_with_brillig(circuit, vec![to_radix_bytecode(10, num_limbs)], &inputs);

    assert!(
        !computed.members.contains_key("w1"),
        "zero-limb ToRadix should produce no outputs"
    );
}

#[test]
fn to_radix_zero_limbs_rejects_nonzero() {
    expect_to_radix_compute_error(1, 10, 0);
}
