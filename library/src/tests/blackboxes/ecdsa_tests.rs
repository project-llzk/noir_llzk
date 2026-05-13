use acir::FieldElement;
use acir::brillig::{
    BitSize, BlackBoxOp, HeapArray, HeapVector, IntegerBitSize, MemoryAddress,
    Opcode as BrilligOpcode,
};
use acir::circuit::Opcode;
use acir::circuit::brillig::{BrilligBytecode, BrilligFunctionId};
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::native_types::{Expression, Witness};
use llzk::prelude::{LlzkContext, Module};

use crate::program::translate_program;
use crate::tests::{
    count_occurrences, make_circuit_with_opcodes, make_program_with_brillig,
    translate_single_circuit_module,
};

const PK_X_START: u32 = 0;
const PK_Y_START: u32 = 32;
const SIG_START: u32 = 64;
const HASH_START: u32 = 128;
const PREDICATE_W: u32 = 160;
const OUTPUT_W: u32 = 161;

fn byte_inputs(start: u32, len: usize) -> Vec<FunctionInput<FieldElement>> {
    (start..start + len as u32)
        .map(|i| FunctionInput::Witness(Witness(i)))
        .collect()
}

fn ecdsa_secp256k1_opcode() -> Opcode<FieldElement> {
    let pk_x: [FunctionInput<FieldElement>; 32] = byte_inputs(PK_X_START, 32).try_into().unwrap();
    let pk_y: [FunctionInput<FieldElement>; 32] = byte_inputs(PK_Y_START, 32).try_into().unwrap();
    let sig: [FunctionInput<FieldElement>; 64] = byte_inputs(SIG_START, 64).try_into().unwrap();
    let hash: [FunctionInput<FieldElement>; 32] = byte_inputs(HASH_START, 32).try_into().unwrap();
    Opcode::BlackBoxFuncCall(BlackBoxFuncCall::EcdsaSecp256k1 {
        public_key_x: Box::new(pk_x),
        public_key_y: Box::new(pk_y),
        signature: Box::new(sig),
        hashed_message: Box::new(hash),
        predicate: FunctionInput::Witness(Witness(PREDICATE_W)),
        output: Witness(OUTPUT_W),
    })
}

fn ecdsa_secp256k1_brillig_blackbox() -> BrilligOpcode<FieldElement> {
    BrilligOpcode::BlackBox(BlackBoxOp::EcdsaSecp256k1 {
        hashed_msg: heap_array(10, 32),
        public_key_x: heap_array(11, 32),
        public_key_y: heap_array(12, 32),
        signature: heap_array(13, 64),
        result: MemoryAddress::Direct(20),
    })
}

fn heap_array(pointer: u32, size: u32) -> HeapArray {
    HeapArray {
        pointer: MemoryAddress::Direct(pointer),
        size: acir::brillig::lengths::SemiFlattenedLength(size),
    }
}

fn const_int(dst: u32, value: u128) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Const {
        destination: MemoryAddress::Direct(dst),
        bit_size: BitSize::Integer(IntegerBitSize::U32),
        value: FieldElement::from(value),
    }
}

fn brillig_stop() -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Stop {
        return_data: HeapVector {
            pointer: MemoryAddress::Direct(0),
            size: MemoryAddress::Direct(0),
        },
    }
}

fn brillig_bytecode(ops: Vec<BrilligOpcode<FieldElement>>) -> BrilligBytecode<FieldElement> {
    let mut bytecode = Vec::with_capacity(ops.len() + 2);
    bytecode.push(const_int(0, 0));
    bytecode.push(BrilligOpcode::CalldataCopy {
        destination_address: MemoryAddress::Direct(0),
        size_address: MemoryAddress::Direct(0),
        offset_address: MemoryAddress::Direct(0),
    });
    bytecode.extend(ops);

    BrilligBytecode {
        function_name: "test_brillig".to_string(),
        bytecode,
    }
}

fn brillig_call_opcode(id: u32) -> Opcode<FieldElement> {
    Opcode::BrilligCall {
        id: BrilligFunctionId(id),
        inputs: vec![],
        outputs: vec![],
        predicate: Expression::one(),
    }
}

fn assert_module_verifies(module: &Module<'_>) {
    llzk::operation::verify_operation_with_diags(&module.as_operation())
        .expect("Module should verify");
}

#[test]
fn ecdsa_acir_compute_and_constrain_call_shared_compute_helper() {
    let context = LlzkContext::new();
    let private: Vec<u32> = (PK_X_START..=PREDICATE_W).collect();
    let circuit = make_circuit_with_opcodes(
        OUTPUT_W,
        &private,
        &[],
        &[OUTPUT_W],
        vec![ecdsa_secp256k1_opcode()],
    );

    let module =
        translate_single_circuit_module(&context, circuit).expect("translation should pass");
    let ir = format!("{}", module.as_operation());

    assert_module_verifies(&module);
    assert_eq!(
        count_occurrences(&ir, "function.def @ecdsa_secp256k1_compute"),
        1
    );
    assert_eq!(
        count_occurrences(&ir, "function.call @ecdsa_secp256k1_compute"),
        2,
        "ACIR compute and constrain should call the shared ECDSA helper"
    );
}

#[test]
fn ecdsa_acir_and_brillig_share_compute_helper() {
    let context = LlzkContext::new();
    let private: Vec<u32> = (PK_X_START..=PREDICATE_W).collect();
    let circuit = make_circuit_with_opcodes(
        OUTPUT_W,
        &private,
        &[],
        &[OUTPUT_W],
        vec![ecdsa_secp256k1_opcode(), brillig_call_opcode(0)],
    );
    let brillig_body = vec![
        const_int(10, 100),
        const_int(11, 200),
        const_int(12, 300),
        const_int(13, 400),
        ecdsa_secp256k1_brillig_blackbox(),
        brillig_stop(),
    ];
    let program = make_program_with_brillig(vec![circuit], vec![brillig_bytecode(brillig_body)]);

    let module = translate_program(&context, &program).expect("translation should pass");
    let ir = format!("{}", module.as_operation());

    assert_module_verifies(&module);
    assert_eq!(
        count_occurrences(&ir, "function.def @ecdsa_secp256k1_compute"),
        1,
        "ACIR and Brillig ECDSA should share one compute helper definition"
    );
    assert_eq!(
        count_occurrences(&ir, "function.call @ecdsa_secp256k1_compute"),
        3,
        "ACIR compute, ACIR constrain, and Brillig should call the shared helper"
    );
}

#[test]
fn ecdsa_compute_uses_module_level_multiprec_helpers() {
    let context = LlzkContext::new();
    let private: Vec<u32> = (PK_X_START..=PREDICATE_W).collect();
    let circuit = make_circuit_with_opcodes(
        OUTPUT_W,
        &private,
        &[],
        &[OUTPUT_W],
        vec![ecdsa_secp256k1_opcode()],
    );

    let module =
        translate_single_circuit_module(&context, circuit).expect("translation should pass");
    let ir = format!("{}", module.as_operation());

    assert_module_verifies(&module);
    assert_eq!(
        count_occurrences(&ir, "function.def @ecdsa_secp256k1_mul_mod_n"),
        1,
        "ECDSA should emit the scalar-field multiplication helper once"
    );
    assert_eq!(
        count_occurrences(&ir, "function.def @ecdsa_secp256k1_mul_mod_p"),
        1,
        "ECDSA should emit the base-field multiplication helper once"
    );
    assert!(
        count_occurrences(&ir, "function.call @ecdsa_secp256k1_mul_mod_n") > 0,
        "ECDSA compute should call the shared scalar-field multiplication helper"
    );
    assert!(
        count_occurrences(&ir, "function.call @ecdsa_secp256k1_mul_mod_p") > 0,
        "ECDSA compute should call the shared base-field multiplication helper"
    );
}
