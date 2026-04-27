//! End-to-end tests for the EcdsaSecp256r1 verify opcode.
//!
//! Curve constants and opcode constructor only — the verify driver, oracle,
//! and nondet helpers all live in the parent `ecdsa` module.

use acir::FieldElement;
use acir::circuit::Opcode;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::native_types::Witness;
use num_bigint::BigUint;

use super::{
    Curve, HASH_START, OUTPUT_W, PK_X_START, PK_Y_START, PREDICATE_W, SIG_START, byte_inputs,
    run_predicate_false_test, run_result_at_infinity_test, run_verify_test,
    run_verify_test_with_s_mode,
};

/// secp256r1 base field modulus: 2^256 - 2^224 + 2^192 + 2^96 - 1.
fn secp256r1_p() -> BigUint {
    BigUint::parse_bytes(
        b"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
        16,
    )
    .unwrap()
}

fn secp256r1_n() -> BigUint {
    BigUint::parse_bytes(
        b"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        16,
    )
    .unwrap()
}

fn secp256r1_g() -> (BigUint, BigUint) {
    let gx = BigUint::parse_bytes(
        b"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
        16,
    )
    .unwrap();
    let gy = BigUint::parse_bytes(
        b"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
        16,
    )
    .unwrap();
    (gx, gy)
}

fn secp256r1_b() -> BigUint {
    BigUint::parse_bytes(
        b"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
        16,
    )
    .unwrap()
}

fn ecdsa_secp256r1_opcode() -> Opcode<FieldElement> {
    let pk_x: [FunctionInput<FieldElement>; 32] = byte_inputs(PK_X_START, 32).try_into().unwrap();
    let pk_y: [FunctionInput<FieldElement>; 32] = byte_inputs(PK_Y_START, 32).try_into().unwrap();
    let sig: [FunctionInput<FieldElement>; 64] = byte_inputs(SIG_START, 64).try_into().unwrap();
    let hash: [FunctionInput<FieldElement>; 32] = byte_inputs(HASH_START, 32).try_into().unwrap();
    Opcode::BlackBoxFuncCall(BlackBoxFuncCall::EcdsaSecp256r1 {
        public_key_x: Box::new(pk_x),
        public_key_y: Box::new(pk_y),
        signature: Box::new(sig),
        hashed_message: Box::new(hash),
        predicate: FunctionInput::Witness(Witness(PREDICATE_W)),
        output: Witness(OUTPUT_W),
    })
}

fn r1() -> Curve {
    let p = secp256r1_p();
    let a = (&p - 3u32) % &p;
    Curve {
        n: secp256r1_n(),
        g: secp256r1_g(),
        a,
        b: secp256r1_b(),
        p,
        opcode: ecdsa_secp256r1_opcode,
    }
}

#[test]
fn verify_accepts_small_d_k_z() {
    let d = BigUint::from(7u32);
    let k = BigUint::from(1234u32);
    let z = BigUint::from(100u32);
    run_verify_test(&r1(), d, k, z);
}

#[test]
fn verify_rejects_high_s_signature() {
    let d = BigUint::from(7u32);
    let k = BigUint::from(1234u32);
    let z = BigUint::from(100u32);
    run_verify_test_with_s_mode(&r1(), d, k, z, true);
}

#[test]
fn predicate_false_ignores_invalid_inputs() {
    run_predicate_false_test(&r1());
}

#[test]
fn result_at_infinity_returns_false() {
    run_result_at_infinity_test(&r1());
}
