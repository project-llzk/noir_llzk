//! End-to-end tests for the EcdsaSecp256k1 verify opcode.
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

/// secp256k1 base field modulus: 2^256 - 2^32 - 977.
fn secp256k1_p() -> BigUint {
    let bytes: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF,
        0xFC, 0x2F,
    ];
    BigUint::from_bytes_be(&bytes)
}

fn secp256k1_n() -> BigUint {
    BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .unwrap()
}

fn secp256k1_g() -> (BigUint, BigUint) {
    let gx = BigUint::parse_bytes(
        b"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        16,
    )
    .unwrap();
    let gy = BigUint::parse_bytes(
        b"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
        16,
    )
    .unwrap();
    (gx, gy)
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

fn k1() -> Curve {
    Curve {
        p: secp256k1_p(),
        n: secp256k1_n(),
        g: secp256k1_g(),
        a: BigUint::from(0u32),
        b: BigUint::from(7u32),
        opcode: ecdsa_secp256k1_opcode,
    }
}

#[test]
fn verify_accepts_small_d_k_z() {
    let d = BigUint::from(7u32);
    let k = BigUint::from(1234u32);
    let z = BigUint::from(100u32);
    run_verify_test(&k1(), d, k, z);
}

#[test]
fn verify_rejects_high_s_signature() {
    let d = BigUint::from(7u32);
    let k = BigUint::from(1234u32);
    let z = BigUint::from(100u32);
    run_verify_test_with_s_mode(&k1(), d, k, z, true);
}

#[test]
fn predicate_false_ignores_invalid_inputs() {
    run_predicate_false_test(&k1());
}

#[test]
fn result_at_infinity_returns_false() {
    run_result_at_infinity_test(&k1());
}

#[test]
fn verify_accepts_larger_d_k_z() {
    let d = BigUint::parse_bytes(
        b"DEADBEEFCAFE0000000000000000000000000000000000000000000000000001",
        16,
    )
    .unwrap();
    let k = BigUint::parse_bytes(
        b"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        16,
    )
    .unwrap();
    let z = BigUint::parse_bytes(
        b"AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899",
        16,
    )
    .unwrap();
    let n = secp256k1_n();
    run_verify_test(&k1(), &d % &n, &k % &n, &z % &n);
}

#[test]
fn verify_accepts_hash_reduced_mod_n() {
    let n = secp256k1_n();
    let d = BigUint::from(7u32);
    let k = BigUint::from(1234u32);
    let z = &n + 100u32;
    run_verify_test(&k1(), d, k, z);
}

#[test]
fn verify_accepts_private_key_n_minus_one() {
    let n = secp256k1_n();
    let d = &n - 1u32;
    let k = BigUint::from(1234u32);
    let z = BigUint::from(100u32);
    run_verify_test(&k1(), d, k, z);
}
