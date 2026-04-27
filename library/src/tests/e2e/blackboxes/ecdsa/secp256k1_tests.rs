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
    run_verify_test_with_s_mode, secp_add, secp_double,
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

fn secp256k1_2g() -> (BigUint, BigUint) {
    let x = BigUint::parse_bytes(
        b"C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
        16,
    )
    .unwrap();
    let y = BigUint::parse_bytes(
        b"1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A",
        16,
    )
    .unwrap();
    (x, y)
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
fn oracle_double_g_equals_2g() {
    // Cross-check our Rust oracle against the canonical secp256k1 2G vector.
    let p = secp256k1_p();
    let a = BigUint::from(0u32);
    let doubled = secp_double(&secp256k1_g(), &p, &a);
    assert_eq!(doubled, secp256k1_2g());
}

#[test]
fn oracle_scalar_mul_3_equals_3g() {
    // 3·G via double + add against the canonical 3G vector.
    let p = secp256k1_p();
    let a = BigUint::from(0u32);
    let g = secp256k1_g();
    let doubled = secp_double(&g, &p, &a);
    let added = secp_add(&doubled, &g, &p);
    let expected_3g_x = BigUint::parse_bytes(
        b"F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        16,
    )
    .unwrap();
    let expected_3g_y = BigUint::parse_bytes(
        b"388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672",
        16,
    )
    .unwrap();
    assert_eq!(added, (expected_3g_x, expected_3g_y));
}
