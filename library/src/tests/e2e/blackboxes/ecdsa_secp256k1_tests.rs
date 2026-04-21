//! End-to-end tests for the EcdsaSecp256k1 **stub** opcode.
//!
//! The stub packs `public_key_x` and the first 32 bytes of `signature` into
//! 4 little-endian 64-bit limbs, then drives `multiprec::emit_add_mod_p` on
//! them modulo the secp256k1 base field prime. These tests feed controlled
//! byte inputs and expected nondets (k, r limbs, per-limb carries) to
//! exercise the addition path end-to-end.

use acir::FieldElement;
use acir::circuit::Opcode;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::native_types::Witness;
use llzk_interpreter::Felt;
use num_bigint::{BigInt, BigUint, Sign};

use crate::tests::e2e::{assert_witness_eq, felt_u64, run_e2e_with_nondet};
use crate::tests::make_circuit_with_opcodes;

const PK_X_START: u32 = 0;
const PK_Y_START: u32 = 32;
const SIG_START: u32 = 64;
const HASH_START: u32 = 128;
const PREDICATE_W: u32 = 160;
const OUTPUT_W: u32 = 161;

/// secp256k1 base field modulus: 2^256 - 2^32 - 977.
fn secp256k1_p() -> BigUint {
    let bytes: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF,
        0xFC, 0x2F,
    ];
    BigUint::from_bytes_be(&bytes)
}

fn byte_inputs(start: u32, count: usize) -> Vec<FunctionInput<FieldElement>> {
    (0..count)
        .map(|i| FunctionInput::Witness(Witness(start + i as u32)))
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

/// Converts a BigUint into 32 big-endian byte inputs (zero-padded on the left).
fn biguint_to_be_bytes(value: &BigUint) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    assert!(bytes.len() <= 32, "value exceeds 32 bytes");
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);
    padded
}

fn inputs_from_pk_x_and_sig_r(pk_x: &BigUint, sig_r: &BigUint) -> Vec<crate::tests::e2e::Value> {
    let mut inputs = Vec::with_capacity((PREDICATE_W + 1) as usize);
    inputs.extend(
        biguint_to_be_bytes(pk_x)
            .iter()
            .map(|&b| felt_u64(b as u64)),
    );
    // pk_y (unused): 32 zeros.
    inputs.extend(std::iter::repeat_n(felt_u64(0), 32));
    // signature: first 32 bytes = sig_r (BE), next 32 bytes = zeros.
    inputs.extend(
        biguint_to_be_bytes(sig_r)
            .iter()
            .map(|&b| felt_u64(b as u64)),
    );
    inputs.extend(std::iter::repeat_n(felt_u64(0), 32));
    // hashed_message (unused): 32 zeros.
    inputs.extend(std::iter::repeat_n(felt_u64(0), 32));
    // predicate.
    inputs.push(felt_u64(1));
    inputs
}

/// Computes the nondet sequence that `emit_add_mod_p(a, b, p)` consumes:
/// `[k, r0, r1, r2, r3, c1, c2, c3, c4]` in order of emission.
fn add_mod_p_nondets(a: &BigUint, b: &BigUint, p: &BigUint) -> Vec<Felt> {
    let sum = a + b;
    let k = if &sum >= p { 1u64 } else { 0u64 };
    let r = &sum - k * p;
    mod_p_nondets_from_identity(a, b, &r, p, k, /* b_sign = */ 1)
}

/// Nondet sequence for `emit_sub_mod_p(a, b, p)`:
/// `[k, r0, r1, r2, r3, c1, c2, c3, c4]`.
fn sub_mod_p_nondets(a: &BigUint, b: &BigUint, p: &BigUint) -> Vec<Felt> {
    let (k, r) = if a >= b {
        (0u64, a - b)
    } else {
        (1u64, (a + p) - b)
    };
    mod_p_nondets_from_identity(a, b, &r, p, k, /* b_sign = */ -1)
}

/// Shared nondet builder: replays the per-limb polynomial identity
/// `a_i + b_sign·b_i + kp_sign·k·p_i - r_i + carry_in = carry_out · 2^64`
/// (kp_sign = -b_sign: add uses `-k·p`, sub uses `+k·p`).
fn mod_p_nondets_from_identity(
    a: &BigUint,
    b: &BigUint,
    r: &BigUint,
    p: &BigUint,
    k: u64,
    b_sign: i128,
) -> Vec<Felt> {
    let kp_sign = -b_sign;
    let a_limbs = biguint_to_le_64_limbs(a);
    let b_limbs = biguint_to_le_64_limbs(b);
    let r_limbs = biguint_to_le_64_limbs(r);
    let p_limbs = biguint_to_le_64_limbs(p);
    let two_64 = 1i128 << 64;

    let mut carries = [0i128; 4];
    let mut carry_in: i128 = 0;
    for i in 0..4 {
        let lhs = (a_limbs[i] as i128)
            + b_sign * (b_limbs[i] as i128)
            + kp_sign * (k as i128) * (p_limbs[i] as i128)
            - (r_limbs[i] as i128)
            + carry_in;
        let carry_out = lhs / two_64;
        assert_eq!(
            carry_out * two_64,
            lhs,
            "limb {i} identity does not divide 2^64 (lhs={lhs})"
        );
        carries[i] = carry_out;
        carry_in = carry_out;
    }
    assert_eq!(carry_in, 0, "final carry must be zero");

    let mut nondets = Vec::with_capacity(9);
    nondets.push(Felt::from_u64(k));
    for limb in r_limbs {
        nondets.push(Felt::from_u64(limb));
    }
    for carry in carries {
        nondets.push(signed_felt(carry));
    }
    nondets
}

fn biguint_to_le_64_limbs(value: &BigUint) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    let bytes = value.to_bytes_le();
    for (i, chunk) in bytes.chunks(8).enumerate().take(4) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        limbs[i] = u64::from_le_bytes(buf);
    }
    limbs
}

fn bn254_prime() -> BigUint {
    BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .unwrap()
}

/// Encodes a small signed integer as a felt, wrapping negative values via
/// `p - |x|`.
fn signed_felt(value: i128) -> Felt {
    if value >= 0 {
        Felt::from_u64(value as u64)
    } else {
        Felt::new(bn254_prime() - BigUint::from(value.unsigned_abs()))
    }
}

/// Wider signed felt for values up to ~2^128 (multiplication carries).
fn signed_felt_big(value: &BigInt) -> Felt {
    match value.sign() {
        Sign::Minus => {
            let magnitude = value.magnitude().clone();
            Felt::new(bn254_prime() - magnitude)
        }
        _ => Felt::new(value.magnitude().clone()),
    }
}

/// Nondet sequence for `emit_mul_mod_p(a, b, p)`:
/// `[q0..q3, r0..r3, c1..c6]` in emission order.
fn mul_mod_p_nondets(a: &BigUint, b: &BigUint, p: &BigUint) -> Vec<Felt> {
    let prod = a * b;
    let q = &prod / p;
    let r = &prod - &q * p;

    let a_limbs = biguint_to_le_64_limbs(a);
    let b_limbs = biguint_to_le_64_limbs(b);
    let p_limbs = biguint_to_le_64_limbs(p);
    let q_limbs = biguint_to_le_64_limbs(&q);
    let r_limbs = biguint_to_le_64_limbs(&r);

    // Per-limb polynomial sums: up to 4 * (2^64 - 1)^2 ≈ 2^130, so use BigInt.
    let mut ab_poly: Vec<BigInt> = vec![BigInt::from(0); 7];
    let mut qp_poly: Vec<BigInt> = vec![BigInt::from(0); 7];
    for i in 0..4 {
        for j in 0..4 {
            ab_poly[i + j] += BigInt::from(a_limbs[i]) * BigInt::from(b_limbs[j]);
            qp_poly[i + j] += BigInt::from(q_limbs[i]) * BigInt::from(p_limbs[j]);
        }
    }
    let r_poly: [BigInt; 7] = std::array::from_fn(|k| {
        if k < 4 {
            BigInt::from(r_limbs[k])
        } else {
            BigInt::from(0)
        }
    });

    let two_64 = BigInt::from(1u128 << 64);
    let mut carries: Vec<BigInt> = Vec::with_capacity(6);
    let mut carry_in = BigInt::from(0);
    for k in 0..7 {
        let lhs: BigInt = &ab_poly[k] - &qp_poly[k] - &r_poly[k] + &carry_in;
        if k == 6 {
            assert_eq!(lhs, BigInt::from(0), "final limb must be zero");
        } else {
            let carry_out = &lhs / &two_64;
            let remainder = &lhs - &carry_out * &two_64;
            assert_eq!(remainder, BigInt::from(0), "limb {k} not divisible by 2^64");
            carries.push(carry_out.clone());
            carry_in = carry_out;
        }
    }

    let mut nondets = Vec::with_capacity(4 + 4 + 6);
    for limb in q_limbs {
        nondets.push(Felt::from_u64(limb));
    }
    for limb in r_limbs {
        nondets.push(Felt::from_u64(limb));
    }
    for carry in &carries {
        nondets.push(signed_felt_big(carry));
    }
    nondets
}

/// Nondet sequence for `emit_inv_mod_p(a, p)`: 4 limbs of `a_inv` followed by
/// the 14-element mul nondet sequence proving `a · a_inv ≡ 1 (mod p)`.
fn inv_mod_p_nondets(a: &BigUint, p: &BigUint) -> Vec<Felt> {
    let a_inv = a.modpow(&(p - 2u32), p);
    let a_inv_limbs = biguint_to_le_64_limbs(&a_inv);

    let mut nondets = Vec::with_capacity(4 + 14);
    for limb in a_inv_limbs {
        nondets.push(Felt::from_u64(limb));
    }
    nondets.extend(mul_mod_p_nondets(a, &a_inv, p));
    nondets
}

fn run_with_pk_x_and_sig_r(pk_x: &BigUint, sig_r: &BigUint) {
    let private: Vec<u32> = (0..=PREDICATE_W).collect();
    let circuit = make_circuit_with_opcodes(
        OUTPUT_W,
        &private,
        &[],
        &[OUTPUT_W],
        vec![ecdsa_secp256k1_opcode()],
    );
    let inputs = inputs_from_pk_x_and_sig_r(pk_x, sig_r);
    let p = secp256k1_p();
    let mut nondet = add_mod_p_nondets(pk_x, sig_r, &p);
    nondet.extend(sub_mod_p_nondets(pk_x, sig_r, &p));
    nondet.extend(mul_mod_p_nondets(pk_x, sig_r, &p));
    nondet.extend(inv_mod_p_nondets(pk_x, &p));

    let computed = run_e2e_with_nondet(circuit, &inputs, &nondet);
    assert_witness_eq(&computed.members, &format!("w{OUTPUT_W}"), "1");
}

#[test]
fn stub_add_one_plus_zero() {
    // a must be nonzero (inv(a) is computed by the stub).
    run_with_pk_x_and_sig_r(&BigUint::from(1u32), &BigUint::from(0u32));
}

#[test]
fn stub_add_one_plus_one() {
    run_with_pk_x_and_sig_r(&BigUint::from(1u32), &BigUint::from(1u32));
}

#[test]
fn stub_add_crosses_limb_boundary() {
    let max_limb = BigUint::from(u64::MAX);
    run_with_pk_x_and_sig_r(&max_limb, &BigUint::from(1u32));
}

#[test]
fn stub_add_wraps_modulus_k_equals_one() {
    let p = secp256k1_p();
    let p_minus_one = &p - 1u32;
    run_with_pk_x_and_sig_r(&p_minus_one, &BigUint::from(2u32));
}

#[test]
fn stub_add_full_width_values() {
    // Two arbitrary values close to but below p, picked so the sum is still < 2p.
    let p = secp256k1_p();
    let a = &p / 3u32;
    let b = &p - &a - 7u32;
    run_with_pk_x_and_sig_r(&a, &b);
}

#[test]
fn stub_sub_a_less_than_b_triggers_borrow() {
    // a < b forces sub's k = 1 (r = a - b + p), independently of the add path.
    run_with_pk_x_and_sig_r(&BigUint::from(3u32), &BigUint::from(10u32));
}

#[test]
fn stub_sub_crosses_limb_boundary() {
    // a = 2^64 (into limb[1]), b = 1: a - b leaves limb[0] = 2^64 - 1 with a borrow from limb[1].
    let a = BigUint::from(1u64) << 64;
    run_with_pk_x_and_sig_r(&a, &BigUint::from(1u32));
}
