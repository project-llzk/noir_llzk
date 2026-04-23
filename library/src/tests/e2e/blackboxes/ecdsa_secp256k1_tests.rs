//! End-to-end tests for the EcdsaSecp256k1 **stub** opcode.
//!
//! The stub packs `(pk_x, pk_y)` and the first 64 bytes of `signature` into
//! two secp256k1 affine points, runs `emit_point_add_affine`, and also
//! exercises `emit_inv_mod_p` on `pk_x`. These tests drive the stub with real
//! secp256k1 test vectors (G, 2G, 3G) and derive the full nondet sequence
//! (~100 slots for the curve add + 18 for the standalone inv).

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

/// secp256k1 scalar field order `n`.
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

fn biguint_to_be_bytes(value: &BigUint) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    assert!(bytes.len() <= 32, "value exceeds 32 bytes");
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);
    padded
}

fn inputs_from_pk_sig_z(
    pk: &(BigUint, BigUint),
    sig_r: &BigUint,
    sig_s: &BigUint,
    z: &BigUint,
) -> Vec<crate::tests::e2e::Value> {
    let mut inputs = Vec::with_capacity((PREDICATE_W + 1) as usize);
    inputs.extend(
        biguint_to_be_bytes(&pk.0)
            .iter()
            .map(|&b| felt_u64(b as u64)),
    );
    inputs.extend(
        biguint_to_be_bytes(&pk.1)
            .iter()
            .map(|&b| felt_u64(b as u64)),
    );
    inputs.extend(
        biguint_to_be_bytes(sig_r)
            .iter()
            .map(|&b| felt_u64(b as u64)),
    );
    inputs.extend(
        biguint_to_be_bytes(sig_s)
            .iter()
            .map(|&b| felt_u64(b as u64)),
    );
    inputs.extend(biguint_to_be_bytes(z).iter().map(|&b| felt_u64(b as u64)));
    inputs.push(felt_u64(1));
    inputs
}

// ── Nondet oracles ──────────────────────────────────────────────────────

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

fn signed_felt(value: i128) -> Felt {
    if value >= 0 {
        Felt::from_u64(value as u64)
    } else {
        Felt::new(bn254_prime() - BigUint::from(value.unsigned_abs()))
    }
}

fn signed_felt_big(value: &BigInt) -> Felt {
    match value.sign() {
        Sign::Minus => Felt::new(bn254_prime() - value.magnitude().clone()),
        _ => Felt::new(value.magnitude().clone()),
    }
}

/// `[k, r0..r3, c1..c4, d0..d3, c1..c4]` for `emit_add_mod_p(a, b, p)` —
/// the 9-element identity + the 8-element `r < p` canonicalisation.
fn add_mod_p_nondets(a: &BigUint, b: &BigUint, p: &BigUint) -> Vec<Felt> {
    let sum = a + b;
    let k = if &sum >= p { 1u64 } else { 0u64 };
    let r = &sum - k * p;
    let mut out = mod_p_nondets_from_identity(a, b, &r, p, k, 1);
    out.extend(assert_lt_modulus_nondets(&r, p));
    out
}

/// `[k, r0..r3, c1..c4, d0..d3, c1..c4]` for `emit_sub_mod_p(a, b, p)`.
fn sub_mod_p_nondets(a: &BigUint, b: &BigUint, p: &BigUint) -> Vec<Felt> {
    let (k, r) = if a >= b {
        (0u64, a - b)
    } else {
        (1u64, (a + p) - b)
    };
    let mut out = mod_p_nondets_from_identity(a, b, &r, p, k, -1);
    out.extend(assert_lt_modulus_nondets(&r, p));
    out
}

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
        assert_eq!(carry_out * two_64, lhs, "limb {i} not divisible by 2^64");
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

/// `[q0..q3, r0..r3, c1..c6]` for `emit_mul_mod_p(a, b, p)`.
fn mul_mod_p_nondets(a: &BigUint, b: &BigUint, p: &BigUint) -> Vec<Felt> {
    let prod = a * b;
    let q = &prod / p;
    let r = &prod - &q * p;
    let a_limbs = biguint_to_le_64_limbs(a);
    let b_limbs = biguint_to_le_64_limbs(b);
    let p_limbs = biguint_to_le_64_limbs(p);
    let q_limbs = biguint_to_le_64_limbs(&q);
    let r_limbs = biguint_to_le_64_limbs(&r);
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
    let mut nondets = Vec::with_capacity(14 + 8);
    for limb in q_limbs {
        nondets.push(Felt::from_u64(limb));
    }
    for limb in r_limbs {
        nondets.push(Felt::from_u64(limb));
    }
    for carry in &carries {
        nondets.push(signed_felt_big(carry));
    }
    // Canonicalisation: r < p.
    nondets.extend(assert_lt_modulus_nondets(&r, p));
    nondets
}

/// Full nondet sequence emitted by `emit_point_add_complete` on finite
/// (x1, y1) + (x2, y2): the regular add formula + the internal
/// emit_point_double_complete (for the x1==x2 doubling case) + two
/// limbs_eq_boolean calls (for the x_eq / y_eq selectors). Always emitted
/// regardless of actual cases; garbage is discarded by select.
fn point_add_complete_regular_nondets(
    x1: &BigUint,
    y1: &BigUint,
    x2: &BigUint,
    y2: &BigUint,
    p: &BigUint,
) -> Vec<Felt> {
    let dy = (p + y2 - y1) % p;
    let dx = (p + x2 - x1) % p;
    let zero = BigUint::from(0u32);
    let lambda = if dx == zero {
        zero.clone()
    } else {
        let dx_inv = dx.modpow(&(p - 2u32), p);
        (&dy * &dx_inv) % p
    };
    let lambda_sq = (&lambda * &lambda) % p;
    let x_sum = (x1 + x2) % p;
    let x3 = (p + &lambda_sq - &x_sum) % p;
    let x1_minus_x3 = (p + x1 - &x3) % p;
    let lambda_dx3 = (&lambda * &x1_minus_x3) % p;
    let _y3 = (p + &lambda_dx3 - y1) % p;

    let mut nondet = Vec::new();
    // Regular add.
    nondet.extend(sub_mod_p_nondets(y2, y1, p));
    nondet.extend(sub_mod_p_nondets(x2, x1, p));
    nondet.extend(safe_div_mod_p_nondets(&dy, &dx, p));
    nondet.extend(mul_mod_p_nondets(&lambda, &lambda, p));
    nondet.extend(add_mod_p_nondets(x1, x2, p));
    nondet.extend(sub_mod_p_nondets(&lambda_sq, &x_sum, p));
    nondet.extend(sub_mod_p_nondets(x1, &x3, p));
    nondet.extend(mul_mod_p_nondets(&lambda, &x1_minus_x3, p));
    nondet.extend(sub_mod_p_nondets(&lambda_dx3, y1, p));
    // Doubling branch (emit_point_double_complete on p1).
    nondet.extend(point_double_complete_regular_nondets(x1, y1, p));
    // x_eq / y_eq boolean checks.
    nondet.extend(limbs_eq_boolean_nondets(x1, x2));
    nondet.extend(limbs_eq_boolean_nondets(y1, y2));
    nondet
}

/// `[b_is_zero, inv_hint, q0..q3, q_lt_nondets, mul_nondets]` for
/// `emit_safe_div_mod_p(a, b, p)`. Handles both b ≠ 0 (normal division)
/// and b = 0 (returns garbage q = 0 with b_is_zero = 1).
fn safe_div_mod_p_nondets(a: &BigUint, b: &BigUint, p: &BigUint) -> Vec<Felt> {
    let zero = BigUint::from(0u32);
    let (b_is_zero, inv_hint, q) = if b == &zero {
        (1u64, zero.clone(), zero.clone())
    } else {
        let b_limbs = biguint_to_le_64_limbs(b);
        let b_sum = b_limbs.iter().fold(zero.clone(), |acc, &x| acc + x);
        let p_bn = bn254_prime();
        let inv = b_sum.modpow(&(&p_bn - 2u32), &p_bn);
        let b_inv = b.modpow(&(p - 2u32), p);
        let q_val = (a * &b_inv) % p;
        (0u64, inv, q_val)
    };
    let q_limbs = biguint_to_le_64_limbs(&q);

    let mut nondets = Vec::new();
    nondets.push(Felt::from_u64(b_is_zero));
    nondets.push(Felt::new(inv_hint));
    for limb in q_limbs {
        nondets.push(Felt::from_u64(limb));
    }
    nondets.extend(assert_lt_modulus_nondets(&q, p));
    nondets.extend(mul_mod_p_nondets(b, &q, p));
    nondets
}

/// `[a_inv0..a_inv3, a_inv_lt_nondets, mul_nondets..]` for `emit_inv_mod_p(a, p)`.
/// a_inv is witnessed and canonicalised (+8) before the internal mul verifies
/// `a · a_inv ≡ 1 mod p` (the mul itself also canonicalises its result).
fn inv_mod_p_nondets(a: &BigUint, p: &BigUint) -> Vec<Felt> {
    let a_inv = a.modpow(&(p - 2u32), p);
    let a_inv_limbs = biguint_to_le_64_limbs(&a_inv);
    let mut nondets = Vec::with_capacity(4 + 8 + 22);
    for limb in a_inv_limbs {
        nondets.push(Felt::from_u64(limb));
    }
    nondets.extend(assert_lt_modulus_nondets(&a_inv, p));
    nondets.extend(mul_mod_p_nondets(a, &a_inv, p));
    nondets
}

// ── Rust oracle for secp256k1 affine arithmetic ─────────────────────────

fn secp_add(p1: &(BigUint, BigUint), p2: &(BigUint, BigUint), p: &BigUint) -> (BigUint, BigUint) {
    let (x1, y1) = p1;
    let (x2, y2) = p2;
    let dy = (p + y2 - y1) % p;
    let dx = (p + x2 - x1) % p;
    let dx_inv = dx.modpow(&(p - 2u32), p);
    let lambda = (&dy * &dx_inv) % p;
    let lambda_sq = (&lambda * &lambda) % p;
    let x_sum = (x1 + x2) % p;
    let x3 = (p + &lambda_sq - &x_sum) % p;
    let x1_minus_x3 = (p + x1 - &x3) % p;
    let lambda_dx3 = (&lambda * &x1_minus_x3) % p;
    let y3 = (p + &lambda_dx3 - y1) % p;
    (x3, y3)
}

fn secp_double(pt: &(BigUint, BigUint), p: &BigUint) -> (BigUint, BigUint) {
    let (x, y) = pt;
    let x_sq = (x * x) % p;
    let three_x_sq = (&x_sq * 3u32) % p;
    let two_y = (y * 2u32) % p;
    let two_y_inv = two_y.modpow(&(p - 2u32), p);
    let lambda = (&three_x_sq * &two_y_inv) % p;
    let lambda_sq = (&lambda * &lambda) % p;
    let two_x = (x * 2u32) % p;
    let x3 = (p + &lambda_sq - &two_x) % p;
    let x_minus_x3 = (p + x - &x3) % p;
    let lambda_dx3 = (&lambda * &x_minus_x3) % p;
    let y3 = (p + &lambda_dx3 - y) % p;
    (x3, y3)
}

/// Nondets for the regular doubling portion of `emit_point_double_complete`.
/// Always emitted regardless of whether the input is infinity (select handles
/// the discard). Uses safe_div so y = 0 doesn't fail.
fn point_double_complete_regular_nondets(x: &BigUint, y: &BigUint, p: &BigUint) -> Vec<Felt> {
    let zero = BigUint::from(0u32);
    let x_sq = (x * x) % p;
    let two_x_sq = (&x_sq + &x_sq) % p;
    let three_x_sq = (&two_x_sq + &x_sq) % p;
    let two_y = (y + y) % p;
    let lambda = if two_y == zero {
        zero.clone()
    } else {
        let two_y_inv = two_y.modpow(&(p - 2u32), p);
        (&three_x_sq * &two_y_inv) % p
    };
    let lambda_sq = (&lambda * &lambda) % p;
    let two_x = (x + x) % p;
    let x3 = (p + &lambda_sq - &two_x) % p;
    let x_minus_x3 = (p + x - &x3) % p;
    let lambda_dx3 = (&lambda * &x_minus_x3) % p;

    let mut nondet = Vec::new();
    nondet.extend(mul_mod_p_nondets(x, x, p));
    nondet.extend(add_mod_p_nondets(&x_sq, &x_sq, p));
    nondet.extend(add_mod_p_nondets(&two_x_sq, &x_sq, p));
    nondet.extend(add_mod_p_nondets(y, y, p));
    nondet.extend(safe_div_mod_p_nondets(&three_x_sq, &two_y, p));
    nondet.extend(mul_mod_p_nondets(&lambda, &lambda, p));
    nondet.extend(add_mod_p_nondets(x, x, p));
    nondet.extend(sub_mod_p_nondets(&lambda_sq, &two_x, p));
    nondet.extend(sub_mod_p_nondets(x, &x3, p));
    nondet.extend(mul_mod_p_nondets(&lambda, &x_minus_x3, p));
    nondet.extend(sub_mod_p_nondets(&lambda_dx3, y, p));
    nondet
}

/// Replays `emit_scalar_mul_general(point, bits)` and returns
/// (result_xy, result_is_infinity, nondets). Accepts any 256-bit scalar.
fn scalar_mul_general_execute(
    point: &(BigUint, BigUint),
    bits_lsb_first: &[u8],
    p: &BigUint,
) -> ((BigUint, BigUint), bool, Vec<Felt>) {
    let zero = BigUint::from(0u32);
    let mut acc = (zero.clone(), zero.clone());
    let mut acc_inf = true;
    let mut nondets = Vec::new();
    for &bit in bits_lsb_first.iter().rev() {
        // double_complete: regular formula always emitted on (acc.x, acc.y)
        nondets.extend(point_double_complete_regular_nondets(&acc.0, &acc.1, p));
        let (doubled, doubled_inf) = if acc_inf {
            ((zero.clone(), zero.clone()), true)
        } else {
            (secp_double(&acc, p), false)
        };
        // add_complete: regular formula always emitted on (doubled, point)
        nondets.extend(point_add_complete_regular_nondets(
            &doubled.0, &doubled.1, &point.0, &point.1, p,
        ));
        let (added, added_inf) = if doubled_inf {
            (point.clone(), false)
        } else {
            (secp_add(&doubled, point, p), false)
        };
        if bit == 1 {
            acc = added;
            acc_inf = added_inf;
        } else {
            acc = doubled;
            acc_inf = doubled_inf;
        }
    }
    (acc, acc_inf, nondets)
}

fn biguint_to_bits_256(value: &BigUint) -> [u8; 256] {
    let limbs = biguint_to_le_64_limbs(value);
    std::array::from_fn(|i| ((limbs[i / 64] >> (i % 64)) & 1) as u8)
}

/// Drives the restructured verify body with a full ECDSA-style setup.
/// Given secret scalar `d` and nonce `k`, generates a valid signature for
/// message hash `z` and exercises the complete pipeline.
fn run_verify_test(d: BigUint, k: BigUint, z: BigUint) {
    let p = secp256k1_p();
    let n = secp256k1_n();
    let g = secp256k1_g();

    // Q = d·G
    let d_bits = biguint_to_bits_256(&d);
    let (q, q_inf, _) = scalar_mul_general_execute(&g, &d_bits, &p);
    assert!(!q_inf && q.0 < n, "pk Q.x must be < n for Fr arithmetic");

    // R_k = k·G and sig_r = R_k.x mod n
    let k_bits = biguint_to_bits_256(&k);
    let (r_k, r_k_inf, _) = scalar_mul_general_execute(&g, &k_bits, &p);
    assert!(!r_k_inf, "nonce k must produce a finite point");
    let sig_r = &r_k.0 % &n;
    assert!(sig_r != BigUint::from(0u32), "pick a nonce avoiding R_k.x ≡ 0 mod n");

    // sig_s = k⁻¹ · (z + sig_r·d) mod n
    let k_inv_n = k.modpow(&(&n - 2u32), &n);
    let sig_s = (&k_inv_n * ((&z + &sig_r * &d) % &n)) % &n;
    assert!(sig_s != BigUint::from(0u32), "sig_s must be nonzero");

    // u1, u2
    let s_inv = sig_s.modpow(&(&n - 2u32), &n);
    let u1_target = (&z * &s_inv) % &n;
    let u2_target = (&sig_r * &s_inv) % &n;

    // Replay the two scalar muls and the point add.
    let u1_bits = biguint_to_bits_256(&u1_target);
    let u2_bits = biguint_to_bits_256(&u2_target);
    let (r1, r1_inf, u1g_nondets) = scalar_mul_general_execute(&g, &u1_bits, &p);
    let (r2, r2_inf, u2q_nondets) = scalar_mul_general_execute(&q, &u2_bits, &p);
    let r_add_nondets =
        point_add_complete_regular_nondets(&r1.0, &r1.1, &r2.0, &r2.1, &p);
    let r_final = secp_add(&r1, &r2, &p);
    assert!(!r1_inf && !r2_inf, "u1·G and u2·Q must both be finite for this stub");
    assert!(r_final == r_k, "u1·G + u2·Q should equal k·G");
    assert!(r_final.0 < n, "R.x must be < n for the k=0 reduction path");

    // Build circuit + inputs.
    let private: Vec<u32> = (0..=PREDICATE_W).collect();
    let circuit = make_circuit_with_opcodes(
        OUTPUT_W,
        &private,
        &[],
        &[OUTPUT_W],
        vec![ecdsa_secp256k1_opcode()],
    );
    let inputs = inputs_from_pk_sig_z(&q, &sig_r, &sig_s, &z);

    // Nondet sequence in emission order.
    let mut nondet = Vec::new();

    // Q on curve: y² = x³ + 7 (mod p).
    let x_sq = (&q.0 * &q.0) % &p;
    let x_cubed = (&x_sq * &q.0) % &p;
    nondet.extend(mul_mod_p_nondets(&q.0, &q.0, &p));
    nondet.extend(mul_mod_p_nondets(&x_sq, &q.0, &p));
    nondet.extend(add_mod_p_nondets(&x_cubed, &BigUint::from(7u32), &p));
    nondet.extend(mul_mod_p_nondets(&q.1, &q.1, &p));

    nondet.extend(assert_lt_modulus_nondets(&sig_r, &n));
    nondet.extend(assert_lt_modulus_nondets(&sig_s, &n));
    nondet.extend(limbs_eq_boolean_nondets(&sig_r, &BigUint::from(0u32)));
    nondet.extend(inv_mod_p_nondets(&sig_s, &n));
    nondet.extend(mul_mod_p_nondets(&z, &s_inv, &n));
    nondet.extend(mul_mod_p_nondets(&sig_r, &s_inv, &n));
    nondet.extend(bit_decompose_256_nondets(&u1_target));
    nondet.extend(u1g_nondets);
    nondet.extend(bit_decompose_256_nondets(&u2_target));
    nondet.extend(u2q_nondets);
    nondet.extend(r_add_nondets);
    nondet.extend(add_mod_p_nondets(&r_final.0, &BigUint::from(0u32), &n));
    nondet.extend(assert_lt_modulus_nondets(&sig_r, &n));
    nondet.extend(limbs_eq_boolean_nondets(&sig_r, &sig_r));

    let computed = run_e2e_with_nondet(circuit, &inputs, &nondet);
    assert_witness_eq(&computed.members, &format!("w{OUTPUT_W}"), "1");
}

/// Nondet sequence for `emit_limbs_eq_boolean(a, b)`: `[is_eq, inv_hint]`.
/// When a == b, `is_eq = 1` and inv_hint is ignored (use 0).
/// When a != b, `is_eq = 0` and inv_hint = (Σ (a_i - b_i)²)⁻¹ mod p_bn254.
fn limbs_eq_boolean_nondets(a: &BigUint, b: &BigUint) -> Vec<Felt> {
    if a == b {
        vec![Felt::from_u64(1), Felt::from_u64(0)]
    } else {
        let a_limbs = biguint_to_le_64_limbs(a);
        let b_limbs = biguint_to_le_64_limbs(b);
        let p_bn = bn254_prime();
        let mut sum_sq = BigUint::from(0u32);
        for i in 0..4 {
            let d = a_limbs[i].abs_diff(b_limbs[i]);
            let d_bu = BigUint::from(d);
            sum_sq += &d_bu * &d_bu;
        }
        let inv = sum_sq.modpow(&(&p_bn - 2u32), &p_bn);
        vec![Felt::from_u64(0), Felt::new(inv)]
    }
}

/// Nondet sequence for `emit_assert_lt_modulus(value, modulus)`:
/// `[d0..d3, c1..c4]` where `d = modulus - 1 - value`.
fn assert_lt_modulus_nondets(value: &BigUint, modulus: &BigUint) -> Vec<Felt> {
    assert!(value < modulus, "value must be < modulus");
    let d = modulus - 1u32 - value;
    let d_limbs = biguint_to_le_64_limbs(&d);
    let m_minus_1 = modulus - 1u32;
    let m_limbs = biguint_to_le_64_limbs(&m_minus_1);
    let v_limbs = biguint_to_le_64_limbs(value);

    // Replay: v_i + d_i - m_i + carry_in = carry_out · 2^64.
    let two_64 = 1i128 << 64;
    let mut carries = [0i128; 4];
    let mut carry_in: i128 = 0;
    for i in 0..4 {
        let lhs = (v_limbs[i] as i128) + (d_limbs[i] as i128) - (m_limbs[i] as i128) + carry_in;
        let carry_out = lhs / two_64;
        assert_eq!(carry_out * two_64, lhs, "limb {i} not divisible by 2^64");
        carries[i] = carry_out;
        carry_in = carry_out;
    }
    assert_eq!(carry_in, 0, "final carry must be zero");

    let mut nondets = Vec::with_capacity(8);
    for limb in d_limbs {
        nondets.push(Felt::from_u64(limb));
    }
    for carry in carries {
        nondets.push(signed_felt(carry));
    }
    nondets
}

/// Emits the 256 nondet bit values for `emit_bit_decompose_256(value)`.
fn bit_decompose_256_nondets(value: &BigUint) -> Vec<Felt> {
    let limbs = biguint_to_le_64_limbs(value);
    let mut bits = Vec::with_capacity(256);
    for limb in limbs {
        for i in 0..64 {
            bits.push(Felt::from_u64((limb >> i) & 1));
        }
    }
    bits
}

#[test]
fn stub_verify_accepts_valid_signature() {
    // Proper ECDSA setup: secret d, nonce k, message hash z generate a valid
    // (pk, sig_r, sig_s) that the stub's u1·G + u2·Q = R verify accepts.
    let d = BigUint::from(7u32);
    let k = BigUint::from(1234u32);
    let z = BigUint::from(100u32);
    run_verify_test(d, k, z);
}

#[test]
fn oracle_double_g_equals_2g() {
    // Cross-check our Rust oracle against the canonical secp256k1 2G vector.
    let p = secp256k1_p();
    let doubled = secp_double(&secp256k1_g(), &p);
    assert_eq!(doubled, secp256k1_2g());
}

#[test]
fn oracle_scalar_mul_3_equals_3g() {
    // Cross-check scalar mul oracle: 3·G should equal the canonical 3G vector.
    let p = secp256k1_p();
    // Replay the algorithm in Rust: start with acc = G, 1 iteration (bit = 1).
    let g = secp256k1_g();
    let doubled = secp_double(&g, &p);
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
