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

/// `[q_div0..q_div3, q_lt_d..q_lt_c, mul_nondets..]` for `emit_div_mod_p(a, b, p)`.
/// `q = a · b⁻¹ mod p`; emitted quotient is canonicalised (+8), then the inner
/// mul proves `b · q = a mod p` and itself canonicalises its output.
fn div_mod_p_nondets(a: &BigUint, b: &BigUint, p: &BigUint) -> Vec<Felt> {
    let b_inv = b.modpow(&(p - 2u32), p);
    let q = (a * &b_inv) % p;
    let q_limbs = biguint_to_le_64_limbs(&q);
    let mut nondets = Vec::with_capacity(4 + 8 + 22);
    for limb in q_limbs {
        nondets.push(Felt::from_u64(limb));
    }
    nondets.extend(assert_lt_modulus_nondets(&q, p));
    nondets.extend(mul_mod_p_nondets(b, &q, p));
    nondets
}

/// Nondets for the regular-add portion of `emit_point_add_complete` on
/// inputs (x1, y1, x2, y2) — identical to the affine add formula, just
/// threaded through `emit_safe_div_mod_p` instead of `emit_div_mod_p`.
fn point_add_complete_regular_nondets(
    x1: &BigUint,
    y1: &BigUint,
    x2: &BigUint,
    y2: &BigUint,
    p: &BigUint,
) -> Vec<Felt> {
    let dy = (p + y2 - y1) % p;
    let dx = (p + x2 - x1) % p;
    let dx_inv = dx.modpow(&(p - 2u32), p);
    let lambda = (&dy * &dx_inv) % p;
    let lambda_sq = (&lambda * &lambda) % p;
    let x_sum = (x1 + x2) % p;
    let x3 = (p + &lambda_sq - &x_sum) % p;
    let x1_minus_x3 = (p + x1 - &x3) % p;
    let lambda_dx3 = (&lambda * &x1_minus_x3) % p;
    let _y3 = (p + &lambda_dx3 - y1) % p;

    let mut nondet = Vec::new();
    nondet.extend(sub_mod_p_nondets(y2, y1, p));
    nondet.extend(sub_mod_p_nondets(x2, x1, p));
    nondet.extend(safe_div_mod_p_nondets(&dy, &dx, p));
    nondet.extend(mul_mod_p_nondets(&lambda, &lambda, p));
    nondet.extend(add_mod_p_nondets(x1, x2, p));
    nondet.extend(sub_mod_p_nondets(&lambda_sq, &x_sum, p));
    nondet.extend(sub_mod_p_nondets(x1, &x3, p));
    nondet.extend(mul_mod_p_nondets(&lambda, &x1_minus_x3, p));
    nondet.extend(sub_mod_p_nondets(&lambda_dx3, y1, p));
    nondet
}

/// `[b_is_zero, inv_hint, q0..q3, q_lt_nondets, mul_nondets]` for
/// `emit_safe_div_mod_p(a, b, p)`. `b` must be nonzero for this oracle path.
fn safe_div_mod_p_nondets(a: &BigUint, b: &BigUint, p: &BigUint) -> Vec<Felt> {
    assert!(b != &BigUint::from(0u32), "only the nonzero-b path is wired up");
    // b_sum = Σ b_i (no wraparound, canonical).
    let b_limbs = biguint_to_le_64_limbs(b);
    let b_sum = b_limbs.iter().fold(BigUint::from(0u32), |acc, &x| acc + x);
    let p_bn = bn254_prime();
    let inv_hint = b_sum.modpow(&(&p_bn - 2u32), &p_bn);

    let b_inv = b.modpow(&(p - 2u32), p);
    let q = (a * &b_inv) % p;
    let q_limbs = biguint_to_le_64_limbs(&q);

    let mut nondets = Vec::new();
    nondets.push(Felt::from_u64(0)); // b_is_zero = 0
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

/// Full nondet sequence for `emit_point_add_affine(p1, p2)`, in emission order.
/// ~100 slots: 4 subs, 1 add, 1 div, 2 muls.
fn point_add_affine_nondets(
    p1: &(BigUint, BigUint),
    p2: &(BigUint, BigUint),
    p: &BigUint,
) -> Vec<Felt> {
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
    let _y3 = (p + &lambda_dx3 - y1) % p;

    let mut nondets = Vec::with_capacity(100);
    nondets.extend(sub_mod_p_nondets(y2, y1, p));
    nondets.extend(sub_mod_p_nondets(x2, x1, p));
    nondets.extend(div_mod_p_nondets(&dy, &dx, p));
    nondets.extend(mul_mod_p_nondets(&lambda, &lambda, p));
    nondets.extend(add_mod_p_nondets(x1, x2, p));
    nondets.extend(sub_mod_p_nondets(&lambda_sq, &x_sum, p));
    nondets.extend(sub_mod_p_nondets(x1, &x3, p));
    nondets.extend(mul_mod_p_nondets(&lambda, &x1_minus_x3, p));
    nondets.extend(sub_mod_p_nondets(&lambda_dx3, y1, p));
    nondets
}

/// Nondet sequence for `emit_point_double(p)` — ~123 slots: 1 mul (x²),
/// 4 adds (2x², 3x², 2y, 2x), 1 div (λ), 1 mul (λ²), 3 subs (x3, x-x3, y3),
/// 1 mul (λ·(x-x3)).
fn point_double_nondets(p_pt: &(BigUint, BigUint), p: &BigUint) -> Vec<Felt> {
    let (x, y) = p_pt;
    let x_sq = (x * x) % p;
    let two_x_sq = (&x_sq + &x_sq) % p;
    let three_x_sq = (&two_x_sq + &x_sq) % p;
    let two_y = (y + y) % p;
    let two_y_inv = two_y.modpow(&(p - 2u32), p);
    let lambda = (&three_x_sq * &two_y_inv) % p;
    let lambda_sq = (&lambda * &lambda) % p;
    let two_x = (x + x) % p;
    let x3 = (p + &lambda_sq - &two_x) % p;
    let x_minus_x3 = (p + x - &x3) % p;
    let lambda_dx3 = (&lambda * &x_minus_x3) % p;
    let _y3 = (p + &lambda_dx3 - y) % p;

    let mut nondets = Vec::with_capacity(123);
    nondets.extend(mul_mod_p_nondets(x, x, p));
    nondets.extend(add_mod_p_nondets(&x_sq, &x_sq, p));
    nondets.extend(add_mod_p_nondets(&two_x_sq, &x_sq, p));
    nondets.extend(add_mod_p_nondets(y, y, p));
    nondets.extend(div_mod_p_nondets(&three_x_sq, &two_y, p));
    nondets.extend(mul_mod_p_nondets(&lambda, &lambda, p));
    nondets.extend(add_mod_p_nondets(x, x, p));
    nondets.extend(sub_mod_p_nondets(&lambda_sq, &two_x, p));
    nondets.extend(sub_mod_p_nondets(x, &x3, p));
    nondets.extend(mul_mod_p_nondets(&lambda, &x_minus_x3, p));
    nondets.extend(sub_mod_p_nondets(&lambda_dx3, y, p));
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

/// Replays `emit_scalar_mul_known_msb(point, bits_lsb_first)` to derive the
/// nondet sequence and the final accumulator point. `bits_lsb_first` must
/// have MSB = 1.
fn scalar_mul_known_msb_execute(
    point: &(BigUint, BigUint),
    bits_lsb_first: &[u8],
    p: &BigUint,
) -> ((BigUint, BigUint), Vec<Felt>) {
    assert!(!bits_lsb_first.is_empty() && *bits_lsb_first.last().unwrap() == 1);
    let mut acc = point.clone();
    let mut nondets = Vec::new();
    for &bit in bits_lsb_first.iter().rev().skip(1) {
        let doubled = secp_double(&acc, p);
        let added = secp_add(&doubled, point, p);
        nondets.extend(point_double_nondets(&acc, p));
        nondets.extend(point_add_affine_nondets(&doubled, point, p));
        acc = if bit == 1 { added } else { doubled };
    }
    (acc, nondets)
}

/// Drives the restructured verify body. Given pk, sig_s, and a target u1
/// (with MSB=1), derives sig_r = (u1·pk).x mod n such that the final check
/// is satisfied, and exercises the full pipeline.
fn run_verify_test(pk: (BigUint, BigUint), sig_s: BigUint, u1_target: BigUint) {
    let p = secp256k1_p();
    let n = secp256k1_n();
    assert!(sig_s < n && sig_s != BigUint::from(0u32));
    assert!(pk.0 < n, "pk.x must be < n");
    assert!(u1_target < n, "u1_target must be < n");

    // Compute z so u1 = z · s_inv mod n = u1_target.
    let s_inv = sig_s.modpow(&(&n - 2u32), &n);
    let z = (&u1_target * &sig_s) % &n;
    debug_assert_eq!((&z * &s_inv) % &n, u1_target);

    // Simulate u1·G → derive expected sig_r.
    let u1_limbs = biguint_to_le_64_limbs(&u1_target);
    let u1_bits: [u8; 256] = std::array::from_fn(|i| {
        let limb = u1_limbs[i / 64];
        ((limb >> (i % 64)) & 1) as u8
    });
    let g = secp256k1_g();
    let (r_point, sm_nondets) = scalar_mul_known_msb_execute(&g, &u1_bits, &p);
    assert!(
        r_point.0 < n,
        "R.x < n for this test vector (k=0 reduction path)"
    );
    let sig_r = r_point.0.clone();

    // Build circuit + inputs.
    let private: Vec<u32> = (0..=PREDICATE_W).collect();
    let circuit = make_circuit_with_opcodes(
        OUTPUT_W,
        &private,
        &[],
        &[OUTPUT_W],
        vec![ecdsa_secp256k1_opcode()],
    );
    let inputs = inputs_from_pk_sig_z(&pk, &sig_r, &sig_s, &z);

    // Nondet sequence in emission order.
    let mut nondet = Vec::new();

    // Q on curve: y² = x³ + 7 (mod p). Primitives now canonicalise internally,
    // so no explicit assert_lt needed — just the 3 muls + 1 add.
    let x_sq = (&pk.0 * &pk.0) % &p;
    let x_cubed = (&x_sq * &pk.0) % &p;
    nondet.extend(mul_mod_p_nondets(&pk.0, &pk.0, &p)); // x²
    nondet.extend(mul_mod_p_nondets(&x_sq, &pk.0, &p)); // x³
    nondet.extend(add_mod_p_nondets(&x_cubed, &BigUint::from(7u32), &p)); // x³ + 7
    nondet.extend(mul_mod_p_nondets(&pk.1, &pk.1, &p)); // y²

    nondet.extend(assert_lt_modulus_nondets(&sig_r, &n));
    nondet.extend(assert_lt_modulus_nondets(&sig_s, &n));
    // sig_r ≠ 0 check.
    nondet.extend(limbs_eq_boolean_nondets(&sig_r, &BigUint::from(0u32)));
    nondet.extend(inv_mod_p_nondets(&sig_s, &n)); // s_inv
    nondet.extend(mul_mod_p_nondets(&z, &s_inv, &n)); // u1
    nondet.extend(mul_mod_p_nondets(&sig_r, &s_inv, &n)); // u2 (value unused downstream)
    nondet.extend(bit_decompose_256_nondets(&u1_target));
    nondet.extend(sm_nondets);
    nondet.extend(add_mod_p_nondets(&r_point.0, &BigUint::from(0u32), &n)); // R.x mod n
    nondet.extend(assert_lt_modulus_nondets(&sig_r, &n));
    // Safe-div exercise: pk.y / pk.x mod p (pk.x nonzero for G).
    nondet.extend(safe_div_mod_p_nondets(&pk.1, &pk.0, &p));

    // emit_point_add_complete(O + pk) → pk. Oracle replays the regular add
    // formula on x1=0, y1=0, x2=pk.x, y2=pk.y (producing garbage that's then
    // discarded by the select on inf1=1).
    let zero_bu = BigUint::from(0u32);
    nondet.extend(point_add_complete_regular_nondets(
        &zero_bu, &zero_bu, &pk.0, &pk.1, &p,
    ));
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
fn stub_verify_accepts_consistent_sig_r() {
    // Arbitrary u1 with bit 255 set (MSB precondition); arbitrary nonzero s < n.
    let u1_target = (BigUint::from(1u32) << 255) + 1u32;
    let sig_s = secp256k1_2g().1; // 2G.y — nonzero, < n.
    run_verify_test(secp256k1_g(), sig_s, u1_target);
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
