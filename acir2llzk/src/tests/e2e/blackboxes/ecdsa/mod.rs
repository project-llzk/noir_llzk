//! Shared driver and nondet oracle for ECDSA e2e tests. Per-curve files
//! supply only constants + the opcode constructor.

mod secp256k1_tests;
mod secp256r1_tests;

use acir::FieldElement;
use acir::circuit::Opcode;
use acir::circuit::opcodes::FunctionInput;
use acir::native_types::Witness;
use llzk_interpreter::Felt;
use num_bigint::{BigInt, BigUint, Sign};

use crate::tests::e2e::{Value, assert_witness_eq, felt_u64, run_e2e_with_phase_nondets};
use crate::tests::make_circuit_with_opcodes;

pub(super) const PK_X_START: u32 = 0;
pub(super) const PK_Y_START: u32 = 32;
pub(super) const SIG_START: u32 = 64;
pub(super) const HASH_START: u32 = 128;
pub(super) const PREDICATE_W: u32 = 160;
pub(super) const OUTPUT_W: u32 = 161;

pub(super) struct Curve {
    pub p: BigUint,
    pub n: BigUint,
    pub g: (BigUint, BigUint),
    pub a: BigUint,
    pub b: BigUint,
    pub opcode: fn() -> Opcode<FieldElement>,
}

impl Curve {
    pub fn half_n_plus_one(&self) -> BigUint {
        &self.n / 2u32 + 1u32
    }
}

pub(super) fn byte_inputs(start: u32, count: usize) -> Vec<FunctionInput<FieldElement>> {
    (0..count)
        .map(|i| FunctionInput::Witness(Witness(start + i as u32)))
        .collect()
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
) -> Vec<Value> {
    inputs_from_pk_sig_z_with_predicate(pk, sig_r, sig_s, z, 1)
}

fn inputs_from_pk_sig_z_with_predicate(
    pk: &(BigUint, BigUint),
    sig_r: &BigUint,
    sig_s: &BigUint,
    z: &BigUint,
    predicate: u64,
) -> Vec<Value> {
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
    inputs.push(felt_u64(predicate));
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
pub(super) fn add_mod_p_nondets(a: &BigUint, b: &BigUint, p: &BigUint) -> Vec<Felt> {
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
pub(super) fn mul_mod_p_nondets(a: &BigUint, b: &BigUint, p: &BigUint) -> Vec<Felt> {
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
    nondets.extend(assert_lt_modulus_nondets(&r, p));
    nondets
}

/// Nondets for `emit_point_add_complete`. All branches' nondets are emitted
/// regardless of the actual case — selects discard the unused ones.
fn point_add_complete_regular_nondets(
    x1: &BigUint,
    y1: &BigUint,
    x2: &BigUint,
    y2: &BigUint,
    p: &BigUint,
    a: &BigUint,
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
    nondet.extend(sub_mod_p_nondets(y2, y1, p));
    nondet.extend(sub_mod_p_nondets(x2, x1, p));
    nondet.extend(safe_div_mod_p_nondets(&dy, &dx, p));
    nondet.extend(mul_mod_p_nondets(&lambda, &lambda, p));
    nondet.extend(add_mod_p_nondets(x1, x2, p));
    nondet.extend(sub_mod_p_nondets(&lambda_sq, &x_sum, p));
    nondet.extend(sub_mod_p_nondets(x1, &x3, p));
    nondet.extend(mul_mod_p_nondets(&lambda, &x1_minus_x3, p));
    nondet.extend(sub_mod_p_nondets(&lambda_dx3, y1, p));
    nondet.extend(point_double_complete_regular_nondets(x1, y1, p, a));
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

// ── Generic short Weierstrass affine arithmetic ─────────────────────────

pub(super) fn secp_add(
    p1: &(BigUint, BigUint),
    p2: &(BigUint, BigUint),
    p: &BigUint,
) -> (BigUint, BigUint) {
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

pub(super) fn secp_double(pt: &(BigUint, BigUint), p: &BigUint, a: &BigUint) -> (BigUint, BigUint) {
    let (x, y) = pt;
    let x_sq = (x * x) % p;
    let three_x_sq = (&x_sq * 3u32) % p;
    let numerator = (&three_x_sq + a) % p;
    let two_y = (y * 2u32) % p;
    let two_y_inv = two_y.modpow(&(p - 2u32), p);
    let lambda = (&numerator * &two_y_inv) % p;
    let lambda_sq = (&lambda * &lambda) % p;
    let two_x = (x * 2u32) % p;
    let x3 = (p + &lambda_sq - &two_x) % p;
    let x_minus_x3 = (p + x - &x3) % p;
    let lambda_dx3 = (&lambda * &x_minus_x3) % p;
    let y3 = (p + &lambda_dx3 - y) % p;
    (x3, y3)
}

/// Nondets for the regular doubling portion of `emit_point_double_complete`
/// on curve `y² = x³ + a·x + b`. Slope = (3x² + a) / (2y) via safe_div.
fn point_double_complete_regular_nondets(
    x: &BigUint,
    y: &BigUint,
    p: &BigUint,
    a: &BigUint,
) -> Vec<Felt> {
    let zero = BigUint::from(0u32);
    let x_sq = (x * x) % p;
    let two_x_sq = (&x_sq + &x_sq) % p;
    let three_x_sq = (&two_x_sq + &x_sq) % p;
    let numerator = (&three_x_sq + a) % p;
    let two_y = (y + y) % p;
    let lambda = if two_y == zero {
        zero.clone()
    } else {
        let two_y_inv = two_y.modpow(&(p - 2u32), p);
        (&numerator * &two_y_inv) % p
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
    nondet.extend(add_mod_p_nondets(&three_x_sq, a, p));
    nondet.extend(add_mod_p_nondets(y, y, p));
    nondet.extend(safe_div_mod_p_nondets(&numerator, &two_y, p));
    nondet.extend(mul_mod_p_nondets(&lambda, &lambda, p));
    nondet.extend(add_mod_p_nondets(x, x, p));
    nondet.extend(sub_mod_p_nondets(&lambda_sq, &two_x, p));
    nondet.extend(sub_mod_p_nondets(x, &x3, p));
    nondet.extend(mul_mod_p_nondets(&lambda, &x_minus_x3, p));
    nondet.extend(sub_mod_p_nondets(&lambda_dx3, y, p));
    nondet
}

fn scalar_mul_general_execute(
    point: &(BigUint, BigUint),
    bits_lsb_first: &[u8],
    p: &BigUint,
    a: &BigUint,
) -> ((BigUint, BigUint), bool, Vec<Felt>) {
    let zero = BigUint::from(0u32);
    let mut acc = (zero.clone(), zero.clone());
    let mut acc_inf = true;
    let mut nondets = Vec::new();
    for &bit in bits_lsb_first.iter().rev() {
        nondets.extend(point_double_complete_regular_nondets(&acc.0, &acc.1, p, a));
        let (doubled, doubled_inf) = if acc_inf {
            ((zero.clone(), zero.clone()), true)
        } else {
            (secp_double(&acc, p, a), false)
        };
        nondets.extend(point_add_complete_regular_nondets(
            &doubled.0, &doubled.1, &point.0, &point.1, p, a,
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

type MaybePoint = ((BigUint, BigUint), bool);

fn complete_double_execute(
    point: &(BigUint, BigUint),
    is_infinity: bool,
    p: &BigUint,
    a: &BigUint,
) -> MaybePoint {
    if is_infinity {
        ((BigUint::from(0u32), BigUint::from(0u32)), true)
    } else {
        (secp_double(point, p, a), false)
    }
}

fn complete_add_execute(
    p1: &(BigUint, BigUint),
    p1_inf: bool,
    p2: &(BigUint, BigUint),
    p2_inf: bool,
    p: &BigUint,
    a: &BigUint,
) -> MaybePoint {
    if p1_inf {
        return (p2.clone(), p2_inf);
    }
    if p2_inf {
        return (p1.clone(), p1_inf);
    }
    if p1.0 == p2.0 {
        if p1.1 == p2.1 {
            (secp_double(p1, p, a), false)
        } else {
            ((BigUint::from(0u32), BigUint::from(0u32)), true)
        }
    } else {
        (secp_add(p1, p2, p), false)
    }
}

fn joint_scalar_mul_execute(
    p1: &(BigUint, BigUint),
    p1_bits_lsb_first: &[u8],
    p2: &(BigUint, BigUint),
    p2_bits_lsb_first: &[u8],
    p: &BigUint,
    a: &BigUint,
) -> ((BigUint, BigUint), bool, Vec<Felt>) {
    let zero_point = (BigUint::from(0u32), BigUint::from(0u32));
    let (p1_multiples, mut nondets) = window_multiples_execute(p1, p, a);
    let (p2_multiples, p2_multiples_nondets) = window_multiples_execute(p2, p, a);
    nondets.extend(p2_multiples_nondets);

    // Mirrors the i==0 / j==0 shortcut in `emit_joint_window_table`: the circuit
    // only emits add-nondets for entries with i≥1 ∧ j≥1, so we skip the rest.
    let mut table = Vec::with_capacity(16);
    for (i, p1_multiple) in p1_multiples.iter().enumerate() {
        for (j, p2_multiple) in p2_multiples.iter().enumerate() {
            let entry = if i == 0 {
                p2_multiple.clone()
            } else if j == 0 {
                p1_multiple.clone()
            } else {
                nondets.extend(point_add_complete_regular_nondets(
                    &p1_multiple.0.0,
                    &p1_multiple.0.1,
                    &p2_multiple.0.0,
                    &p2_multiple.0.1,
                    p,
                    a,
                ));
                complete_add_execute(
                    &p1_multiple.0,
                    p1_multiple.1,
                    &p2_multiple.0,
                    p2_multiple.1,
                    p,
                    a,
                )
            };
            table.push(entry);
        }
    }

    let mut acc = zero_point;
    let mut acc_inf = true;
    for window in (0..p1_bits_lsb_first.len() / 2).rev() {
        for _ in 0..2 {
            nondets.extend(point_double_complete_regular_nondets(&acc.0, &acc.1, p, a));
            let (doubled, doubled_inf) = complete_double_execute(&acc, acc_inf, p, a);
            acc = doubled;
            acc_inf = doubled_inf;
        }

        let start = window * 2;
        let p1_index =
            p1_bits_lsb_first[start] as usize + 2 * p1_bits_lsb_first[start + 1] as usize;
        let p2_index =
            p2_bits_lsb_first[start] as usize + 2 * p2_bits_lsb_first[start + 1] as usize;
        let (addend, addend_inf) = &table[p1_index * 4 + p2_index];
        nondets.extend(point_add_complete_regular_nondets(
            &acc.0, &acc.1, &addend.0, &addend.1, p, a,
        ));
        let (added, added_inf) = complete_add_execute(&acc, acc_inf, addend, *addend_inf, p, a);
        acc = added;
        acc_inf = added_inf;
    }
    (acc, acc_inf, nondets)
}

fn window_multiples_execute(
    point: &(BigUint, BigUint),
    p: &BigUint,
    a: &BigUint,
) -> (Vec<MaybePoint>, Vec<Felt>) {
    let zero_point = (BigUint::from(0u32), BigUint::from(0u32));
    let mut nondets = Vec::new();

    nondets.extend(point_double_complete_regular_nondets(
        &point.0, &point.1, p, a,
    ));
    let (double, double_inf) = complete_double_execute(point, false, p, a);

    nondets.extend(point_add_complete_regular_nondets(
        &double.0, &double.1, &point.0, &point.1, p, a,
    ));
    let (triple, triple_inf) = complete_add_execute(&double, double_inf, point, false, p, a);

    (
        vec![
            (zero_point, true),
            (point.clone(), false),
            (double, double_inf),
            (triple, triple_inf),
        ],
        nondets,
    )
}

fn biguint_to_bits_256(value: &BigUint) -> [u8; 256] {
    let limbs = biguint_to_le_64_limbs(value);
    std::array::from_fn(|i| ((limbs[i / 64] >> (i % 64)) & 1) as u8)
}

/// Generates a valid signature for `(d, k, z)` and runs verify.
pub(super) fn run_verify_test(curve: &Curve, d: BigUint, k: BigUint, z: BigUint) {
    run_verify_test_with_s_mode(curve, d, k, z, false);
}

pub(super) fn run_verify_test_with_s_mode(
    curve: &Curve,
    d: BigUint,
    k: BigUint,
    z: BigUint,
    use_high_s: bool,
) {
    let Curve { p, n, g, a, .. } = curve;

    let d_bits = biguint_to_bits_256(&d);
    let (q, q_inf, _) = scalar_mul_general_execute(g, &d_bits, p, a);
    assert!(!q_inf && &q.0 < n, "pk Q.x must be < n for Fr arithmetic");

    let k_bits = biguint_to_bits_256(&k);
    let (r_k, r_k_inf, _) = scalar_mul_general_execute(g, &k_bits, p, a);
    assert!(!r_k_inf, "nonce k must produce a finite point");
    let sig_r = &r_k.0 % n;
    assert!(
        sig_r != BigUint::from(0u32),
        "pick a nonce avoiding R_k.x ≡ 0 mod n"
    );

    let k_inv_n = k.modpow(&(n - 2u32), n);
    let mut sig_s = (&k_inv_n * ((&z + &sig_r * &d) % n)) % n;
    assert!(sig_s != BigUint::from(0u32), "sig_s must be nonzero");
    let half_n_plus_one = curve.half_n_plus_one();
    if sig_s >= half_n_plus_one {
        sig_s = n - &sig_s;
    }
    if use_high_s {
        sig_s = n - &sig_s;
    }

    run_verify_input_test(curve, &q, &sig_r, &sig_s, &z);
}

/// Predicate=0 with deliberately invalid inputs. Output must be 1 since
/// the verifier short-circuits when predicate is disabled.
pub(super) fn run_predicate_false_test(curve: &Curve) {
    let Curve { p, n, g, a, .. } = curve;
    let zero = BigUint::from(0u32);
    let sig_r = BigUint::from(1u32);
    let sig_s = BigUint::from(1u32);
    let z = zero.clone();
    let s_inv = BigUint::from(1u32);
    let u1_target = zero.clone();
    let u2_target = BigUint::from(1u32);

    let u1_bits = biguint_to_bits_256(&u1_target);
    let u2_bits = biguint_to_bits_256(&u2_target);
    let (r_final, r_inf, joint_mul_nondets) =
        joint_scalar_mul_execute(g, &u1_bits, g, &u2_bits, p, a);
    assert!(!r_inf, "0·G + 1·G should be finite");
    assert!(&r_final.0 < n, "R.x must be canonical in Fr");

    let private: Vec<u32> = (0..=PREDICATE_W).collect();
    let circuit =
        make_circuit_with_opcodes(OUTPUT_W, &private, &[], &[OUTPUT_W], vec![(curve.opcode)()]);
    let raw_invalid_pk = (p.clone(), p.clone());
    let inputs = inputs_from_pk_sig_z_with_predicate(&raw_invalid_pk, &zero, &zero, &zero, 0);

    let mut nondet = Vec::new();
    nondet.extend(assert_lt_modulus_nondets(&g.0, p));
    nondet.extend(assert_lt_modulus_nondets(&g.1, p));
    nondet.extend(on_curve_check_nondets(g, p, a, &curve.b));
    nondet.extend(assert_lt_modulus_nondets(&sig_r, n));
    nondet.extend(assert_lt_modulus_nondets(&sig_s, n));
    nondet.extend(limbs_eq_boolean_nondets(&sig_r, &zero));
    nondet.extend(lt_modulus_boolean_nondets(&sig_s, &curve.half_n_plus_one()));
    nondet.extend(inv_mod_p_nondets(&sig_s, n));
    nondet.extend(mul_mod_p_nondets(&z, &s_inv, n));
    nondet.extend(mul_mod_p_nondets(&sig_r, &s_inv, n));
    nondet.extend(limbs_bits_nondets(&u1_target));
    nondet.extend(limbs_bits_nondets(&u2_target));
    nondet.extend(joint_mul_nondets);
    nondet.extend(lt_modulus_boolean_nondets(&r_final.0, n));
    nondet.extend(limbs_eq_boolean_nondets(&r_final.0, &sig_r));

    let computed = run_e2e_with_phase_nondets(circuit, &inputs, &[], &nondet);
    assert_witness_eq(&computed.members, &format!("w{OUTPUT_W}"), "1");
}

pub(super) fn run_verify_input_test(
    curve: &Curve,
    pk: &(BigUint, BigUint),
    sig_r: &BigUint,
    sig_s: &BigUint,
    z: &BigUint,
) {
    let Curve { p, n, g, a, b, .. } = curve;
    let zero = BigUint::from(0u32);
    let half_n_plus_one = curve.half_n_plus_one();

    assert!(pk.0 < *p && pk.1 < *p, "pk coords must be canonical");
    assert!(is_on_curve(pk, p, a, b), "pk must be on curve");
    assert!(sig_r < n && sig_r != &zero, "sig_r must be in [1, n)");
    assert!(sig_s < n && sig_s != &zero, "sig_s must be in [1, n)");

    let s_inv = sig_s.modpow(&(n - 2u32), n);
    let u1_target = (z * &s_inv) % n;
    let u2_target = (sig_r * &s_inv) % n;
    let u1_bits = biguint_to_bits_256(&u1_target);
    let u2_bits = biguint_to_bits_256(&u2_target);
    let (r_final, r_inf, joint_mul_nondets) =
        joint_scalar_mul_execute(g, &u1_bits, pk, &u2_bits, p, a);

    let private: Vec<u32> = (0..=PREDICATE_W).collect();
    let circuit =
        make_circuit_with_opcodes(OUTPUT_W, &private, &[], &[OUTPUT_W], vec![(curve.opcode)()]);
    let inputs = inputs_from_pk_sig_z(pk, sig_r, sig_s, z);

    let mut nondet = Vec::new();
    nondet.extend(assert_lt_modulus_nondets(&pk.0, p));
    nondet.extend(assert_lt_modulus_nondets(&pk.1, p));
    nondet.extend(on_curve_check_nondets(pk, p, a, b));
    nondet.extend(assert_lt_modulus_nondets(sig_r, n));
    nondet.extend(assert_lt_modulus_nondets(sig_s, n));
    nondet.extend(limbs_eq_boolean_nondets(sig_r, &zero));
    nondet.extend(lt_modulus_boolean_nondets(sig_s, &half_n_plus_one));
    nondet.extend(inv_mod_p_nondets(sig_s, n));
    nondet.extend(mul_mod_p_nondets(z, &s_inv, n));
    nondet.extend(mul_mod_p_nondets(sig_r, &s_inv, n));
    nondet.extend(limbs_bits_nondets(&u1_target));
    nondet.extend(limbs_bits_nondets(&u2_target));
    nondet.extend(joint_mul_nondets);
    nondet.extend(lt_modulus_boolean_nondets(&r_final.0, n));
    nondet.extend(limbs_eq_boolean_nondets(&r_final.0, sig_r));

    let expected = !r_inf && r_final.0 < *n && r_final.0 == *sig_r && sig_s < &half_n_plus_one;
    let compute_nondet = if sig_s >= &half_n_plus_one {
        Vec::new()
    } else {
        vec![Felt::from_u64(if expected { 1 } else { 0 })]
    };
    let computed = run_e2e_with_phase_nondets(circuit, &inputs, &compute_nondet, &nondet);
    assert_witness_eq(
        &computed.members,
        &format!("w{OUTPUT_W}"),
        if expected { "1" } else { "0" },
    );
}

pub(super) fn run_result_at_infinity_test(curve: &Curve) {
    let Curve { p, n, g, a, .. } = curve;
    let d = BigUint::from(7u32);
    let d_bits = biguint_to_bits_256(&d);
    let (pk, pk_inf, _) = scalar_mul_general_execute(g, &d_bits, p, a);
    assert!(!pk_inf);

    let sig_r = BigUint::from(1u32);
    let sig_s = BigUint::from(1u32);
    let z = n - &d;
    run_verify_input_test(curve, &pk, &sig_r, &sig_s, &z);
}

/// Nondets emitted by `assert_on_curve(point)`.
fn on_curve_check_nondets(
    point: &(BigUint, BigUint),
    p: &BigUint,
    a: &BigUint,
    b: &BigUint,
) -> Vec<Felt> {
    let mut nondet = Vec::new();
    let x_sq = (&point.0 * &point.0) % p;
    let x_cubed = (&x_sq * &point.0) % p;
    let a_x = (a * &point.0) % p;
    let x_cubed_plus_ax = (&x_cubed + &a_x) % p;
    nondet.extend(mul_mod_p_nondets(&point.0, &point.0, p)); // x²
    nondet.extend(mul_mod_p_nondets(&x_sq, &point.0, p)); // x³
    nondet.extend(mul_mod_p_nondets(a, &point.0, p)); // a·x
    nondet.extend(add_mod_p_nondets(&x_cubed, &a_x, p)); // x³ + a·x
    nondet.extend(add_mod_p_nondets(&x_cubed_plus_ax, b, p)); // + b
    nondet.extend(mul_mod_p_nondets(&point.1, &point.1, p)); // y²
    nondet
}

fn is_on_curve(point: &(BigUint, BigUint), p: &BigUint, a: &BigUint, b: &BigUint) -> bool {
    let x_sq = (&point.0 * &point.0) % p;
    let x_cubed = (&x_sq * &point.0) % p;
    let a_x = (a * &point.0) % p;
    let rhs = (&x_cubed + &a_x + b) % p;
    let y_sq = (&point.1 * &point.1) % p;
    y_sq == rhs
}

/// Nondet sequence for `emit_limbs_eq_boolean(a, b)`: `[is_eq, inv_hint]`.
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

fn ge_modulus_nondets(value: &BigUint, modulus: &BigUint) -> Vec<Felt> {
    assert!(value >= modulus, "value must be >= modulus");
    let d = value - modulus;
    let d_limbs = biguint_to_le_64_limbs(&d);
    let m_limbs = biguint_to_le_64_limbs(modulus);
    let v_limbs = biguint_to_le_64_limbs(value);

    let two_64 = 1i128 << 64;
    let mut carries = [0i128; 4];
    let mut carry_in: i128 = 0;
    for i in 0..4 {
        let lhs = (v_limbs[i] as i128) - (m_limbs[i] as i128) - (d_limbs[i] as i128) + carry_in;
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

fn lt_modulus_boolean_nondets(value: &BigUint, modulus: &BigUint) -> Vec<Felt> {
    let mut nondets = Vec::with_capacity(1 + 8 + 8);
    if value < modulus {
        nondets.push(Felt::from_u64(1));
        nondets.extend(assert_lt_modulus_nondets(value, modulus));
        nondets.extend((0..8).map(|_| Felt::from_u64(0)));
    } else {
        nondets.push(Felt::from_u64(0));
        nondets.extend((0..8).map(|_| Felt::from_u64(0)));
        nondets.extend(ge_modulus_nondets(value, modulus));
    }
    nondets
}

fn limbs_bits_nondets(value: &BigUint) -> Vec<Felt> {
    let limbs = biguint_to_le_64_limbs(value);
    let mut bits = Vec::with_capacity(256);
    for limb in limbs {
        for i in 0..64 {
            bits.push(Felt::from_u64((limb >> i) & 1));
        }
    }
    bits
}
