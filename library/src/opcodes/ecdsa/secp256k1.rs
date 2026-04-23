//! EcdsaSecp256k1 opcode — **stub**, structurally shaped like real verify.
//!
//! Current state: runs the ECDSA Fr chain (s⁻¹, u1, u2), bit-decomposes u1,
//! scalar-multiplies the public key by u1 (standing in for `u1·G + u2·Q`),
//! reduces the result's x-coordinate mod n, and compares it against `r` from
//! the signature. Writes the resulting equality bit to `output`.
//!
//! Known shortcuts vs. real verify:
//!   - Scalar mul uses `pk` as base (should be `u1·G + u2·Q`).
//!   - scalar_mul_known_msb requires MSB = 1 on the scalar.
//!   - No infinity / doubling / ±P edge case handling in curve ops.
//!   - No validation that (r, s) ∈ [1, n-1] or that `pk` is on the curve.
//!   - No predicate gating.

use std::collections::BTreeSet;

use acir::{
    FieldElement,
    circuit::Opcode,
    circuit::opcodes::{BlackBoxFuncCall, FunctionInput},
    native_types::Witness,
};

use llzk::prelude::Value;

use crate::{
    block_writer::BlockWriter,
    error::Error,
    multiprec::{
        LIMBS, Limbs256, emit_add_mod_p, emit_assert_lt_modulus, emit_bit_decompose_256,
        emit_inv_mod_p, emit_limbs_eq_boolean, emit_mul_mod_p,
    },
    opcodes::{
        OpcodeEmitter, collect_input_witness, ecdsa::curve::emit_scalar_mul_general,
        emit_blackbox_input,
    },
};

/// secp256k1 base field modulus: 2^256 - 2^32 - 977, little-endian 64-bit limbs.
pub(super) const SECP256K1_P: [u64; 4] = [
    0xFFFF_FFFE_FFFF_FC2F,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
];

/// secp256k1 scalar field order `n`, little-endian 64-bit limbs.
/// n = 0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141.
pub(super) const SECP256K1_N: [u64; 4] = [
    0xBFD2_5E8C_D036_4141,
    0xBAAE_DCE6_AF48_A03B,
    0xFFFF_FFFF_FFFF_FFFE,
    0xFFFF_FFFF_FFFF_FFFF,
];

/// secp256k1 generator G.x = 0x79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798.
pub(super) const SECP256K1_GX: [u64; 4] = [
    0x59F2_815B_16F8_1798,
    0x029B_FCDB_2DCE_28D9,
    0x55A0_6295_CE87_0B07,
    0x79BE_667E_F9DC_BBAC,
];

/// secp256k1 generator G.y = 0x483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8.
pub(super) const SECP256K1_GY: [u64; 4] = [
    0x9C47_D08F_FB10_D4B8,
    0xFD17_B448_A685_5419,
    0x5DA4_FBFC_0E11_08A8,
    0x483A_DA77_26A3_C465,
];

pub(crate) struct EcdsaSecp256k1<'a> {
    public_key_x: &'a [FunctionInput<FieldElement>; 32],
    public_key_y: &'a [FunctionInput<FieldElement>; 32],
    signature: &'a [FunctionInput<FieldElement>; 64],
    hashed_message: &'a [FunctionInput<FieldElement>; 32],
    predicate: &'a FunctionInput<FieldElement>,
    output: Witness,
}

impl OpcodeEmitter for EcdsaSecp256k1<'_> {
    fn get_witnesses(&self) -> BTreeSet<u32> {
        let mut witnesses = BTreeSet::from([self.output.0]);
        for input in self
            .public_key_x
            .iter()
            .chain(self.public_key_y.iter())
            .chain(self.signature.iter())
            .chain(self.hashed_message.iter())
            .chain(std::iter::once(self.predicate))
        {
            collect_input_witness(&mut witnesses, input);
        }
        witnesses
    }

    fn emit_compute<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let is_valid = self.emit_verify_body(writer)?;
        writer.write_member(&format!("w{}", self.output.0), is_valid)?;
        writer.mark_known(self.output.0, is_valid);
        Ok(())
    }

    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let is_valid = self.emit_verify_body(writer)?;
        let actual = writer.read_witness(self.output.0)?;
        // Predicate gating: predicate · (output − is_valid) = 0. When
        // predicate = 1, forces output = is_valid. When predicate = 0, the
        // output is unconstrained.
        let predicate = emit_blackbox_input(writer, self.predicate)?;
        let zero = writer.emit_constant(&FieldElement::from(0u128))?;
        let neg_valid = writer.insert_neg(is_valid)?;
        let diff = writer.insert_add(actual, neg_valid)?;
        let gated = writer.insert_mul(predicate, diff)?;
        writer.insert_constrain_eq(gated, zero);
        Ok(())
    }
}

impl EcdsaSecp256k1<'_> {
    /// Emits the verify body and returns a felt ∈ {0, 1} indicating validity.
    /// Current shape: `scalar_mul(u1_bits, pk).x mod n == r`.
    fn emit_verify_body<'c, 'b>(
        &self,
        writer: &mut BlockWriter<'c, 'b>,
    ) -> Result<Value<'c, 'b>, Error> {
        let pk_x = pack_bytes_be_to_le_limbs(writer, self.public_key_x)?;
        let pk_y = pack_bytes_be_to_le_limbs(writer, self.public_key_y)?;
        assert_on_curve(writer, &pk_x, &pk_y)?;
        let sig_r_bytes: &[FunctionInput<FieldElement>; 32] = self.signature[..32]
            .try_into()
            .expect("signature has at least 32 bytes");
        let sig_s_bytes: &[FunctionInput<FieldElement>; 32] = self.signature[32..64]
            .try_into()
            .expect("signature has 64 bytes");
        let sig_r = pack_bytes_be_to_le_limbs(writer, sig_r_bytes)?;
        let sig_s = pack_bytes_be_to_le_limbs(writer, sig_s_bytes)?;
        let z = pack_bytes_be_to_le_limbs(writer, self.hashed_message)?;

        // Input validation: r, s ∈ [1, n). s ≠ 0 falls out of inv_mod_p
        // (s · s_inv ≡ 1 mod n is unsatisfiable for s = 0); r ≠ 0 is explicit.
        emit_assert_lt_modulus(writer, &sig_r, &SECP256K1_N)?;
        emit_assert_lt_modulus(writer, &sig_s, &SECP256K1_N)?;
        let zero = writer.emit_constant(&FieldElement::from(0u128))?;
        let zero_limbs: Limbs256 = [zero; LIMBS];
        let r_is_zero = emit_limbs_eq_boolean(writer, &sig_r, &zero_limbs)?;
        writer.insert_constrain_eq(r_is_zero, zero);

        // Fr chain: s_inv = s⁻¹ mod n, u1 = z·s_inv, u2 = r·s_inv.
        let s_inv = emit_inv_mod_p(writer, &sig_s, &SECP256K1_N)?;
        let u1 = emit_mul_mod_p(writer, &z, &s_inv, &SECP256K1_N)?;
        let _u2 = emit_mul_mod_p(writer, &sig_r, &s_inv, &SECP256K1_N)?;

        // Scalar mul: R = u1·G (stand-in for the real u1·G + u2·Q).
        // Uses the general (infinity-aware) implementation so any u1 ∈ [0, n)
        // works — no more MSB=1 precondition.
        let g = emit_limbs_constant(writer, &SECP256K1_GX, &SECP256K1_GY)?;
        let u1_bits = emit_bit_decompose_256(writer, &u1)?;
        let (r_x, _r_y, r_inf) = emit_scalar_mul_general(writer, g, &u1_bits)?;
        // R at infinity → invalid signature. Assert R is finite.
        writer.insert_constrain_eq(r_inf, zero);

        // Reduce R.x mod n and assert < n.
        let r_x_mod_n = emit_add_mod_p(writer, &r_x, &zero_limbs, &SECP256K1_N)?;
        emit_assert_lt_modulus(writer, &r_x_mod_n, &SECP256K1_N)?;

        // Final equality: is_valid = (R.x mod n == sig_r).
        emit_limbs_eq_boolean(writer, &r_x_mod_n, &sig_r)
    }
}

/// Emits an affine point from two 4-limb constants.
fn emit_limbs_constant<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    x: &[u64; LIMBS],
    y: &[u64; LIMBS],
) -> Result<(Limbs256<'c, 'b>, Limbs256<'c, 'b>), Error> {
    Ok((pack_u64_limbs(writer, x)?, pack_u64_limbs(writer, y)?))
}

fn pack_u64_limbs<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    limbs: &[u64; LIMBS],
) -> Result<Limbs256<'c, 'b>, Error> {
    let mut out: [Option<Value<'c, 'b>>; LIMBS] = [None; LIMBS];
    for (slot, &limb) in out.iter_mut().zip(limbs.iter()) {
        *slot = Some(writer.emit_constant(&FieldElement::from(limb as u128))?);
    }
    Ok(out.map(|s| s.expect("all slots filled")))
}

/// Asserts `(x, y)` lies on secp256k1: `y² ≡ x³ + 7 (mod p)`. Both sides are
/// already canonical since the multiprec primitives enforce `r < p`.
fn assert_on_curve<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    x: &Limbs256<'c, 'b>,
    y: &Limbs256<'c, 'b>,
) -> Result<(), Error> {
    let zero = writer.emit_constant(&FieldElement::from(0u128))?;
    let seven_val = writer.emit_constant(&FieldElement::from(7u128))?;
    let seven = [seven_val, zero, zero, zero];
    let x_sq = emit_mul_mod_p(writer, x, x, &SECP256K1_P)?;
    let x_cubed = emit_mul_mod_p(writer, &x_sq, x, &SECP256K1_P)?;
    let rhs = emit_add_mod_p(writer, &x_cubed, &seven, &SECP256K1_P)?;
    let y_sq = emit_mul_mod_p(writer, y, y, &SECP256K1_P)?;
    for (a, b) in y_sq.iter().zip(rhs.iter()) {
        writer.insert_constrain_eq(*a, *b);
    }
    Ok(())
}

/// Packs 32 big-endian bytes into 4 little-endian 64-bit limbs.
/// `bytes[0]` is the overall most-significant byte → ends up in `limbs[3]`'s
/// high byte; `bytes[31]` is LSB → `limbs[0]`'s low byte.
fn pack_bytes_be_to_le_limbs<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    bytes: &[FunctionInput<FieldElement>; 32],
) -> Result<Limbs256<'c, 'b>, Error> {
    let mut limbs: [Option<Value<'c, 'b>>; LIMBS] = [None; LIMBS];
    for (limb_idx, slot) in limbs.iter_mut().enumerate() {
        let byte_start = (3 - limb_idx) * 8;
        let mut acc = writer.emit_constant(&FieldElement::from(0u128))?;
        for i in 0..8 {
            let byte_value = emit_blackbox_input(writer, &bytes[byte_start + i])?;
            let shift = 8u32 * (7 - i) as u32;
            let coeff = writer.emit_constant(&FieldElement::from(1u128 << shift))?;
            let term = writer.insert_mul(byte_value, coeff)?;
            acc = writer.insert_add(acc, term)?;
        }
        *slot = Some(acc);
    }
    Ok(limbs.map(|s| s.expect("all slots filled")))
}

pub(crate) fn from_opcode<'a>(opcode: &'a Opcode<FieldElement>) -> Option<EcdsaSecp256k1<'a>> {
    match opcode {
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::EcdsaSecp256k1 {
            public_key_x,
            public_key_y,
            signature,
            hashed_message,
            predicate,
            output,
        }) => Some(EcdsaSecp256k1 {
            public_key_x,
            public_key_y,
            signature,
            hashed_message,
            predicate,
            output: *output,
        }),
        _ => None,
    }
}
