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
        OpcodeEmitter, collect_input_witness, ecdsa::curve::emit_scalar_mul_known_msb,
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
        writer.insert_constrain_eq(actual, is_valid);
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

        // Input validation: r, s ∈ [0, n). (s ≠ 0 falls out of inv_mod_p's
        // constraint `s · s_inv ≡ 1 mod n`, which is unsatisfiable for s = 0.)
        emit_assert_lt_modulus(writer, &sig_r, &SECP256K1_N)?;
        emit_assert_lt_modulus(writer, &sig_s, &SECP256K1_N)?;

        // Fr chain: s_inv = s⁻¹ mod n, u1 = z·s_inv, u2 = r·s_inv.
        let s_inv = emit_inv_mod_p(writer, &sig_s, &SECP256K1_N)?;
        let u1 = emit_mul_mod_p(writer, &z, &s_inv, &SECP256K1_N)?;
        let _u2 = emit_mul_mod_p(writer, &sig_r, &s_inv, &SECP256K1_N)?;

        // Scalar mul: R = u1·pk (stand-in for the real u1·G + u2·Q).
        let u1_bits = emit_bit_decompose_256(writer, &u1)?;
        let (r_x, _r_y) = emit_scalar_mul_known_msb(writer, (pk_x, pk_y), &u1_bits)?;

        // Reduce R.x mod n and assert < n.
        let zero = writer.emit_constant(&FieldElement::from(0u128))?;
        let zero_limbs: Limbs256 = [zero; LIMBS];
        let r_x_mod_n = emit_add_mod_p(writer, &r_x, &zero_limbs, &SECP256K1_N)?;
        emit_assert_lt_modulus(writer, &r_x_mod_n, &SECP256K1_N)?;

        // Final equality: is_valid = (R.x mod n == sig_r).
        emit_limbs_eq_boolean(writer, &r_x_mod_n, &sig_r)
    }
}

/// Asserts `(x, y)` lies on secp256k1: `y² ≡ x³ + 7 (mod p)`.
/// Canonicalises both sides via `emit_assert_lt_modulus` (so they're in
/// [0, p)), then compares limb-wise.
fn assert_on_curve<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    x: &Limbs256<'c, 'b>,
    y: &Limbs256<'c, 'b>,
) -> Result<(), Error> {
    let seven = {
        let zero = writer.emit_constant(&FieldElement::from(0u128))?;
        let seven_val = writer.emit_constant(&FieldElement::from(7u128))?;
        [seven_val, zero, zero, zero]
    };
    let x_sq = emit_mul_mod_p(writer, x, x, &SECP256K1_P)?;
    let x_cubed = emit_mul_mod_p(writer, &x_sq, x, &SECP256K1_P)?;
    let rhs = emit_add_mod_p(writer, &x_cubed, &seven, &SECP256K1_P)?;
    let y_sq = emit_mul_mod_p(writer, y, y, &SECP256K1_P)?;
    emit_assert_lt_modulus(writer, &rhs, &SECP256K1_P)?;
    emit_assert_lt_modulus(writer, &y_sq, &SECP256K1_P)?;
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
