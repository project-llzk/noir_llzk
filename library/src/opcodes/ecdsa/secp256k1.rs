//! `EcdsaSecp256k1` verify.

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
        emit_assert_lt_modulus, emit_bit_decompose_256, emit_inv_mod_p, emit_limbs_eq_boolean,
        emit_limbs_lt_modulus_boolean, emit_mul_mod_p, emit_zero_limbs,
    },
    opcodes::{
        OpcodeEmitter, collect_input_witness,
        ecdsa::{
            curve::{CurveParams, assert_on_curve, emit_joint_scalar_mul},
            shared::{
                emit_limbs_constant, emit_not, emit_select_limbs, emit_select_value,
                pack_bytes_be_to_le_limbs, pack_u64_limbs,
            },
        },
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

/// floor(n / 2) + 1. Low-S signatures must satisfy s < this value.
const SECP256K1_HALF_N_PLUS_ONE: [u64; 4] = [
    0xDFE9_2F46_681B_20A1,
    0x5D57_6E73_57A4_501D,
    0xFFFF_FFFF_FFFF_FFFF,
    0x7FFF_FFFF_FFFF_FFFF,
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

/// secp256k1 curve params: y² = x³ + 7 (a = 0, b = 7).
const SECP256K1_PARAMS: CurveParams = CurveParams {
    p: SECP256K1_P,
    a: [0, 0, 0, 0],
    b: [7, 0, 0, 0],
};

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
        let expected = self.emit_verify_body(writer)?;
        let actual = writer.read_witness(self.output.0)?;
        writer.insert_constrain_eq(actual, expected);
        Ok(())
    }
}

impl EcdsaSecp256k1<'_> {
    fn emit_verify_body<'c, 'b>(
        &self,
        writer: &mut BlockWriter<'c, 'b>,
    ) -> Result<Value<'c, 'b>, Error> {
        let predicate = emit_blackbox_input(writer, self.predicate)?;
        let one = writer.emit_constant(&FieldElement::from(1u128))?;

        let pk_x_raw = pack_bytes_be_to_le_limbs(writer, self.public_key_x)?;
        let pk_y_raw = pack_bytes_be_to_le_limbs(writer, self.public_key_y)?;
        let safe_pk = emit_limbs_constant(writer, &SECP256K1_GX, &SECP256K1_GY)?;
        let pk_x = emit_select_limbs(writer, predicate, &pk_x_raw, &safe_pk.0)?;
        let pk_y = emit_select_limbs(writer, predicate, &pk_y_raw, &safe_pk.1)?;
        emit_assert_lt_modulus(writer, &pk_x, &SECP256K1_P)?;
        emit_assert_lt_modulus(writer, &pk_y, &SECP256K1_P)?;
        assert_on_curve(writer, &pk_x, &pk_y, &SECP256K1_PARAMS)?;
        let sig_r_bytes: &[FunctionInput<FieldElement>; 32] = self.signature[..32]
            .try_into()
            .expect("signature has at least 32 bytes");
        let sig_s_bytes: &[FunctionInput<FieldElement>; 32] = self.signature[32..64]
            .try_into()
            .expect("signature has 64 bytes");
        let sig_r_raw = pack_bytes_be_to_le_limbs(writer, sig_r_bytes)?;
        let sig_s_raw = pack_bytes_be_to_le_limbs(writer, sig_s_bytes)?;
        let z_raw = pack_bytes_be_to_le_limbs(writer, self.hashed_message)?;
        let zero_limbs = emit_zero_limbs(writer)?;
        let one_limbs = pack_u64_limbs(writer, &[1, 0, 0, 0])?;
        let sig_r = emit_select_limbs(writer, predicate, &sig_r_raw, &one_limbs)?;
        let sig_s = emit_select_limbs(writer, predicate, &sig_s_raw, &one_limbs)?;
        let z = emit_select_limbs(writer, predicate, &z_raw, &zero_limbs)?;

        emit_assert_lt_modulus(writer, &sig_r, &SECP256K1_N)?;
        emit_assert_lt_modulus(writer, &sig_s, &SECP256K1_N)?;
        let zero = writer.emit_constant(&FieldElement::from(0u128))?;
        let r_is_zero = emit_limbs_eq_boolean(writer, &sig_r, &zero_limbs)?;
        writer.insert_constrain_eq(r_is_zero, zero);
        let s_is_low = emit_limbs_lt_modulus_boolean(writer, &sig_s, &SECP256K1_HALF_N_PLUS_ONE)?;

        let s_inv = emit_inv_mod_p(writer, &sig_s, &SECP256K1_N)?;
        let u1 = emit_mul_mod_p(writer, &z, &s_inv, &SECP256K1_N)?;
        let u2 = emit_mul_mod_p(writer, &sig_r, &s_inv, &SECP256K1_N)?;

        let g = emit_limbs_constant(writer, &SECP256K1_GX, &SECP256K1_GY)?;
        let u1_bits = emit_bit_decompose_256(writer, &u1)?;
        let u2_bits = emit_bit_decompose_256(writer, &u2)?;
        let (r_x, _r_y, r_inf) = emit_joint_scalar_mul(
            writer,
            g,
            &u1_bits,
            (pk_x, pk_y),
            &u2_bits,
            &SECP256K1_PARAMS,
        )?;
        let r_is_finite = emit_not(writer, r_inf)?;
        let r_x_lt_n = emit_limbs_lt_modulus_boolean(writer, &r_x, &SECP256K1_N)?;

        let r_eq = emit_limbs_eq_boolean(writer, &r_x, &sig_r)?;
        let valid = writer.insert_mul(r_eq, r_is_finite)?;
        let valid = writer.insert_mul(valid, r_x_lt_n)?;
        let valid = writer.insert_mul(valid, s_is_low)?;
        emit_select_value(writer, predicate, valid, one)
    }
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
