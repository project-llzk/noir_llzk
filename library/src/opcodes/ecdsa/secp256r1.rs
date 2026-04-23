//! EcdsaSecp256r1 opcode — complete verification.
//!
//! Structurally identical to [`super::secp256k1`]. Only the curve constants
//! change: secp256r1 uses `y² = x³ - 3·x + b` with `a = -3 mod p`, different
//! `p`, `n`, `G`, and `b`.

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
        emit_add_mod_p, emit_assert_lt_modulus, emit_bit_decompose_256, emit_inv_mod_p,
        emit_limbs_eq_boolean, emit_mul_mod_p, emit_zero_limbs,
    },
    opcodes::{
        OpcodeEmitter, collect_input_witness,
        ecdsa::{
            curve::{
                CurveParams, assert_on_curve, emit_point_add_complete, emit_scalar_mul_general,
            },
            shared::{emit_limbs_constant, pack_bytes_be_to_le_limbs},
        },
        emit_blackbox_input,
    },
};

/// secp256r1 base field p = 2^256 − 2^224 + 2^192 + 2^96 − 1.
/// p = 0xFFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF.
pub(super) const SECP256R1_P: [u64; 4] = [
    0xFFFF_FFFF_FFFF_FFFF,
    0x0000_0000_FFFF_FFFF,
    0x0000_0000_0000_0000,
    0xFFFF_FFFF_0000_0001,
];

/// secp256r1 scalar order n.
/// n = 0xFFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551.
pub(super) const SECP256R1_N: [u64; 4] = [
    0xF3B9_CAC2_FC63_2551,
    0xBCE6_FAAD_A717_9E84,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_0000_0000,
];

/// secp256r1 a coefficient = -3 mod p = p - 3.
pub(super) const SECP256R1_A: [u64; 4] = [
    0xFFFF_FFFF_FFFF_FFFC,
    0x0000_0000_FFFF_FFFF,
    0x0000_0000_0000_0000,
    0xFFFF_FFFF_0000_0001,
];

/// secp256r1 b coefficient.
/// b = 0x5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B.
pub(super) const SECP256R1_B: [u64; 4] = [
    0x3BCE_3C3E_27D2_604B,
    0x651D_06B0_CC53_B0F6,
    0xB3EB_BD55_7698_86BC,
    0x5AC6_35D8_AA3A_93E7,
];

/// secp256r1 generator G.x.
/// = 0x6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0 F4A13945 D898C296.
pub(super) const SECP256R1_GX: [u64; 4] = [
    0xF4A1_3945_D898_C296,
    0x7703_7D81_2DEB_33A0,
    0xF8BC_E6E5_63A4_40F2,
    0x6B17_D1F2_E12C_4247,
];

/// secp256r1 generator G.y.
/// = 0x4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 2BCE3357 6B315ECE CBB64068 37BF51F5.
pub(super) const SECP256R1_GY: [u64; 4] = [
    0xCBB6_4068_37BF_51F5,
    0x2BCE_3357_6B31_5ECE,
    0x8EE7_EB4A_7C0F_9E16,
    0x4FE3_42E2_FE1A_7F9B,
];

const SECP256R1_PARAMS: CurveParams = CurveParams {
    p: SECP256R1_P,
    a: SECP256R1_A,
    b: SECP256R1_B,
};

pub(crate) struct EcdsaSecp256r1<'a> {
    public_key_x: &'a [FunctionInput<FieldElement>; 32],
    public_key_y: &'a [FunctionInput<FieldElement>; 32],
    signature: &'a [FunctionInput<FieldElement>; 64],
    hashed_message: &'a [FunctionInput<FieldElement>; 32],
    predicate: &'a FunctionInput<FieldElement>,
    output: Witness,
}

impl OpcodeEmitter for EcdsaSecp256r1<'_> {
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
        let predicate = emit_blackbox_input(writer, self.predicate)?;
        let zero = writer.emit_constant(&FieldElement::from(0u128))?;
        let neg_valid = writer.insert_neg(is_valid)?;
        let diff = writer.insert_add(actual, neg_valid)?;
        let gated = writer.insert_mul(predicate, diff)?;
        writer.insert_constrain_eq(gated, zero);
        Ok(())
    }
}

impl EcdsaSecp256r1<'_> {
    fn emit_verify_body<'c, 'b>(
        &self,
        writer: &mut BlockWriter<'c, 'b>,
    ) -> Result<Value<'c, 'b>, Error> {
        let pk_x = pack_bytes_be_to_le_limbs(writer, self.public_key_x)?;
        let pk_y = pack_bytes_be_to_le_limbs(writer, self.public_key_y)?;
        assert_on_curve(writer, &pk_x, &pk_y, &SECP256R1_PARAMS)?;
        let sig_r_bytes: &[FunctionInput<FieldElement>; 32] = self.signature[..32]
            .try_into()
            .expect("signature has at least 32 bytes");
        let sig_s_bytes: &[FunctionInput<FieldElement>; 32] = self.signature[32..64]
            .try_into()
            .expect("signature has 64 bytes");
        let sig_r = pack_bytes_be_to_le_limbs(writer, sig_r_bytes)?;
        let sig_s = pack_bytes_be_to_le_limbs(writer, sig_s_bytes)?;
        let z = pack_bytes_be_to_le_limbs(writer, self.hashed_message)?;

        emit_assert_lt_modulus(writer, &sig_r, &SECP256R1_N)?;
        emit_assert_lt_modulus(writer, &sig_s, &SECP256R1_N)?;
        let zero = writer.emit_constant(&FieldElement::from(0u128))?;
        let zero_limbs = emit_zero_limbs(writer)?;
        let r_is_zero = emit_limbs_eq_boolean(writer, &sig_r, &zero_limbs)?;
        writer.insert_constrain_eq(r_is_zero, zero);

        let s_inv = emit_inv_mod_p(writer, &sig_s, &SECP256R1_N)?;
        let u1 = emit_mul_mod_p(writer, &z, &s_inv, &SECP256R1_N)?;
        let u2 = emit_mul_mod_p(writer, &sig_r, &s_inv, &SECP256R1_N)?;

        let g = emit_limbs_constant(writer, &SECP256R1_GX, &SECP256R1_GY)?;
        let u1_bits = emit_bit_decompose_256(writer, &u1)?;
        let r1 = emit_scalar_mul_general(writer, g, &u1_bits, &SECP256R1_PARAMS)?;
        let u2_bits = emit_bit_decompose_256(writer, &u2)?;
        let r2 = emit_scalar_mul_general(writer, (pk_x, pk_y), &u2_bits, &SECP256R1_PARAMS)?;
        let (r_x, _r_y, r_inf) = emit_point_add_complete(writer, r1, r2, &SECP256R1_PARAMS)?;
        writer.insert_constrain_eq(r_inf, zero);

        let r_x_mod_n = emit_add_mod_p(writer, &r_x, &zero_limbs, &SECP256R1_N)?;
        emit_assert_lt_modulus(writer, &r_x_mod_n, &SECP256R1_N)?;

        emit_limbs_eq_boolean(writer, &r_x_mod_n, &sig_r)
    }
}

pub(crate) fn from_opcode<'a>(opcode: &'a Opcode<FieldElement>) -> Option<EcdsaSecp256r1<'a>> {
    match opcode {
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::EcdsaSecp256r1 {
            public_key_x,
            public_key_y,
            signature,
            hashed_message,
            predicate,
            output,
        }) => Some(EcdsaSecp256r1 {
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
