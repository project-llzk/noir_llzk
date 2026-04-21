//! EcdsaSecp256k1 opcode — **stub**.
//!
//! Current state: packs `(pk_x, pk_y)` and the first 64 bytes of `signature`
//! into two secp256k1 affine points, drives `emit_point_add_affine` plus a
//! standalone `emit_inv_mod_p`, and writes `output = 1` unconditionally. Used
//! as a test vehicle for the multiprec and curve modules while ECDSA grows.

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
    multiprec::{LIMBS, Limbs256, emit_inv_mod_p},
    opcodes::{
        OpcodeEmitter, collect_input_witness,
        ecdsa::curve::{emit_point_add_affine, emit_point_double, emit_scalar_mul_known_msb},
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
        self.exercise_multiprec(writer)?;
        let one = writer.emit_constant(&FieldElement::from(1u128))?;
        writer.write_member(&format!("w{}", self.output.0), one)?;
        writer.mark_known(self.output.0, one);
        Ok(())
    }

    fn emit_constrain<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        self.exercise_multiprec(writer)?;
        let one = writer.emit_constant(&FieldElement::from(1u128))?;
        let actual = writer.read_witness(self.output.0)?;
        writer.insert_constrain_eq(actual, one);
        Ok(())
    }
}

impl EcdsaSecp256k1<'_> {
    /// Packs `(pk_x, pk_y)` and the first 64 bytes of signature into two
    /// secp256k1 affine points, drives `emit_point_add_affine`, and also
    /// exercises `emit_inv_mod_p` on `pk_x`. Temporary — will be replaced by
    /// real ECDSA verify logic.
    fn exercise_multiprec<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let p1_x = pack_bytes_be_to_le_limbs(writer, self.public_key_x)?;
        let p1_y = pack_bytes_be_to_le_limbs(writer, self.public_key_y)?;
        let sig_x: &[FunctionInput<FieldElement>; 32] = self.signature[..32]
            .try_into()
            .expect("signature has at least 32 bytes");
        let sig_y: &[FunctionInput<FieldElement>; 32] = self.signature[32..64]
            .try_into()
            .expect("signature has 64 bytes");
        let p2_x = pack_bytes_be_to_le_limbs(writer, sig_x)?;
        let p2_y = pack_bytes_be_to_le_limbs(writer, sig_y)?;
        let _sum = emit_point_add_affine(writer, (p1_x, p1_y), (p2_x, p2_y))?;
        let _inv = emit_inv_mod_p(writer, &p1_x, &SECP256K1_P)?;
        let _dbl = emit_point_double(writer, (p1_x, p1_y))?;

        // Exercise scalar mul for k = 3 (bits LSB-first: [1, 1]). Result = 3·p1.
        let one = writer.emit_constant(&FieldElement::from(1u128))?;
        let scalar_bits = [one, one];
        let _mul = emit_scalar_mul_known_msb(writer, (p1_x, p1_y), &scalar_bits)?;
        Ok(())
    }
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
