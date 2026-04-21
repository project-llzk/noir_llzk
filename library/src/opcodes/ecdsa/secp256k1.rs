//! EcdsaSecp256k1 opcode — **stub**.
//!
//! Current state: wires a single `emit_add_mod_p` call (on hardcoded constants)
//! into the @compute and @constrain bodies, writes `output = 1` unconditionally.
//! Used as a test vehicle for the multiprec module while we grow it.

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
    multiprec::{LIMBS, Limbs256, emit_add_mod_p, emit_inv_mod_p, emit_mul_mod_p, emit_sub_mod_p},
    opcodes::{OpcodeEmitter, collect_input_witness, emit_blackbox_input},
};

/// secp256k1 base field modulus: 2^256 - 2^32 - 977, little-endian 64-bit limbs.
const SECP256K1_P: [u64; 4] = [
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
    /// Packs pk_x and the first 32 bytes of signature into 4-limb little-endian
    /// integers and feeds them to `emit_add_mod_p` and `emit_sub_mod_p`.
    /// Temporary — will be replaced by real ECDSA verify logic.
    fn exercise_multiprec<'c, 'b>(&self, writer: &mut BlockWriter<'c, 'b>) -> Result<(), Error> {
        let a = pack_bytes_be_to_le_limbs(writer, self.public_key_x)?;
        let sig_r: &[FunctionInput<FieldElement>; 32] = self.signature[..32]
            .try_into()
            .expect("signature has at least 32 bytes");
        let b = pack_bytes_be_to_le_limbs(writer, sig_r)?;
        let _add = emit_add_mod_p(writer, &a, &b, &SECP256K1_P)?;
        let _sub = emit_sub_mod_p(writer, &a, &b, &SECP256K1_P)?;
        let _mul = emit_mul_mod_p(writer, &a, &b, &SECP256K1_P)?;
        let _inv = emit_inv_mod_p(writer, &a, &SECP256K1_P)?;
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
