pub(crate) mod cipher;
pub(crate) mod common;
pub(crate) mod ecdsa;
pub(crate) mod grumpkin;
pub(crate) mod hash;
pub(crate) mod registry;

use acir::{FieldElement, circuit::Opcode};

use crate::{
    error::Error,
    opcodes::{
        TranslatedOpcode, aes128, bitwise, blake2s, blake3, ecdsa as ecdsa_opcodes,
        grumpkin as grumpkin_opcodes, keccak, poseidon2, sha256,
    },
};

/// Dispatches a [`BlackBoxFuncCall`](acir::circuit::opcodes::BlackBoxFuncCall) opcode
/// to its handler.
pub(crate) fn build_blackbox_handler<'a>(
    opcode: &'a Opcode<FieldElement>,
) -> Result<Option<TranslatedOpcode<'a>>, Error> {
    if let Some(curve_add_op) = grumpkin_opcodes::embedded_curve_add::from_opcode(opcode) {
        return Ok(Some(Box::new(curve_add_op)));
    }

    if let Some(msm_op) = grumpkin_opcodes::multi_scalar_mul::from_opcode(opcode) {
        return Ok(Some(Box::new(msm_op)));
    }

    if let Some(range_op) = bitwise::rangecheck::from_opcode(opcode) {
        return Ok(Some(Box::new(range_op)));
    }

    if let Some(xor_op) = bitwise::xor::from_opcode(opcode) {
        return Ok(Some(Box::new(xor_op)));
    }

    if let Some(and_op) = bitwise::and::from_opcode(opcode) {
        return Ok(Some(Box::new(and_op)));
    }

    if let Some(blake2s_op) = blake2s::from_opcode(opcode)? {
        return Ok(Some(Box::new(blake2s_op)));
    }

    if let Some(blake3_op) = blake3::from_opcode(opcode)? {
        return Ok(Some(Box::new(blake3_op)));
    }

    if let Some(sha256_op) = sha256::from_opcode(opcode)? {
        return Ok(Some(Box::new(sha256_op)));
    }

    if let Some(aes_op) = aes128::from_opcode(opcode)? {
        return Ok(Some(Box::new(aes_op)));
    }

    if let Some(keccak_op) = keccak::from_opcode(opcode)? {
        return Ok(Some(Box::new(keccak_op)));
    }

    if let Some(poseidon2_op) = poseidon2::from_opcode(opcode)? {
        return Ok(Some(Box::new(poseidon2_op)));
    }

    if let Some(ecdsa_op) = ecdsa_opcodes::from_opcode(opcode)? {
        return Ok(Some(Box::new(ecdsa_op)));
    }

    Ok(None)
}
