//! Shared ECDSA blackbox helpers.
//!
//! ACIR and Brillig wrappers both call into this module; they should only
//! marshal their own opcode shapes and leave the actual LLZK helper emission
//! here.

pub(crate) mod constants;
mod curve;
mod limbs;
mod modular;
mod point;
mod verify;

pub(crate) use constants::{
    ECDSA_HASH_BYTES, ECDSA_HELPER_INPUTS, ECDSA_PK_BYTES, ECDSA_SECP256K1_COMPUTE_HELPER_NAME,
    ECDSA_SECP256K1_INV_MOD_N_HELPER_NAME, ECDSA_SECP256K1_INV_MOD_P_HELPER_NAME,
    ECDSA_SECP256K1_MUL_MOD_N_HELPER_NAME, ECDSA_SECP256K1_MUL_MOD_P_HELPER_NAME,
    ECDSA_SECP256R1_COMPUTE_HELPER_NAME, ECDSA_SECP256R1_INV_MOD_N_HELPER_NAME,
    ECDSA_SECP256R1_INV_MOD_P_HELPER_NAME, ECDSA_SECP256R1_MUL_MOD_N_HELPER_NAME,
    ECDSA_SECP256R1_MUL_MOD_P_HELPER_NAME, ECDSA_SIG_BYTES,
};
pub(crate) use modular::{
    emit_secp256k1_inv_mod_n_helper, emit_secp256k1_inv_mod_p_helper,
    emit_secp256k1_mul_mod_n_helper, emit_secp256k1_mul_mod_p_helper,
    emit_secp256r1_inv_mod_n_helper, emit_secp256r1_inv_mod_p_helper,
    emit_secp256r1_mul_mod_n_helper, emit_secp256r1_mul_mod_p_helper,
};
pub(crate) use verify::{emit_secp256k1_compute_helper, emit_secp256r1_compute_helper};

#[cfg(all(test, feature = "e2e"))]
mod tests;
