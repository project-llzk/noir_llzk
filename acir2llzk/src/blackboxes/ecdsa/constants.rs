use crate::multiprec::LIMBS;

pub(crate) const ECDSA_PK_BYTES: usize = 32;
pub(crate) const ECDSA_SIG_BYTES: usize = 64;
pub(crate) const ECDSA_HASH_BYTES: usize = 32;

/// `pk_x + pk_y + sig + hashed_message + predicate` bytes.
pub(crate) const ECDSA_HELPER_INPUTS: usize =
    2 * ECDSA_PK_BYTES + ECDSA_SIG_BYTES + ECDSA_HASH_BYTES + 1;

pub(crate) const ECDSA_SECP256K1_COMPUTE_HELPER_NAME: &str = "ecdsa_secp256k1_compute";
pub(crate) const ECDSA_SECP256R1_COMPUTE_HELPER_NAME: &str = "ecdsa_secp256r1_compute";

pub(crate) const ECDSA_SECP256K1_MUL_MOD_N_HELPER_NAME: &str = "ecdsa_secp256k1_mul_mod_n";
pub(crate) const ECDSA_SECP256R1_MUL_MOD_N_HELPER_NAME: &str = "ecdsa_secp256r1_mul_mod_n";
pub(crate) const ECDSA_SECP256K1_MUL_MOD_P_HELPER_NAME: &str = "ecdsa_secp256k1_mul_mod_p";
pub(crate) const ECDSA_SECP256R1_MUL_MOD_P_HELPER_NAME: &str = "ecdsa_secp256r1_mul_mod_p";
pub(crate) const ECDSA_SECP256K1_INV_MOD_N_HELPER_NAME: &str = "ecdsa_secp256k1_inv_mod_n";
pub(crate) const ECDSA_SECP256R1_INV_MOD_N_HELPER_NAME: &str = "ecdsa_secp256r1_inv_mod_n";
pub(crate) const ECDSA_SECP256K1_INV_MOD_P_HELPER_NAME: &str = "ecdsa_secp256k1_inv_mod_p";
pub(crate) const ECDSA_SECP256R1_INV_MOD_P_HELPER_NAME: &str = "ecdsa_secp256r1_inv_mod_p";

/// secp256k1 base field: `p = 2^256 - 2^32 - 977`.
pub(super) const SECP256K1_P: [u64; LIMBS] = [
    0xFFFF_FFFE_FFFF_FC2F,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
];

pub(super) const SECP256K1_N: [u64; LIMBS] = [
    0xBFD2_5E8C_D036_4141,
    0xBAAE_DCE6_AF48_A03B,
    0xFFFF_FFFF_FFFF_FFFE,
    0xFFFF_FFFF_FFFF_FFFF,
];

/// `floor(n/2) + 1` — low-S threshold; valid signatures must satisfy `s <` this.
pub(super) const SECP256K1_HALF_N_PLUS_ONE: [u64; LIMBS] = [
    0xDFE9_2F46_681B_20A1,
    0x5D57_6E73_57A4_501D,
    0xFFFF_FFFF_FFFF_FFFF,
    0x7FFF_FFFF_FFFF_FFFF,
];

pub(super) const SECP256K1_B: [u64; LIMBS] = [7, 0, 0, 0];

pub(super) const SECP256K1_GX: [u64; LIMBS] = [
    0x59F2_815B_16F8_1798,
    0x029B_FCDB_2DCE_28D9,
    0x55A0_6295_CE87_0B07,
    0x79BE_667E_F9DC_BBAC,
];

pub(super) const SECP256K1_GY: [u64; LIMBS] = [
    0x9C47_D08F_FB10_D4B8,
    0xFD17_B448_A685_5419,
    0x5DA4_FBFC_0E11_08A8,
    0x483A_DA77_26A3_C465,
];

/// secp256r1 base field: `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`.
pub(super) const SECP256R1_P: [u64; LIMBS] = [
    0xFFFF_FFFF_FFFF_FFFF,
    0x0000_0000_FFFF_FFFF,
    0x0000_0000_0000_0000,
    0xFFFF_FFFF_0000_0001,
];

pub(super) const SECP256R1_N: [u64; LIMBS] = [
    0xF3B9_CAC2_FC63_2551,
    0xBCE6_FAAD_A717_9E84,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_0000_0000,
];

pub(super) const SECP256R1_HALF_N_PLUS_ONE: [u64; LIMBS] = [
    0x79DC_E561_7E31_92A9,
    0xDE73_7D56_D38B_CF42,
    0x7FFF_FFFF_FFFF_FFFF,
    0x7FFF_FFFF_8000_0000,
];

pub(super) const SECP256R1_B: [u64; LIMBS] = [
    0x3BCE_3C3E_27D2_604B,
    0x651D_06B0_CC53_B0F6,
    0xB3EB_BD55_7698_86BC,
    0x5AC6_35D8_AA3A_93E7,
];

pub(super) const SECP256R1_GX: [u64; LIMBS] = [
    0xF4A1_3945_D898_C296,
    0x7703_7D81_2DEB_33A0,
    0xF8BC_E6E5_63A4_40F2,
    0x6B17_D1F2_E12C_4247,
];

pub(super) const SECP256R1_GY: [u64; LIMBS] = [
    0xCBB6_4068_37BF_51F5,
    0x2BCE_3357_6B31_5ECE,
    0x8EE7_EB4A_7C0F_9E16,
    0x4FE3_42E2_FE1A_7F9B,
];
