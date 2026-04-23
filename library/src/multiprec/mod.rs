//! Non-native 256-bit modular arithmetic, represented as 4 little-endian 64-bit limbs.
//!
//! Each primitive emits its constraint chain directly into a [`BlockWriter`]
//! (nondet witness + polynomial identity + range checks). Works in both
//! `@compute` and `@constrain` phases: in `@compute` the `constrain.eq` / `bool.assert`
//! ops are emitted but have no effect (the interpreter solves nondets); in
//! `@constrain` they form the verification.
//!
//! Parameterised by a constant prime `p` passed as `[u64; 4]` (little-endian limbs).

mod add;
mod bits;
mod common;
mod compare;
mod div;
mod inverse;
mod mul;
mod sub;

pub(crate) use add::emit_add_mod_p;
pub(crate) use bits::emit_bit_decompose_256;
pub(crate) use compare::{emit_assert_lt_modulus, emit_limbs_eq_boolean};
pub(crate) use div::{emit_div_mod_p, emit_safe_div_mod_p};
pub(crate) use inverse::emit_inv_mod_p;
pub(crate) use mul::emit_mul_mod_p;
pub(crate) use sub::emit_sub_mod_p;

use llzk::prelude::Value;

pub(crate) const LIMBS: usize = 4;
pub(crate) const LIMB_BITS: u32 = 64;

/// 256-bit value as 4 little-endian 64-bit limbs. Index 0 is the least-significant limb.
pub(crate) type Limbs256<'c, 'a> = [Value<'c, 'a>; LIMBS];
