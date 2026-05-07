//! Handler for Brillig's `BlackBox` (built-in compute escape).
//!
//! Brillig `BlackBoxOp` variants name native compute functions the VM
//! offers as building blocks (hashes, EC ops, etc.). For circuit
//! emission we route them through the same shared helpers the ACIR
//! `BlackBoxFuncCall` path uses — felt-in / felt-out top-level
//! functions registered via [`BlackboxFunction`].
//!
//! Per variant: read the input felts out of the source `HeapArray`,
//! call the helper, write the result felts back into the destination
//! `HeapArray`. `HeapArray` pointers are read at runtime — the
//! pointer register's felt is loaded once via `ram.load`, cast to
//! `index`, and then `base + i` slot indices are computed for each
//! element.
//!
//! Variants that still need extra constraint/hint plumbing currently return
//! [`Error::UnsupportedBrillig`]; see each one's match arm for details.

use acir::brillig::{BlackBoxOp, MemoryAddress};
use llzk::prelude::{OperationRef, Value};

use crate::error::Error;

use super::super::memory::Memory;
use super::super::translator::TranslationCtx;
use super::BrilligHandler;

mod aes128;
mod blake2s;
mod blake3;
mod ecdsa;
mod embedded_curve_add;
mod keccak;
mod poseidon2;
mod sha256;
mod to_radix;

use aes128::emit_aes128;
use blake2s::emit_blake2s;
use blake3::emit_blake3;
use ecdsa::emit_ecdsa;
use embedded_curve_add::emit_embedded_curve_add;
use keccak::emit_keccakf1600;
use poseidon2::emit_poseidon2;
use sha256::emit_sha256_compression;
use to_radix::emit_to_radix;

pub(super) struct BlackBoxOpHandler<'a> {
    pub op: &'a BlackBoxOp,
}

impl<'a, M: Memory> BrilligHandler<'a, M> for BlackBoxOpHandler<'a> {
    fn execute(
        &self,
        ctx: &mut TranslationCtx<'_, '_, '_, M>,
        opcode_index: usize,
    ) -> Result<(), Error> {
        match self.op {
            BlackBoxOp::Poseidon2Permutation { message, output } => {
                emit_poseidon2(ctx, message, output, opcode_index)
            }
            BlackBoxOp::Sha256Compression {
                input,
                hash_values,
                output,
            } => emit_sha256_compression(ctx, input, hash_values, output, opcode_index),
            BlackBoxOp::Keccakf1600 { input, output } => {
                emit_keccakf1600(ctx, input, output, opcode_index)
            }
            BlackBoxOp::Blake2s { message, output } => {
                emit_blake2s(ctx, message, output, opcode_index)
            }
            BlackBoxOp::Blake3 { message, output } => {
                emit_blake3(ctx, message, output, opcode_index)
            }
            BlackBoxOp::AES128Encrypt {
                inputs,
                iv,
                key,
                outputs,
            } => emit_aes128(ctx, inputs, iv, key, outputs, opcode_index),
            BlackBoxOp::EmbeddedCurveAdd {
                input1_x,
                input1_y,
                input1_infinite,
                input2_x,
                input2_y,
                input2_infinite,
                result,
            } => emit_embedded_curve_add(
                ctx,
                *input1_x,
                *input1_y,
                *input1_infinite,
                *input2_x,
                *input2_y,
                *input2_infinite,
                result,
                opcode_index,
            ),
            BlackBoxOp::EcdsaSecp256k1 {
                hashed_msg,
                public_key_x,
                public_key_y,
                signature,
                result,
            } => emit_ecdsa(
                ctx,
                crate::blackboxes::registry::BlackboxFunction::EcdsaSecp256k1Compute,
                hashed_msg,
                public_key_x,
                public_key_y,
                signature,
                *result,
                opcode_index,
            ),
            BlackBoxOp::EcdsaSecp256r1 {
                hashed_msg,
                public_key_x,
                public_key_y,
                signature,
                result,
            } => emit_ecdsa(
                ctx,
                crate::blackboxes::registry::BlackboxFunction::EcdsaSecp256r1Compute,
                hashed_msg,
                public_key_x,
                public_key_y,
                signature,
                *result,
                opcode_index,
            ),
            BlackBoxOp::ToRadix {
                input,
                radix,
                output_pointer,
                num_limbs,
                output_bits,
            } => emit_to_radix(ctx, *input, *radix, *output_pointer, *num_limbs, *output_bits),
            // `MultiScalarMul`'s shared helper takes per-scalar bit
            // arrays (254 bits each). Brillig hands us raw lo/hi limbs,
            // so wiring this would mean nondet-decomposing each scalar
            // into bits and emitting range / reconstruction constraints
            // — same work the ACIR side does in `emit_scalar_constraints`.
            BlackBoxOp::MultiScalarMul { .. } => Err(Error::UnsupportedBrillig {
                reason: format!(
                    "BlackBox at bytecode index {opcode_index}: variant {} \
                     is not yet supported",
                    self.op
                ),
            }),
        }
    }
}

/// Loads `size` consecutive felts from a Brillig `HeapArray` whose base
/// address is held at runtime in `pointer`'s register slot. Emits one
/// `ram.load` + `cast.toindex` for the pointer felt, then `size`
/// `ram.load`s at `base + i`.
pub(super) fn read_heap_array<'c, 'b, M: Memory>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
    pointer: MemoryAddress,
    size: usize,
) -> Result<Vec<Value<'c, 'b>>, Error> {
    let base = resolve_base(ctx, pointer)?;
    (0..size)
        .map(|i| {
            let slot = slot_at_offset(ctx, base, i)?;
            ctx.writer.insert_ram_load(slot)
        })
        .collect()
}

/// Stores `size` felts into `size` consecutive `HeapArray` slots
/// whose base is read at runtime from `pointer`'s register. Mirrors
/// [`read_heap_array`]. `values.len()` must equal `size`.
pub(super) fn write_heap_array<'c, 'b, M: Memory>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
    pointer: MemoryAddress,
    size: usize,
    values: &[Value<'c, 'b>],
) -> Result<(), Error> {
    debug_assert_eq!(
        size,
        values.len(),
        "write_heap_array: size must match values length"
    );
    let base = resolve_base(ctx, pointer)?;
    for (i, &value) in values.iter().enumerate() {
        let slot = slot_at_offset(ctx, base, i)?;
        ctx.writer.insert_ram_store(slot, value);
    }
    Ok(())
}

/// Collects the first `count` results of a `function.call` op as
/// felt-typed `Value`s.
pub(super) fn collect_results<'c, 'b>(
    call: OperationRef<'c, 'b>,
    count: usize,
) -> Result<Vec<Value<'c, 'b>>, Error> {
    (0..count)
        .map(|i| call.result(i).map(Into::into).map_err(Error::from))
        .collect()
}

/// Reads the felt held in `pointer`'s register slot and casts it to
/// the `index`-typed SSA value used as a base address for `ram.load` /
/// `ram.store`.
fn resolve_base<'c, 'b, M: Memory>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
    pointer: MemoryAddress,
) -> Result<Value<'c, 'b>, Error> {
    let ptr_felt = ctx.memory.read(ctx.writer, pointer)?;
    ctx.writer.cast_to_index(ptr_felt)
}

/// Returns `base` itself when `offset == 0`; otherwise `base +
/// arith.constant offset` as an `index`-typed value.
fn slot_at_offset<'c, 'b, M: Memory>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
    base: Value<'c, 'b>,
    offset: usize,
) -> Result<Value<'c, 'b>, Error> {
    if offset == 0 {
        return Ok(base);
    }
    let off = ctx.writer.insert_integer(offset)?;
    ctx.writer.insert_index_add(base, off)
}
