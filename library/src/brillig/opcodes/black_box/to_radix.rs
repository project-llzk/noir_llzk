use acir::{FieldElement, brillig::MemoryAddress};
use llzk::prelude::{Block, BlockLike, Value};

use crate::{
    Error, brillig::translator::TranslationCtx, brillig_writer::BrilligWriter, writer::Writer,
};

/// Lowers `BlackBoxOp::ToRadix` with all parameters read at runtime.
///
/// Decomposes `input` into `num_limbs` limbs base `radix`, storing each
/// limb at `output_pointer + offset` where `offset = num_limbs - 1 - i`
/// (big-endian: LSB at the highest offset, MSB at offset 0).
pub(super) fn emit_to_radix(
    ctx: &mut TranslationCtx<'_, '_, '_>,
    input_addr: MemoryAddress,
    radix_addr: MemoryAddress,
    output_pointer_addr: MemoryAddress,
    num_limbs_addr: MemoryAddress,
    output_bits_addr: MemoryAddress,
) -> Result<(), Error> {
    let input = ctx.memory.read(ctx.writer, input_addr)?;
    let radix = ctx.memory.read(ctx.writer, radix_addr)?;
    let num_limbs_felt = ctx.memory.read(ctx.writer, num_limbs_addr)?;
    let num_limbs_idx = ctx.writer.cast_to_index(num_limbs_felt)?;
    let base_ptr_felt = ctx.memory.read(ctx.writer, output_pointer_addr)?;
    let base_ptr_idx = ctx.writer.cast_to_index(base_ptr_felt)?;
    let output_bits = ctx.memory.read(ctx.writer, output_bits_addr)?;

    // `output_bits == 1 -> radix == 2`.
    let two = ctx.writer.emit_constant(&FieldElement::from(2u128))?;
    let radix_is_two_i1 = ctx.writer.insert_bool_eq(radix, two)?;
    let radix_is_two_felt = ctx.writer.insert_cast_to_felt(radix_is_two_i1)?;
    let radix_when_binary = ctx.writer.insert_bool_le(output_bits, radix_is_two_felt)?;
    ctx.writer.insert_bool_assert(radix_when_binary)?;

    let working = emit_decomp_dynamic(ctx.writer, input, radix, num_limbs_idx, base_ptr_idx)?;

    // High-order remainder must be zero, otherwise the
    // input doesn't fit in `num_limbs` limbs of `radix`.
    let zero = ctx.writer.emit_constant(&FieldElement::from(0u128))?;
    let fits = ctx.writer.insert_bool_eq(working, zero)?;
    ctx.writer.insert_bool_assert(fits)
}

/// Emits decomposition into radix where the number of limbs
/// is not known at compile time
fn emit_decomp_dynamic<'c, 'b>(
    writer: &mut BrilligWriter<'c, 'b>,
    input: Value<'c, 'b>,
    radix: Value<'c, 'b>,
    num_limbs_idx: Value<'c, 'b>,
    base_ptr_idx: Value<'c, 'b>,
) -> Result<Value<'c, 'b>, Error> {
    let index_ty = writer.index_type();
    let felt_ty = writer.felt_type();
    let location = writer.location();
    let zero_idx = writer.insert_integer(0)?;
    let one_idx = writer.insert_integer(1)?;
    // `last_offset = num_limbs - 1`. With `num_limbs == 0` the before-test
    // `i < num_limbs` immediately exits, so this subtraction's underflow
    // (it lives in the body block but never runs) is harmless.
    let last_offset_idx = writer.insert_index_sub(num_limbs_idx, one_idx)?;

    // before-block: args (i: index, working: felt). Yields
    // `scf.condition(i < num_limbs, [i, working])`.
    let before_block = Block::new(&[(index_ty, location), (felt_ty, location)]);
    let i_before: Value<'c, '_> = before_block.argument(0)?.into();
    let working_before: Value<'c, '_> = before_block.argument(1)?.into();
    let saved = writer.enter_block(&before_block);
    let cond = writer.insert_cmpi_slt(i_before, num_limbs_idx)?;
    writer.insert_scf_condition(cond, &[i_before, working_before]);
    writer.leave_block(saved);

    // after-block: args (i, working). Computes limb / quot, stores limb at
    // `base + (last_offset - i)`, yields `(i+1, quot)`.
    let after_block = Block::new(&[(index_ty, location), (felt_ty, location)]);
    let i_after: Value<'c, '_> = after_block.argument(0)?.into();
    let working_after: Value<'c, '_> = after_block.argument(1)?.into();
    let saved = writer.enter_block(&after_block);
    let limb = writer.insert_umod(working_after, radix)?;
    let quot = writer.insert_uintdiv(working_after, radix)?;
    let offset_idx = writer.insert_index_sub(last_offset_idx, i_after)?;
    let slot_idx = writer.insert_index_add(base_ptr_idx, offset_idx)?;
    writer.insert_ram_store(slot_idx, limb);
    let next_i = writer.insert_index_add(i_after, one_idx)?;
    writer.insert_scf_yield(&[next_i, quot]);
    writer.leave_block(saved);

    let while_op = writer.insert_scf_while_op(
        &[zero_idx, input],
        &[index_ty, felt_ty],
        before_block,
        after_block,
    )?;
    // The loop's second result is the final `working` value, yielded out
    // of the before-region's `scf.condition` when the loop exits.
    Ok(while_op.result(1)?.into())
}

/// Peels `num_limbs` LSB-first limbs of `radix` from `input` using
/// `felt.uintdiv` / `felt.umod`. Asserts the high-order remainder is
/// zero so truncated decompositions are rejected during witness
/// generation, matching ACVM behaviour.
///
/// Used when `num_limbs` is known a known constant (e.g in MSM).
pub(super) fn emit_limb_decomp<'c, 'b>(
    writer: &mut BrilligWriter<'c, 'b>,
    input: Value<'c, 'b>,
    radix: Value<'c, 'b>,
    num_limbs: usize,
) -> Result<Vec<Value<'c, 'b>>, Error> {
    let mut limbs = Vec::with_capacity(num_limbs);
    let mut working = input;
    for _ in 0..num_limbs {
        let quot = writer.insert_uintdiv(working, radix)?;
        let limb = writer.insert_umod(working, radix)?;
        limbs.push(limb);
        working = quot;
    }
    let zero = writer.emit_constant(&FieldElement::from(0u128))?;
    let fits = writer.insert_bool_eq(working, zero)?;
    writer.insert_bool_assert(fits)?;
    Ok(limbs)
}
