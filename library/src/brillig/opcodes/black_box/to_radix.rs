use acir::{FieldElement, brillig::MemoryAddress};
use llzk::prelude::Value;

use crate::{
    Error,
    brillig::{memory::Memory, opcodes::require_const, translator::TranslationCtx},
    brillig_writer::BrilligWriter,
    writer::Writer,
};

pub(super) fn emit_to_radix<'c, 'b, M: Memory>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
    input_addr: MemoryAddress,
    radix: MemoryAddress,
    output_pointer_addr: MemoryAddress,
    num_limbs_addr: MemoryAddress,
    output_bits_addr: MemoryAddress,
) -> Result<(), Error> {
    let radix = require_const(ctx, radix, "ToRadix", "radix")?;
    let num_limbs = require_const(ctx, num_limbs_addr, "ToRadix", "num_limbs")?;
    let output_bits = require_const(ctx, output_bits_addr, "ToRadix", "output_bits")? != 0;

    if !(2..=256).contains(&radix) {
        return Err(Error::UnsupportedBrillig {
            reason: format!("ToRadix {radix} out of range [2, 256]"),
        });
    }
    if output_bits && radix != 2 {
        return Err(Error::UnsupportedBrillig {
            reason: format!("ToRadix output_bits=true requires radix=2, got {radix}"),
        });
    }

    let input = ctx.memory.read(ctx.writer, input_addr)?;
    let base_ptr = ctx.memory.read(ctx.writer, output_pointer_addr)?;
    let radix_val = ctx
        .writer
        .emit_constant(&FieldElement::from(radix as u128))?;

    let limbs = emit_limb_decomp(ctx.writer, input, radix_val, num_limbs)?;
    for (offset, &limb) in (0..num_limbs).rev().zip(limbs.iter()) {
        let offset_felt = ctx
            .writer
            .emit_constant(&FieldElement::from(offset as u128))?;
        let slot_felt = ctx.writer.insert_add(base_ptr, offset_felt)?;
        let slot_idx = ctx.writer.cast_to_index(slot_felt)?;
        ctx.writer.insert_ram_store(slot_idx, limb);
    }

    Ok(())
}

/// Peels `num_limbs` LSB-first limbs of `radix` from `input` using
/// `felt.uintdiv` / `felt.umod`. Asserts the high-order remainder is
/// zero so truncated decompositions are rejected during witness
/// generation, matching ACVM behaviour.
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
