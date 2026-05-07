use acir::{FieldElement, brillig::MemoryAddress};

use crate::{
    Error,
    opcodes::brillig::{memory::Memory, opcodes::require_const, translator::TranslationCtx},
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

    let mut working = input;
    for offset in (0..num_limbs).rev() {
        let quot = ctx.writer.insert_uintdiv(working, radix_val)?;
        let limb = ctx.writer.insert_umod(working, radix_val)?;
        let offset_felt = ctx
            .writer
            .emit_constant(&FieldElement::from(offset as u128))?;
        let slot_felt = ctx.writer.insert_add(base_ptr, offset_felt)?;
        let slot_idx = ctx.writer.cast_to_index(slot_felt)?;
        ctx.writer.insert_ram_store(slot_idx, limb);
        working = quot;
    }

    // ACVM rejects truncated decompositions during witness generation.
    let zero = ctx.writer.emit_constant(&FieldElement::from(0u128))?;
    let fits_in_limbs = ctx.writer.insert_bool_eq(working, zero)?;
    ctx.writer.insert_bool_assert(fits_in_limbs)?;

    Ok(())
}
