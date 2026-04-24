use acir::FieldElement;
use acir::brillig::{BlackBoxOp, MemoryAddress};

use crate::error::Error;

use super::super::translator::{OpcodeAction, TranslationCtx};
use super::{BrilligHandler, require_const};

pub(super) struct BlackBoxHandler<'a> {
    pub op: &'a BlackBoxOp,
}

impl<'a> BrilligHandler<'a> for BlackBoxHandler<'a> {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        match self.op {
            BlackBoxOp::ToRadix {
                input,
                radix,
                output_pointer,
                num_limbs,
                output_bits,
            } => emit_to_radix(
                ctx,
                opcode_index,
                *input,
                *radix,
                *output_pointer,
                *num_limbs,
                *output_bits,
            ),
            other => Err(Error::UnsupportedBrillig {
                reason: format!(
                    "Brillig BlackBoxOp `{other:?}` at bytecode index {opcode_index} is not supported \
                     (only ToRadix is implemented in Brillig; other blackboxes route through ACIR)"
                ),
            }),
        }
    }
}

fn emit_to_radix<'c, 'b>(
    ctx: &mut TranslationCtx<'c, 'b, '_>,
    opcode_index: usize,
    input_addr: MemoryAddress,
    radix_addr: MemoryAddress,
    output_pointer_addr: MemoryAddress,
    num_limbs_addr: MemoryAddress,
    output_bits_addr: MemoryAddress,
) -> Result<OpcodeAction<'c, 'b>, Error> {
    let radix = require_const(ctx, radix_addr, "ToRadix", "radix", opcode_index)?;
    let num_limbs = require_const(ctx, num_limbs_addr, "ToRadix", "num_limbs", opcode_index)?;
    let output_bits = require_const(
        ctx,
        output_bits_addr,
        "ToRadix",
        "output_bits",
        opcode_index,
    )? != 0;

    if !(2..=256).contains(&radix) {
        return Err(Error::UnsupportedBrillig {
            reason: format!(
                "ToRadix at bytecode index {opcode_index}: radix {radix} out of range [2, 256]"
            ),
        });
    }
    if output_bits && radix != 2 {
        return Err(Error::UnsupportedBrillig {
            reason: format!(
                "ToRadix at bytecode index {opcode_index}: output_bits=true requires radix=2, got {radix}"
            ),
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

    Ok(OpcodeAction::Continue)
}
