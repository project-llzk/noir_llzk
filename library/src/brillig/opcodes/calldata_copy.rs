use acir::brillig::MemoryAddress;

use crate::error::Error;

use super::super::translator::TranslationCtx;
use super::BrilligHandler;

/// Handler for Brillig's `CalldataCopy`.
///
/// Requires call data to have been properly initialised by the regsitry
pub(super) struct CalldataCopyHandler;

impl BrilligHandler<'_> for CalldataCopyHandler {
    fn execute(
        &self,
        ctx: &mut TranslationCtx<'_, '_, '_>,
        opcode_index: usize,
    ) -> Result<(), Error> {
        let (dst_base, size, offset) =
            ctx.calldata_copy_params
                .ok_or_else(|| Error::UnsupportedBrillig {
                    reason: format!(
                        "CalldataCopy at bytecode index {opcode_index}: \
                     no precomputed params (walker should have inserted them; \
                     this is a translator bug)"
                    ),
                })?;

        if offset + size > ctx.calldata.len() {
            return Err(Error::UnsupportedBrillig {
                reason: format!(
                    "CalldataCopy at bytecode index {opcode_index}: calldata range \
                     [{offset}..{}] exceeds calldata length {}",
                    offset + size,
                    ctx.calldata.len()
                ),
            });
        }

        let dst_base = dst_base as usize;
        for j in 0..size {
            let addr = MemoryAddress::Direct((dst_base + j) as u32);
            let val = ctx.calldata[offset + j];
            ctx.writer.insert_write(addr, val)?;
        }
        Ok(())
    }
}
