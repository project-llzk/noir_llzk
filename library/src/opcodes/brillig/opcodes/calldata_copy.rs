use acir::brillig::MemoryAddress;

use crate::error::Error;

use super::super::translator::{OpcodeAction, TranslationCtx};
use super::BrilligHandler;

pub(crate) struct CalldataCopyHandler {
    pub destination_address: MemoryAddress,
    pub size_address: MemoryAddress,
    pub offset_address: MemoryAddress,
}

impl BrilligHandler<'_> for CalldataCopyHandler {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        i: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let size = *ctx.known_constants.get(&self.size_address).ok_or_else(|| {
            Error::UnsupportedBrillig {
                reason: format!(
                    "CalldataCopy at bytecode index {i}: size register {} \
                     is not a known integer constant",
                    self.size_address.to_u32()
                ),
            }
        })?;
        let offset = *ctx
            .known_constants
            .get(&self.offset_address)
            .ok_or_else(|| Error::UnsupportedBrillig {
                reason: format!(
                    "CalldataCopy at bytecode index {i}: offset register {} \
                         is not a known integer constant",
                    self.offset_address.to_u32()
                ),
            })?;
        if offset + size > ctx.calldata.len() {
            return Err(Error::UnsupportedBrillig {
                reason: format!(
                    "CalldataCopy at bytecode index {i}: calldata range \
                     [{offset}..{}] exceeds calldata length {}",
                    offset + size,
                    ctx.calldata.len()
                ),
            });
        }
        let dst_base = self.destination_address.to_u32();
        for j in 0..size {
            let addr = MemoryAddress::Direct(dst_base + j as u32);
            let val = ctx.calldata[offset + j];
            ctx.regmap.set(addr, val);
            let idx = ctx.writer.insert_integer(dst_base as usize + j)?;
            ctx.writer.insert_ram_store(idx, val);
        }
        Ok(OpcodeAction::Continue)
    }
}
