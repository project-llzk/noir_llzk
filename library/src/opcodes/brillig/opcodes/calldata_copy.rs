use acir::brillig::MemoryAddress;

use crate::error::Error;

use super::super::translator::{OpcodeAction, TranslationCtx};
use super::BrilligHandler;

/// Handler for Brillig's `CalldataCopy`.
///
/// Requires `size_address` and `offset_address` to be tracked integer
/// constants (populated by a preceding `Const` opcode). Noir's
/// `calldata_copy_instruction` in `brillig_ir/instructions.rs` guarantees
/// this by emitting `Const` opcodes for both registers immediately before
/// the `CalldataCopy`. Bytecode that computes these values at runtime is
/// rejected with `UnsupportedBrillig`.
pub(super) struct CalldataCopyHandler {
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
        let size =
            ctx.memory
                .get_const(self.size_address)?
                .ok_or_else(|| Error::UnsupportedBrillig {
                    reason: format!(
                        "CalldataCopy at bytecode index {i}: size register {} \
                     is not a known integer constant",
                        self.size_address.to_u32()
                    ),
                })?;
        let offset = ctx.memory.get_const(self.offset_address)?.ok_or_else(|| {
            Error::UnsupportedBrillig {
                reason: format!(
                    "CalldataCopy at bytecode index {i}: offset register {} \
                         is not a known integer constant",
                    self.offset_address.to_u32()
                ),
            }
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
        let MemoryAddress::Direct(dst_base) = ctx.memory.resolve(self.destination_address)? else {
            unreachable!("Memory::resolve only returns Direct");
        };
        let dst_base = dst_base as usize;
        for j in 0..size {
            let addr = MemoryAddress::Direct((dst_base + j) as u32);
            let val = ctx.calldata[offset + j];
            ctx.memory.write(ctx.writer, addr, val)?;
        }
        Ok(OpcodeAction::Continue)
    }
}
