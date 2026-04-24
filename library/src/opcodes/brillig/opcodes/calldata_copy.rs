use acir::brillig::MemoryAddress;

use crate::error::Error;

use super::super::translator::{OpcodeAction, TranslationCtx};
use super::{BrilligHandler, require_const};

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
        let size = require_const(ctx, self.size_address, "CalldataCopy", "size", i)?;
        let offset = require_const(ctx, self.offset_address, "CalldataCopy", "offset", i)?;
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
