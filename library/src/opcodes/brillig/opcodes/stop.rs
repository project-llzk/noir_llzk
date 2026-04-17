use crate::error::Error;

use super::super::translator::{OpcodeAction, TranslationCtx};
use super::BrilligHandler;

pub(crate) struct StopHandler<'a> {
    pub return_data: &'a acir::brillig::HeapVector,
}

impl<'a> BrilligHandler<'a> for StopHandler<'a> {
    fn execute<'c, 'b>(
        &self,
        ctx: &mut TranslationCtx<'c, 'b, '_>,
        opcode_index: usize,
    ) -> Result<OpcodeAction<'c, 'b>, Error> {
        let returns = ctx.emit_return_data(self.return_data, opcode_index)?;
        Ok(OpcodeAction::Return(returns))
    }
}
