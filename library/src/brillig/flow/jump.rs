use acir::brillig::Label;

use crate::error::Error;

use super::super::cfg::Terminator;
use super::{ClassifyCtx, FlowHandler, lookup};

pub(super) struct JumpHandler {
    pub location: Label,
}

impl FlowHandler for JumpHandler {
    fn target(&self) -> Option<Label> {
        Some(self.location)
    }

    fn to_terminator(&self, ctx: &ClassifyCtx<'_>) -> Result<Terminator, Error> {
        Ok(Terminator::Jump(lookup(ctx.index_to_block, self.location)?))
    }
}
