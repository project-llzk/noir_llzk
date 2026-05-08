use acir::brillig::Label;

use crate::error::Error;

use super::super::cfg::Terminator;
use super::{ClassifyCtx, FlowHandler};

pub(super) struct TrapHandler;

impl FlowHandler for TrapHandler {
    fn target(&self) -> Option<Label> {
        None
    }

    fn to_terminator(&self, _ctx: &ClassifyCtx<'_>) -> Result<Terminator, Error> {
        Ok(Terminator::Trap)
    }
}
