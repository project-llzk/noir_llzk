use acir::brillig::Label;

use crate::error::Error;

use super::super::cfg::Terminator;
use super::{ClassifyCtx, FlowHandler};

pub(super) struct StopHandler;

impl FlowHandler for StopHandler {
    fn target(&self) -> Option<Label> {
        None
    }

    fn to_terminator(&self, _ctx: &ClassifyCtx<'_>) -> Result<Terminator, Error> {
        Ok(Terminator::Stop)
    }
}
