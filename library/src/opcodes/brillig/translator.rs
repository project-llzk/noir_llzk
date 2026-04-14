//! Skeleton Brillig bytecode translator.
//!
//! For Milestone 3 Issue 2 this is deliberately minimal: only `Stop` and
//! end-of-bytecode act as terminators; every other opcode returns an
//! `UnsupportedBrillig` error naming the opcode and its bytecode index.
//! Register, arithmetic, and heap lowerings land in Issues 3–7.

use acir::{FieldElement, brillig::Opcode as BrilligOpcode, circuit::brillig::BrilligBytecode};
use llzk::prelude::Value;

use crate::error::Error;

/// Walks the Brillig bytecode and produces the SSA values that should be
/// passed to the sibling function's `function.return`.
pub(crate) fn translate_bytecode<'c, 'a>(
    bytecode: &BrilligBytecode<FieldElement>,
) -> Result<Vec<Value<'c, 'a>>, Error> {
    for (i, op) in bytecode.bytecode.iter().enumerate() {
        match op {
            BrilligOpcode::Stop { .. } => {
                return Ok(Vec::new());
            }
            other => {
                return Err(Error::UnsupportedBrillig {
                    reason: format!(
                        "Brillig opcode `{}` at bytecode index {i} is not supported yet",
                        brillig_op_name(other)
                    ),
                });
            }
        }
    }
    Ok(Vec::new())
}

fn brillig_op_name<F>(op: &BrilligOpcode<F>) -> &'static str {
    match op {
        BrilligOpcode::BinaryFieldOp { .. } => "BinaryFieldOp",
        BrilligOpcode::BinaryIntOp { .. } => "BinaryIntOp",
        BrilligOpcode::Not { .. } => "Not",
        BrilligOpcode::Cast { .. } => "Cast",
        BrilligOpcode::JumpIf { .. } => "JumpIf",
        BrilligOpcode::Jump { .. } => "Jump",
        BrilligOpcode::CalldataCopy { .. } => "CalldataCopy",
        BrilligOpcode::Call { .. } => "Call",
        BrilligOpcode::Const { .. } => "Const",
        BrilligOpcode::IndirectConst { .. } => "IndirectConst",
        BrilligOpcode::Return => "Return",
        BrilligOpcode::ForeignCall { .. } => "ForeignCall",
        BrilligOpcode::Mov { .. } => "Mov",
        BrilligOpcode::ConditionalMov { .. } => "ConditionalMov",
        BrilligOpcode::Load { .. } => "Load",
        BrilligOpcode::Store { .. } => "Store",
        BrilligOpcode::BlackBox(_) => "BlackBox",
        BrilligOpcode::Trap { .. } => "Trap",
        BrilligOpcode::Stop { .. } => "Stop",
    }
}
