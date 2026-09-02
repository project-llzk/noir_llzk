//! Validation for [`super::RegionNode::SetEscapeFlag`] placement.

use super::StructureNode;
use crate::brillig::cfg::BlockId;
use crate::error::Error;

/// Verifies that every [`RegionNode::SetEscapeFlag`] in `body` sits at a
/// structurally-tail position. A break elsewhere would require wrapping
/// subsequent code in `scf.if !flag` during emission; that work is
/// deferred until real bytecode needs it.
pub(super) fn validate_escape_flag_positions(
    body: &[StructureNode],
    header: BlockId,
) -> Result<(), Error> {
    validate_seq(body, header, true)
}

fn validate_seq(seq: &[StructureNode], header: BlockId, tail_inherited: bool) -> Result<(), Error> {
    let last = seq.len().saturating_sub(1);
    for (i, node) in seq.iter().enumerate() {
        let is_tail = tail_inherited && i == last;
        match node {
            StructureNode::SetEscapeFlag { .. } if !is_tail => {
                return Err(Error::UnsupportedBrillig {
                    reason: format!(
                        "Brillig loop b{}: break at non-tail position is not \
                         supported (would require flag-guarded continuation)",
                        header.0
                    ),
                });
            }
            StructureNode::SetEscapeFlag { .. } => {}
            StructureNode::IfThenElse {
                then_branch,
                else_branch,
                ..
            } => {
                validate_seq(then_branch, header, is_tail)?;
                validate_seq(else_branch, header, is_tail)?;
            }
            // Inner Loops own their tail semantics; Call bodies are
            // structured separately with disjoint flag namespaces.
            _ => {}
        }
    }
    Ok(())
}
