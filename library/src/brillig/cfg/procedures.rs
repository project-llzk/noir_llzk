use super::{Block, BlockId, Procedure, Terminator};
use crate::Error;
use std::collections::BTreeSet;

/// For each distinct `Call` target, walk forward without crossing into
/// nested procedures (follow only `continuation` out of a non-divergent
/// `Call`, never `target`, and treat divergent `Call`s as leaves) and
/// collect the blocks visited. Each procedure must have exactly one
/// exit block — either a `Return` (normal) or a `TrapReturn`
/// (`RevertWithString` shape).
pub(super) fn identify_procedures(
    blocks: &[Block],
    successors: &[Vec<BlockId>],
    caller_succ: &[Vec<BlockId>],
    call_targets: &[BlockId],
) -> Result<Vec<Procedure>, Error> {
    let mut procedures = Vec::new();
    for &entry in call_targets {
        let body = procedure_body(entry, caller_succ);
        let exits: Vec<BlockId> = body
            .iter()
            .copied()
            .filter(|b| {
                matches!(
                    blocks[b.0].terminator,
                    Terminator::Return | Terminator::TrapReturn
                )
            })
            .collect();
        // Every leaf must be Return / Trap / TrapReturn; a Stop-leaf
        // inside a procedure body is malformed (Stop is for the
        // function's main exit, not procedures).
        let leaves_well_formed = body.iter().filter(|b| successors[b.0].is_empty()).all(|b| {
            matches!(
                blocks[b.0].terminator,
                Terminator::Return | Terminator::Trap | Terminator::TrapReturn
            )
        });
        let return_block = match exits.as_slice() {
            // Single normal exit.
            [b] if leaves_well_formed && matches!(blocks[b.0].terminator, Terminator::Return) => {
                Some(*b)
            }
            // Single divergent exit (`TrapReturn`). API convention:
            // `return_block = None` signals divergence to consumers.
            [b] if leaves_well_formed
                && matches!(blocks[b.0].terminator, Terminator::TrapReturn) =>
            {
                let _ = b;
                None
            }
            // No `Return` / `TrapReturn` exits, but every leaf is `Trap`
            // (guaranteed by `leaves_well_formed`): an all-trap
            // divergent procedure.
            [] if leaves_well_formed => None,
            other => {
                return Err(Error::UnsupportedBrillig {
                    reason: format!(
                        "Brillig procedure at block {}: expected exactly one \
                         `Return` or `TrapReturn` exit (or all-`Trap` leaves), found {}",
                        entry.0,
                        other.len()
                    ),
                });
            }
        };
        procedures.push(Procedure {
            entry,
            body,
            return_block,
        });
    }
    Ok(procedures)
}

fn procedure_body(entry: BlockId, caller_succ: &[Vec<BlockId>]) -> BTreeSet<BlockId> {
    let mut body = BTreeSet::new();
    body.insert(entry);
    let mut stack = vec![entry];
    while let Some(b) = stack.pop() {
        for &s in &caller_succ[b.0] {
            if body.insert(s) {
                stack.push(s);
            }
        }
    }
    body
}
