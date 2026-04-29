use super::block_splitting::{Block, BlockId, Terminator};
use super::utils::unique_call_targets;
use crate::Error;
use std::collections::{BTreeSet, HashMap};

/// A Brillig procedure: the region of blocks reachable from a
/// [`Terminator::Call`] target. Either ends in a single `Return` (normal
/// procedure, possibly with `Trap` branches in conditional failure paths),
/// or has no `Return` and all leaves are `Trap` (a diverging helper — only
/// `RevertWithString` matches this shape today).
#[derive(Clone, Debug)]
pub(crate) struct Procedure {
    /// Entry block of the procedure (a `Call` target).
    pub(crate) entry: BlockId,
    /// Every block reachable from `entry` without crossing nested calls.
    pub(crate) body: BTreeSet<BlockId>,
    /// `Some(b)` for the unique `Return`-terminated block; `None` for
    /// diverging procedures whose only leaves are `Trap`.
    pub(crate) return_block: Option<BlockId>,
}

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
) -> Result<Vec<Procedure>, Error> {
    let entries = unique_call_targets(blocks);

    let mut procedures = Vec::new();
    for entry in entries {
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
            other => {
                return Err(Error::UnsupportedBrillig {
                    reason: format!(
                        "Brillig procedure at block {}: expected exactly one \
                         `Return` or `TrapReturn` exit, found {}",
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

/// Checks that the procedure call graph is acyclic. Nodes are every
/// procedure plus a synthetic `main` root; edges are `Call`-site → callee-entry
/// pairs. Noir rules out recursion through procedures (user functions are
/// inlined by default; procedures are fixed helpers with a max-depth-2 DAG),
/// so a cycle here means we're looking at bytecode the structurer cannot
/// handle.
pub(super) fn check_call_graph_acyclic(
    blocks: &[Block],
    procedures: &[Procedure],
) -> Result<(), Error> {
    let entry_to_proc: HashMap<BlockId, usize> = procedures
        .iter()
        .enumerate()
        .map(|(i, p)| (p.entry, i))
        .collect();

    let n_functions = procedures.len() + 1;
    let main_idx = procedures.len();
    let function_of = |b: BlockId| -> usize {
        procedures
            .iter()
            .position(|p| p.body.contains(&b))
            .unwrap_or(main_idx)
    };

    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n_functions];
    for (i, block) in blocks.iter().enumerate() {
        if let Terminator::Call { target, .. } = block.terminator {
            let caller = function_of(BlockId(i));
            // `identify_procedures` registers a procedure for every distinct
            // `Call` target in `blocks`, so the lookup is guaranteed to hit.
            let callee = *entry_to_proc
                .get(&target)
                .expect("identify_procedures guarantees every Call target has a procedure entry");
            adj[caller].push(callee);
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Status {
        Unvisited,
        OnStack,
        Done,
    }
    let mut status = vec![Status::Unvisited; n_functions];
    for root in 0..n_functions {
        if status[root] != Status::Unvisited {
            continue;
        }
        let mut stack: Vec<(usize, usize)> = vec![(root, 0)];
        status[root] = Status::OnStack;
        while let Some((node, next_edge)) = stack.last().copied() {
            if next_edge < adj[node].len() {
                let succ = adj[node][next_edge];
                stack.last_mut().unwrap().1 = next_edge + 1;
                match status[succ] {
                    Status::Unvisited => {
                        status[succ] = Status::OnStack;
                        stack.push((succ, 0));
                    }
                    Status::OnStack => {
                        return Err(Error::UnsupportedBrillig {
                            reason: "Brillig procedure call graph contains a cycle \
                                     (recursion through procedures is not supported)"
                                .to_string(),
                        });
                    }
                    Status::Done => {}
                }
            } else {
                status[node] = Status::Done;
                stack.pop();
            }
        }
    }
    Ok(())
}
