use std::collections::{BTreeSet, HashMap};

use super::{BlockId, DomTree, NaturalLoop};

/// Detects every natural loop. A back-edge is an edge `u → v` with `v`
/// dominating `u`; the loop body is the set of blocks from which `u` is
/// reachable without leaving blocks dominated by `v`. Back-edges sharing
/// the same header have their bodies merged into a single loop.
pub(super) fn detect_natural_loops(
    predecessors: &[Vec<BlockId>],
    dominators: &DomTree,
    n: usize,
) -> Vec<NaturalLoop> {
    // Gather back-edges grouped by header.
    let mut per_header: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
    for (b, preds) in predecessors.iter().enumerate().take(n) {
        let block_id = BlockId(b);
        for &pred in preds {
            // edge pred → block_id is a back-edge iff block_id dominates pred.
            if dominators.dominates(block_id, pred) {
                per_header.entry(block_id).or_default().push(pred);
            }
        }
    }

    // For each header, reverse-reach from each back-edge source, stopping
    // at the header.
    let mut loops: Vec<NaturalLoop> = per_header
        .into_iter()
        .map(|(header, sources)| {
            let mut body = BTreeSet::new();
            body.insert(header);
            let mut stack = sources;
            while let Some(v) = stack.pop() {
                if body.insert(v) {
                    for &pred in &predecessors[v.0] {
                        if !body.contains(&pred) {
                            stack.push(pred);
                        }
                    }
                }
            }
            NaturalLoop { header, body }
        })
        .collect();

    loops.sort_by_key(|l| l.header);
    loops
}
