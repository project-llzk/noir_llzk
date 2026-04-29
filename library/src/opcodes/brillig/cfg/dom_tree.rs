// ── Dominator tree (Cooper-Harvey-Kennedy) ─────────────────────────────

use super::block_splitting::{Block, BlockId, Terminator};
use crate::Error;

/// Immediate-dominator table. `idom[i]` is the immediate dominator of
/// block `i`, or `None` for the entry and for blocks unreachable from
/// the entry.
#[derive(Debug)]
pub(crate) struct DomTree {
    idom: Vec<Option<BlockId>>,
    /// Position of each reachable block in reverse-postorder. Used for the
    /// O(log n) `intersect` step and for fast `dominates` queries.
    /// Unreachable blocks hold `usize::MAX`.
    rpo_index: Vec<usize>,
}

impl DomTree {
    /// Dominator tree rooted at `entry`, using the Cooper-Harvey-Kennedy
    /// fixed-point algorithm.
    pub(crate) fn build(
        successors: &[Vec<BlockId>],
        predecessors: &[Vec<BlockId>],
        entry: BlockId,
    ) -> Self {
        let n = successors.len();
        let rpo = reverse_postorder(successors, entry, n);
        Self::build_from_rpo(predecessors, &rpo, entry, n)
    }

    /// Post-dominator tree. A virtual exit `V` post-dominates every block
    /// with no successors (Return/Stop/Trap); CHK then runs on the reversed
    /// graph rooted at `V`. The returned table hides `V`: a real exit
    /// whose only post-dominator was `V` comes back with `idom = None`.
    ///
    /// Built over the *caller's* view of the CFG ([`caller_successors`]):
    /// `Call→target` edges are dropped because the procedure body lives in
    /// a separate region, and `continuation` edges of divergent calls are
    /// also dropped (they're dead code). From the calling function's
    /// perspective, the procedure entry is not a structural successor of
    /// the call site for join-finding purposes.
    pub(crate) fn build_post(
        blocks: &[Block],
        caller_succ: &[Vec<BlockId>],
        caller_pred: &[Vec<BlockId>],
    ) -> Self {
        let n = blocks.len();
        let virt = BlockId(n);

        let mut rev_succ: Vec<Vec<BlockId>> = caller_pred.to_vec();
        rev_succ.push(Vec::new());
        let mut rev_pred: Vec<Vec<BlockId>> = caller_succ.to_vec();
        rev_pred.push(Vec::new());
        for (i, b) in blocks.iter().enumerate() {
            if matches!(
                b.terminator,
                super::block_splitting::Terminator::Return
                    | Terminator::Stop
                    | Terminator::Trap
                    | Terminator::TrapReturn
            ) {
                rev_succ[virt.0].push(BlockId(i));
                rev_pred[i].push(virt);
            }
        }

        let rpo = reverse_postorder(&rev_succ, virt, n + 1);
        let dom = Self::build_from_rpo(&rev_pred, &rpo, virt, n + 1);

        DomTree {
            idom: dom.idom[..n]
                .iter()
                .map(|s| s.filter(|&b| b != virt))
                .collect(),
            rpo_index: dom.rpo_index[..n].to_vec(),
        }
    }

    fn build_from_rpo(
        predecessors: &[Vec<BlockId>],
        rpo: &[BlockId],
        entry: BlockId,
        n: usize,
    ) -> Self {
        let mut rpo_index = vec![usize::MAX; n];
        for (i, &b) in rpo.iter().enumerate() {
            rpo_index[b.0] = i;
        }

        // Sentinel during fixed-point: entry idom'd by itself.
        let mut idom: Vec<Option<BlockId>> = vec![None; n];
        idom[entry.0] = Some(entry);

        let mut changed = true;
        while changed {
            changed = false;
            for &b in rpo.iter().skip(1) {
                let new_idom = predecessors[b.0]
                    .iter()
                    .copied()
                    .filter(|p| idom[p.0].is_some())
                    .reduce(|a, c| intersect(a, c, &idom, &rpo_index));
                if idom[b.0] != new_idom {
                    idom[b.0] = new_idom;
                    changed = true;
                }
            }
        }

        // Replace the entry sentinel with `None` so `idom[entry]` reflects
        // "entry has no dominator above it."
        idom[entry.0] = None;

        DomTree { idom, rpo_index }
    }

    /// Returns the immediate dominator of `b`, or `None` if `b` is the
    /// entry or unreachable.
    pub(crate) fn idom(&self, b: BlockId) -> Option<BlockId> {
        self.idom[b.0]
    }

    /// `true` iff `dom` dominates `sub` (inclusive — every block dominates
    /// itself). Unreachable `sub` returns `false`.
    pub(crate) fn dominates(&self, dom: BlockId, sub: BlockId) -> bool {
        if self.rpo_index[sub.0] == usize::MAX {
            return false;
        }
        if dom == sub {
            return true;
        }
        let mut cur = sub;
        while let Some(p) = self.idom[cur.0] {
            if p == dom {
                return true;
            }
            if p == cur {
                return false;
            }
            cur = p;
        }
        false
    }
}

fn intersect(
    mut a: BlockId,
    mut b: BlockId,
    idom: &[Option<BlockId>],
    rpo_index: &[usize],
) -> BlockId {
    while a != b {
        while rpo_index[a.0] > rpo_index[b.0] {
            a = idom[a.0].expect("CHK: walking idom chain should stay in the processed set");
        }
        while rpo_index[b.0] > rpo_index[a.0] {
            b = idom[b.0].expect("CHK: walking idom chain should stay in the processed set");
        }
    }
    a
}

fn reverse_postorder(successors: &[Vec<BlockId>], entry: BlockId, n: usize) -> Vec<BlockId> {
    let mut visited = vec![false; n];
    let mut postorder = Vec::new();
    dfs_postorder(entry, successors, &mut visited, &mut postorder);
    postorder.reverse();
    postorder
}

fn dfs_postorder(
    node: BlockId,
    successors: &[Vec<BlockId>],
    visited: &mut [bool],
    out: &mut Vec<BlockId>,
) {
    if visited[node.0] {
        return;
    }
    visited[node.0] = true;
    for &succ in &successors[node.0] {
        dfs_postorder(succ, successors, visited, out);
    }
    out.push(node);
}

/// Checks that the reachable subgraph is reducible: every edge that is not
/// strictly forward in reverse-postorder (i.e. a cycle-closing edge) must
/// be a dominator back-edge (target dominates source). Noir's SSA→Brillig
/// lowering emits reducible CFGs; an irreducible CFG means we're looking
/// at unstructured control flow the structurer cannot handle.
pub(super) fn check_reducible(
    successors: &[Vec<BlockId>],
    dominators: &DomTree,
) -> Result<(), Error> {
    for (u, succs) in successors.iter().enumerate() {
        if dominators.rpo_index[u] == usize::MAX {
            continue;
        }
        for &v in succs {
            if dominators.rpo_index[v.0] == usize::MAX {
                continue;
            }
            let forward = dominators.rpo_index[u] < dominators.rpo_index[v.0];
            if !forward && !dominators.dominates(v, BlockId(u)) {
                return Err(Error::UnsupportedBrillig {
                    reason: format!(
                        "Brillig CFG is irreducible: edge from block {} to block {} \
                         is a cycle-closing edge whose target does not dominate its \
                         source (expected only reducible control flow)",
                        u, v.0
                    ),
                });
            }
        }
    }
    Ok(())
}
