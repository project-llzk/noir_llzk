//! Control-flow graph recovery for Brillig bytecode.
//!
//! Recovers basic blocks, successor/predecessor edges, dominator and
//! post-dominator trees, natural loops, and procedure regions from flat
//! Brillig bytecode. The output is consumed by the Phase 3 structurer.
//!
//! **Call handling (editorial extension of the plan).** The plan models
//! `Call L` as a single forward edge to `L`, with the return edge to the
//! post-`Call` continuation deferred to Phase 3. That leaves continuation
//! blocks unreachable from the entry in Phase 2's CFG, which prevents
//! dominator analysis of the caller's structure after a `Call`. This
//! module instead models `Call` as a terminator with successors
//! `[target, continuation]` — the `target` edge is the real forward edge;
//! the `continuation` edge is a synthetic stand-in for the future
//! return-edge, giving a single connected CFG the structurer can walk.
//! Procedure bodies are identified separately via forward reachability
//! from each `Call` target *without* traversing nested `Call` targets.

use std::collections::{BTreeSet, HashMap};

use acir::FieldElement;
use acir::brillig::{Label, MemoryAddress, Opcode as B};

use crate::error::Error;

use super::flow;

// ── BlockId ────────────────────────────────────────────────────────────

/// Identifier of a basic block in the recovered CFG. Entry is `BlockId(0)`;
/// the rest are allocated in first-seen order during the pre-walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct BlockId(pub(crate) usize);

// ── Blocks and terminators ──────────────────────────────────────────────

/// A basic block spans bytecode indices `[start, end_exclusive)`. The final
/// opcode in the range is the block's [`Terminator`]; prior opcodes are the
/// block body.
#[derive(Clone, Debug)]
pub(crate) struct Block {
    pub(crate) start: Label,
    pub(crate) end_exclusive: Label,
    pub(crate) terminator: Terminator,
}

impl Block {
    /// Total number of opcodes in the block (body + terminator).
    pub(crate) fn len(&self) -> usize {
        self.end_exclusive - self.start
    }
}

/// Classification of a block's last opcode. Drives CFG edge construction
/// and structurer dispatch.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Terminator {
    /// `Jump L` — unconditional branch.
    Jump(BlockId),
    /// `JumpIf cond, then_block`. `else_block` is the fall-through (the
    /// instruction immediately after the `JumpIf`).
    JumpIf {
        condition: MemoryAddress,
        then_block: BlockId,
        else_block: BlockId,
    },
    /// `Call L`. `target` is the callee's entry; `continuation` is the
    /// block starting at the instruction after the `Call`. Noir's codegen
    /// always emits SP-restore and return-copy opcodes after `Call`, so
    /// `continuation` is always present — bytecode with `Call` as the
    /// final opcode is rejected by [`classify`].
    Call {
        target: BlockId,
        continuation: BlockId,
    },
    /// `Return` — procedure exit. No CFG successors.
    Return,
    /// `Stop` — function exit with return data. No CFG successors.
    Stop,
    /// `Trap` — execution failure. No CFG successors.
    Trap,
}

// ── Cfg ─────────────────────────────────────────────────────────────────

/// Control-flow graph recovered from Brillig bytecode.
///
/// Blocks are indexed by [`BlockId`]. Block `0` is always the entry.
///
/// [`Debug`] rendering lives in [`super::cfg_display`] and prints blocks,
/// successors, dominator and post-dominator trees, loops, and procedures.
pub(crate) struct Cfg {
    pub(crate) blocks: Vec<Block>,
    /// `successors[i]` — successor [`BlockId`]s of block `i`.
    pub(crate) successors: Vec<Vec<BlockId>>,
    /// `predecessors[i]` — predecessor [`BlockId`]s of block `i`.
    pub(crate) predecessors: Vec<Vec<BlockId>>,
    pub(crate) dominators: DomTree,
    pub(crate) post_dominators: DomTree,
    pub(crate) loops: Vec<NaturalLoop>,
    /// One entry per distinct `Call` target. Empty for procedure-free
    /// bytecode.
    pub(crate) procedures: Vec<Procedure>,
}

impl Cfg {
    /// Builds the CFG for `bytecode`.
    pub(crate) fn build(bytecode: &[B<FieldElement>]) -> Result<Self, Error> {
        let block_ranges = split_blocks(bytecode)?;
        let index_to_block = index_ranges(&block_ranges);
        let blocks = classify(bytecode, &block_ranges, &index_to_block)?;
        let successors = compute_successors(&blocks);
        let predecessors = invert_edges(&successors);

        let dominators = DomTree::build(&successors, &predecessors, BlockId(0));
        let post_dominators = DomTree::build_post(&successors, &predecessors, &blocks);
        let loops = detect_natural_loops(&predecessors, &dominators, blocks.len());

        let procedures = identify_procedures(&blocks, &successors)?;
        check_call_graph_acyclic(&blocks, &procedures)?;
        check_reducible(&successors, &dominators)?;

        Ok(Cfg {
            blocks,
            successors,
            predecessors,
            dominators,
            post_dominators,
            loops,
            procedures,
        })
    }
}

// ── Block splitter ──────────────────────────────────────────────────────

/// Computes the `(start, end_exclusive)` bytecode range of each block.
///
/// A new block starts at index 0, at every jump/call target, and
/// immediately after each `Jump` / `JumpIf` / `Return` / `Stop` / `Trap`.
/// Trailing "phantom" starts past `bytecode.len()` (e.g. a terminator as
/// the last opcode) are dropped.
fn split_blocks(bytecode: &[B<FieldElement>]) -> Result<Vec<(Label, Label)>, Error> {
    if bytecode.is_empty() {
        return Err(Error::UnsupportedBrillig {
            reason: "Brillig bytecode is empty".to_string(),
        });
    }

    let mut starts: BTreeSet<Label> = BTreeSet::new();
    starts.insert(0);

    for (i, op) in bytecode.iter().enumerate() {
        let Some(flow_op) = flow::build_handler(op) else {
            continue;
        };
        if let Some(location) = flow_op.target() {
            if location >= bytecode.len() {
                return Err(Error::UnsupportedBrillig {
                    reason: format!(
                        "Brillig branch at index {i} targets out-of-range \
                         instruction {location}"
                    ),
                });
            }
            starts.insert(location);
        }
        let next = i + 1;
        if next < bytecode.len() {
            starts.insert(next);
        }
    }

    let sorted: Vec<Label> = starts.into_iter().collect();
    let mut ranges = Vec::with_capacity(sorted.len());
    for (idx, &start) in sorted.iter().enumerate() {
        let end = sorted.get(idx + 1).copied().unwrap_or(bytecode.len());
        ranges.push((start, end));
    }
    Ok(ranges)
}

/// Builds a lookup from bytecode index → [`BlockId`]. Only block starts are
/// present in the map.
fn index_ranges(ranges: &[(Label, Label)]) -> HashMap<Label, BlockId> {
    ranges
        .iter()
        .enumerate()
        .map(|(id, (start, _))| (*start, BlockId(id)))
        .collect()
}

/// Classifies each block range's terminator. Returns `UnsupportedBrillig`
/// for bytecode without a terminator in the final block (falling off the
/// end of a function body).
fn classify(
    bytecode: &[B<FieldElement>],
    ranges: &[(Label, Label)],
    index_to_block: &HashMap<Label, BlockId>,
) -> Result<Vec<Block>, Error> {
    let mut blocks = Vec::with_capacity(ranges.len());
    for &(start, end) in ranges {
        let last_idx = end - 1;
        let last_op = &bytecode[last_idx];
        let flow_op = flow::build_handler(last_op).ok_or_else(|| Error::UnsupportedBrillig {
            reason: format!(
                "Brillig block ending at index {last_idx} has non-terminator \
                 opcode `{last_op:?}` — bytecode must end every block with a branch, \
                 Return, Stop, or Trap"
            ),
        })?;
        let terminator = flow_op.to_terminator(&flow::ClassifyCtx {
            index_to_block,
            last_idx,
            bytecode_len: bytecode.len(),
        })?;
        blocks.push(Block {
            start,
            end_exclusive: end,
            terminator,
        });
    }
    Ok(blocks)
}

// ── Successor / predecessor edges ──────────────────────────────────────

fn compute_successors(blocks: &[Block]) -> Vec<Vec<BlockId>> {
    blocks
        .iter()
        .map(|b| match b.terminator {
            Terminator::Jump(target) => vec![target],
            Terminator::JumpIf {
                then_block,
                else_block,
                ..
            } => vec![then_block, else_block],
            Terminator::Call {
                target,
                continuation,
            } => vec![target, continuation],
            Terminator::Return | Terminator::Stop | Terminator::Trap => Vec::new(),
        })
        .collect()
}

fn invert_edges(successors: &[Vec<BlockId>]) -> Vec<Vec<BlockId>> {
    let n = successors.len();
    let mut predecessors = vec![Vec::new(); n];
    for (from, succs) in successors.iter().enumerate() {
        for &BlockId(to) in succs {
            predecessors[to].push(BlockId(from));
        }
    }
    predecessors
}

// ── Dominator tree (Cooper-Harvey-Kennedy) ─────────────────────────────

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
    /// In the reversed graph, successors-of-`u` are forward-predecessors
    /// and predecessors-of-`u` are forward-successors — so the adjacency
    /// lists are just the forward ones cloned, plus the virt row.
    pub(crate) fn build_post(
        successors: &[Vec<BlockId>],
        predecessors: &[Vec<BlockId>],
        blocks: &[Block],
    ) -> Self {
        let n = blocks.len();
        let virt = BlockId(n);

        let mut rev_succ: Vec<Vec<BlockId>> = predecessors.iter().cloned().collect();
        rev_succ.push(Vec::new());
        let mut rev_pred: Vec<Vec<BlockId>> = successors.iter().cloned().collect();
        rev_pred.push(Vec::new());
        for (i, b) in blocks.iter().enumerate() {
            if matches!(
                b.terminator,
                Terminator::Return | Terminator::Stop | Terminator::Trap
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

// ── Natural loops ──────────────────────────────────────────────────────

/// A natural loop: a header and the set of blocks reached by walking
/// backwards from the loop's back-edge source until the header is hit.
#[derive(Clone, Debug)]
pub(crate) struct NaturalLoop {
    pub(crate) header: BlockId,
    pub(crate) body: BTreeSet<BlockId>,
}

/// Detects every natural loop. A back-edge is an edge `u → v` with `v`
/// dominating `u`; the loop body is the set of blocks from which `u` is
/// reachable without leaving blocks dominated by `v`. Back-edges sharing
/// the same header have their bodies merged into a single loop.
fn detect_natural_loops(
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

// ── Invariants ─────────────────────────────────────────────────────────

/// Checks that the reachable subgraph is reducible: every edge that is not
/// strictly forward in reverse-postorder (i.e. a cycle-closing edge) must
/// be a dominator back-edge (target dominates source). Noir's SSA→Brillig
/// lowering emits reducible CFGs; an irreducible CFG means we're looking
/// at unstructured control flow the structurer cannot handle.
fn check_reducible(successors: &[Vec<BlockId>], dominators: &DomTree) -> Result<(), Error> {
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

// ── Procedures ─────────────────────────────────────────────────────────

/// A Brillig procedure: the region of blocks reachable from a [`Terminator::Call`]
/// target, ending in a single `Return`.
#[derive(Clone, Debug)]
pub(crate) struct Procedure {
    /// Entry block of the procedure (a `Call` target).
    pub(crate) entry: BlockId,
    /// Every block in the procedure's body, including `entry` and
    /// `return_block`. Does not include blocks of nested callees.
    pub(crate) body: BTreeSet<BlockId>,
    /// The unique block terminated by [`Terminator::Return`].
    pub(crate) return_block: BlockId,
}

/// Collects every distinct `Call` target from `blocks`, in ascending
/// [`BlockId`] order.
fn unique_call_targets(blocks: &[Block]) -> Vec<BlockId> {
    let mut seen: BTreeSet<BlockId> = BTreeSet::new();
    for b in blocks {
        if let Terminator::Call { target, .. } = b.terminator {
            seen.insert(target);
        }
    }
    seen.into_iter().collect()
}

/// For each distinct `Call` target, walk forward without crossing into
/// nested procedures (i.e. follow only `continuation` out of a `Call`,
/// never `target`) and collect the blocks visited before hitting a
/// `Return`. Noir's SSA invariant guarantees exactly one `Return` per
/// procedure; anything is rejected as unsupported.
fn identify_procedures(
    blocks: &[Block],
    successors: &[Vec<BlockId>],
) -> Result<Vec<Procedure>, Error> {
    let mut procedures = Vec::new();
    for entry in unique_call_targets(blocks) {
        let body = procedure_body(entry, blocks, successors);
        let returns: Vec<BlockId> = body
            .iter()
            .copied()
            .filter(|b| matches!(blocks[b.0].terminator, Terminator::Return))
            .collect();
        let return_block = match returns.len() {
            1 => returns[0],
            n => {
                return Err(Error::UnsupportedBrillig {
                    reason: format!(
                        "Brillig procedure at block {} has {} `Return` blocks, expected 1",
                        entry.0, n
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

fn procedure_body(
    entry: BlockId,
    blocks: &[Block],
    successors: &[Vec<BlockId>],
) -> BTreeSet<BlockId> {
    let mut body = BTreeSet::new();
    body.insert(entry);
    let mut stack = vec![entry];
    while let Some(b) = stack.pop() {
        let to_follow: Vec<BlockId> = match blocks[b.0].terminator {
            // A nested `Call` stays inside the enclosing procedure via its
            // continuation; the callee's body belongs to its own procedure.
            Terminator::Call { continuation, .. } => vec![continuation],
            _ => successors[b.0].clone(),
        };
        for s in to_follow {
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
fn check_call_graph_acyclic(blocks: &[Block], procedures: &[Procedure]) -> Result<(), Error> {
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
