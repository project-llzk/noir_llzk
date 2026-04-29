//! Control-flow graph recovery for Brillig bytecode.
//!
//! Recovers basic blocks, successor/predecessor edges, dominator and
//! post-dominator trees, natural loops, and procedure regions from flat
//! Brillig bytecode. The output is consumed by the structurer.

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
    /// Synthesized terminator for the `RevertWithString` shape: a `Trap`
    /// opcode immediately followed by an orphan `Return` opcode.
    TrapReturn,
    /// Synthesized when a block's last opcode is not a flow op and a
    /// jump/call target lands at the next index, splitting an implicit
    /// fall-through edge.
    Fallthrough(BlockId),
}

// ── Cfg ─────────────────────────────────────────────────────────────────

/// Control-flow graph recovered from Brillig bytecode.
///
/// Blocks are indexed by [`BlockId`]. Block `0` is always the entry.
pub(crate) struct Cfg {
    pub(crate) blocks: Vec<Block>,
    /// `successors[i]` — successor [`BlockId`]s of block `i`.
    pub(crate) successors: Vec<Vec<BlockId>>,
    /// `predecessors[i]` — predecessor [`BlockId`]s of block `i`.
    pub(crate) predecessors: Vec<Vec<BlockId>>,
    pub(crate) dominators: DomTree,
    pub(crate) post_dominators: DomTree,
    pub(crate) loops: Vec<NaturalLoop>,
    /// One entry per distinct `Call` target.
    pub(crate) procedures: Vec<Procedure>,
    /// Blocks where every forward path ends at a
    /// *divergent* leaf — `Trap`, `TrapReturn`, or `Call` to a divergent
    /// procedure.
    pub(crate) divergent_blocks: BTreeSet<BlockId>,
}

impl Cfg {
    /// Builds the CFG for `bytecode`.
    pub(crate) fn build(bytecode: &[B<FieldElement>]) -> Result<Self, Error> {
        let block_ranges = split_blocks(bytecode)?;
        let index_to_block = index_ranges(&block_ranges);
        let mut blocks = classify(bytecode, &block_ranges, &index_to_block)?;
        let initial_successors = compute_successors(&blocks);
        let initial_predecessors = invert_edges(&initial_successors);

        rewrite_trap_return_pattern(&mut blocks, &initial_predecessors);

        let divergent_entries = compute_non_returning_calls(&blocks);

        // Recognise the *dangling-constrain-skip* shape that
        // `codegen_if_not(cond, |ctx| call_<divergent>())` emits when the
        // construct is the last in its function. The skip-arm is dead by construction.
        // Replace the `JumpIf` with a `Jump` to the trap-arm.
        rewrite_dangling_constrain_skips(&mut blocks, &divergent_entries);

        let successors = compute_successors(&blocks);
        let predecessors = invert_edges(&successors);

        // Caller-view of the CFG, computed once and shared by post-dominator
        // construction and always-divergent analysis.
        let caller_succ: Vec<Vec<BlockId>> = (0..blocks.len())
            .map(|i| caller_successors(&blocks, &successors, &divergent_entries, BlockId(i)))
            .collect();
        let caller_pred = invert_edges(&caller_succ);

        let dominators = DomTree::build(&successors, &predecessors, BlockId(0));
        let post_dominators = DomTree::build_post(&blocks, &caller_succ, &caller_pred);
        let loops = detect_natural_loops(&predecessors, &dominators, blocks.len());

        let procedures = identify_procedures(&blocks, &successors, &caller_succ)?;
        check_call_graph_acyclic(&blocks, &procedures)?;
        check_reducible(&successors, &dominators)?;

        // Blocks from which every forward path bottoms out at a
        // divergent leaf (`Trap`/`TrapReturn`/`Call`-divergent), with
        // no escape via `Return` or `Stop`. The structurer keys
        // half-joining `IfThenElse` detection off this when the
        // post-dominator is `None`: the divergent arm of the if takes
        // the panic, the non-divergent arm carries the continuation.
        let always_divergent =
            compute_always_divergent(&blocks, &caller_succ, &caller_pred, &divergent_entries);

        Ok(Cfg {
            blocks,
            successors,
            predecessors,
            dominators,
            post_dominators,
            loops,
            procedures,
            divergent_blocks: always_divergent,
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
pub(crate) fn split_blocks(bytecode: &[B<FieldElement>]) -> Result<Vec<(Label, Label)>, Error> {
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
pub(crate) fn index_ranges(ranges: &[(Label, Label)]) -> HashMap<Label, BlockId> {
    ranges
        .iter()
        .enumerate()
        .map(|(id, (start, _))| (*start, BlockId(id)))
        .collect()
}

/// Classifies each block range's terminator. Returns `UnsupportedBrillig`
/// for bytecode without a terminator in the final block (falling off the
/// end of a function body).
pub(crate) fn classify(
    bytecode: &[B<FieldElement>],
    ranges: &[(Label, Label)],
    index_to_block: &HashMap<Label, BlockId>,
) -> Result<Vec<Block>, Error> {
    let mut blocks = Vec::with_capacity(ranges.len());
    for &(start, end) in ranges {
        let last_idx = end - 1;
        let last_op = &bytecode[last_idx];
        let terminator = match flow::build_handler(last_op) {
            Some(flow_op) => flow_op.to_terminator(&flow::ClassifyCtx {
                index_to_block,
                last_idx,
                bytecode_len: bytecode.len(),
            })?,
            None if end < bytecode.len() => Terminator::Fallthrough(index_to_block[&end]),
            None => {
                return Err(Error::UnsupportedBrillig {
                    reason: format!(
                        "Brillig block ending at index {last_idx} has non-terminator \
                         opcode `{last_op:?}` and no fall-through target — bytecode \
                         must end with a branch, Return, Stop, or Trap"
                    ),
                });
            }
        };
        blocks.push(Block {
            start,
            end_exclusive: end,
            terminator,
        });
    }
    Ok(blocks)
}

// ── Successor / predecessor edges ──────────────────────────────────────

pub(crate) fn compute_successors(blocks: &[Block]) -> Vec<Vec<BlockId>> {
    blocks
        .iter()
        .map(|b| match b.terminator {
            Terminator::Jump(target) | Terminator::Fallthrough(target) => vec![target],
            Terminator::JumpIf {
                then_block,
                else_block,
                ..
            } => vec![then_block, else_block],
            Terminator::Call {
                target,
                continuation,
            } => vec![target, continuation],
            Terminator::Return | Terminator::Stop | Terminator::Trap | Terminator::TrapReturn => {
                Vec::new()
            }
        })
        .collect()
}

pub(crate) fn invert_edges(successors: &[Vec<BlockId>]) -> Vec<Vec<BlockId>> {
    let n = successors.len();
    let mut predecessors = vec![Vec::new(); n];
    for (from, succs) in successors.iter().enumerate() {
        for &BlockId(to) in succs {
            predecessors[to].push(BlockId(from));
        }
    }
    predecessors
}

/// Successors of `b` from the calling function's perspective: a non-divergent
/// `Call` yields only its `continuation` (the procedure body lives in another
/// region); a `Call` to a divergent procedure yields nothing (the continuation
/// is dead code — the procedure never resumes); everything else mirrors the
/// raw `successors` graph. Used by post-dom and loop-exit analyses, which
/// model caller flow rather than the call-graph union.
pub(crate) fn caller_successors(
    blocks: &[Block],
    successors: &[Vec<BlockId>],
    divergent_entries: &BTreeSet<BlockId>,
    b: BlockId,
) -> Vec<BlockId> {
    match blocks[b.0].terminator {
        Terminator::Call {
            target,
            continuation,
        } => {
            if divergent_entries.contains(&target) {
                Vec::new()
            } else {
                vec![continuation]
            }
        }
        _ => successors[b.0].clone(),
    }
}

/// Returns the set of blocks where every forward path (in [`caller_successors`]
/// view) ends at a *divergent* leaf — `Trap`, `TrapReturn`, or `Call` to a
/// divergent procedure. `Return` and `Stop` count as non-divergent escapes,
/// so any block that can reach one is excluded.
///
/// Computed via backward fixed point: seed with the divergent leaves
/// themselves; a block is always-divergent iff its caller-successor set is
/// non-empty and every caller-successor is already divergent.
fn compute_always_divergent(
    blocks: &[Block],
    caller_succ: &[Vec<BlockId>],
    caller_pred: &[Vec<BlockId>],
    divergent_entries: &BTreeSet<BlockId>,
) -> BTreeSet<BlockId> {
    // remaining[j] = caller-successors of j not yet known divergent.
    let mut remaining: Vec<usize> = caller_succ.iter().map(|s| s.len()).collect();

    // Seed: divergent leaves — `Trap`, `TrapReturn`, or `Call` to a
    // divergent procedure. `Return` and `Stop` are non-divergent escapes
    // and are deliberately excluded.
    let mut divergent: BTreeSet<BlockId> = BTreeSet::new();
    let mut worklist: Vec<BlockId> = Vec::new();
    for (i, block) in blocks.iter().enumerate() {
        let is_divergent_leaf = match block.terminator {
            Terminator::Trap | Terminator::TrapReturn => true,
            Terminator::Call { target, .. } => divergent_entries.contains(&target),
            _ => false,
        };
        if is_divergent_leaf {
            divergent.insert(BlockId(i));
            worklist.push(BlockId(i));
        }
    }

    // Propagate: each time x becomes divergent, decrement remaining[j] for
    // every j with x ∈ caller_succ[j]. When remaining[j] hits 0 and j had
    // at least one caller-successor to begin with, j is always-divergent.
    while let Some(x) = worklist.pop() {
        for &pred in &caller_pred[x.0] {
            remaining[pred.0] -= 1;
            if remaining[pred.0] == 0 {
                divergent.insert(pred);
                worklist.push(pred);
            }
        }
    }
    divergent
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
                Terminator::Return | Terminator::Stop | Terminator::Trap | Terminator::TrapReturn
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

/// Retags the `Trap` followed by an orphan `Return` as
/// [`Terminator::TrapReturn`].
///
/// This shape is currently emitted by the Noir `RevertWithString`
/// procedure
pub(crate) fn rewrite_trap_return_pattern(blocks: &mut [Block], predecessors: &[Vec<BlockId>]) {
    for i in 0..blocks.len() {
        if !matches!(blocks[i].terminator, Terminator::Trap) {
            continue;
        }
        let next_idx = i + 1;
        let Some(next) = blocks.get(next_idx) else {
            continue;
        };

        let is_orphan_return = matches!(next.terminator, Terminator::Return)
            && next.len() == 1
            && predecessors[next_idx].is_empty();
        if is_orphan_return {
            blocks[i].terminator = Terminator::TrapReturn;
        }
    }
}

/// Drops the dead then-arm of a *dangling-constrain-skip*: a
/// `codegen_if_not(cond, trap_or_call_divergent())` emitted last in an
/// artifact, whose `end_label` links to the next artifact's entry — i.e.
/// another procedure.
///
/// Pattern: block A is `JumpIf cond, then=t, else=e` with
/// `e.start == A.end_exclusive`, `t.start == e.end_exclusive`, `e`
/// trap-emitting (`Trap`/`TrapReturn`/`Call <divergent>`), and `t` a
/// call target. Retags A as `Jump(e)`.
fn rewrite_dangling_constrain_skips(blocks: &mut [Block], divergent_entries: &BTreeSet<BlockId>) {
    let entry_points: BTreeSet<BlockId> = blocks
        .iter()
        .filter_map(|b| match b.terminator {
            Terminator::Call { target, .. } => Some(target),
            _ => None,
        })
        .collect();

    let mut to_rewrite: Vec<(usize, BlockId)> = Vec::new();
    for (i, b) in blocks.iter().enumerate() {
        let Terminator::JumpIf {
            then_block,
            else_block,
            ..
        } = b.terminator
        else {
            continue;
        };
        // Linear-layout check: codegen_if_not lays out
        //   [A: JumpIf cond, end_label] [B: body] [end_label = T: …]
        // contiguously. A.end == B.start and B.end == T.start.
        if blocks[else_block.0].start != b.end_exclusive
            || blocks[then_block.0].start != blocks[else_block.0].end_exclusive
        {
            continue;
        }
        // T must be a procedure entry — that's what makes the skip-arm
        // a *dangling* edge (a layout coincidence, not real flow).
        if !entry_points.contains(&then_block) {
            continue;
        }
        // B must be a trap-emitting block: Trap, TrapReturn, or a Call
        // to a divergent procedure. Anything else means this is a
        // legitimate JumpIf, not a constrain-skip.
        let trap_emitting = match blocks[else_block.0].terminator {
            Terminator::Trap | Terminator::TrapReturn => true,
            Terminator::Call { target, .. } => divergent_entries.contains(&target),
            _ => false,
        };
        if !trap_emitting {
            continue;
        }
        to_rewrite.push((i, else_block));
    }

    for (i, jump_target) in to_rewrite {
        blocks[i].terminator = Terminator::Jump(jump_target);
    }
}

/// Procedure entries whose entry block terminates with
/// [`Terminator::TrapReturn`].
pub(crate) fn compute_non_returning_calls(blocks: &[Block]) -> BTreeSet<BlockId> {
    unique_call_targets(blocks)
        .into_iter()
        .filter(|e| matches!(blocks[e.0].terminator, Terminator::TrapReturn))
        .collect()
}

/// For each distinct `Call` target, walk forward without crossing into
/// nested procedures (follow only `continuation` out of a non-divergent
/// `Call`, never `target`, and treat divergent `Call`s as leaves) and
/// collect the blocks visited. Each procedure must have exactly one
/// exit block — either a `Return` (normal) or a `TrapReturn`
/// (`RevertWithString` shape).
fn identify_procedures(
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
