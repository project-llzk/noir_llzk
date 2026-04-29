// ── BlockId ────────────────────────────────────────────────────────────

use std::collections::{BTreeSet, HashMap};

use crate::{Error, opcodes::brillig::flow};
use acir::{FieldElement, brillig::Label, brillig::MemoryAddress, brillig::Opcode as B};

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
    /// Statically-dead block.
    Unreachable,
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
