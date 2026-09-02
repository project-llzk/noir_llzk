// ── BlockId ────────────────────────────────────────────────────────────

use std::collections::{BTreeSet, HashMap};

use super::{Block, BlockId, Terminator};
use crate::{Error, brillig::flow};
use acir::{
    FieldElement,
    brillig::{Label, Opcode as B},
};

impl Block {
    /// Total number of opcodes in the block (body + terminator).
    pub(super) fn len(&self) -> usize {
        self.end_exclusive - self.start
    }
}

// ── Block splitter ──────────────────────────────────────────────────────

/// Computes the `(start, end_exclusive)` bytecode range of each block.
///
/// A new block starts at index 0, at every jump/call target, and
/// immediately after each `Jump` / `JumpIf` / `Return` / `Stop` / `Trap`.
/// Trailing "phantom" starts past `bytecode.len()` (e.g. a terminator as
/// the last opcode) are dropped.
pub(super) fn split_blocks(bytecode: &[B<FieldElement>]) -> Result<Vec<(Label, Label)>, Error> {
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
pub(super) fn index_ranges(ranges: &[(Label, Label)]) -> HashMap<Label, BlockId> {
    ranges
        .iter()
        .enumerate()
        .map(|(id, (start, _))| (*start, BlockId(id)))
        .collect()
}

/// Classifies each block range's terminator. Returns `UnsupportedBrillig`
/// for bytecode without a terminator in the final block (falling off the
/// end of a function body).
pub(super) fn classify(
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
