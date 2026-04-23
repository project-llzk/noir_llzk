//! Control-flow graph recovery for Brillig bytecode.

// Phase 1 scaffold consumed by Phase 2/3.
#![allow(dead_code)]

use std::collections::HashMap;

use acir::FieldElement;
use acir::brillig::{Label, Opcode as B};

/// Identifier of a basic block in the recovered CFG. Entry is `BlockId(0)`;
/// the rest are allocated in first-seen order during the pre-walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct BlockId(pub(crate) usize);

/// Maps Brillig target indices (entry + every `Jump`/`JumpIf`/`Call` target)
/// to [`BlockId`]s. Non-target indices are absent.
pub(crate) struct LabelMap {
    targets: HashMap<Label, BlockId>,
}

impl LabelMap {
    /// Pre-walks `bytecode`, allocating a [`BlockId`] for the entry and each
    /// distinct `Jump` / `JumpIf` / `Call` target.
    pub(crate) fn build(bytecode: &[B<FieldElement>]) -> Self {
        let mut targets: HashMap<Label, BlockId> = HashMap::new();
        let mut next_id: usize = 0;

        // Entry block is always a recognised target.
        targets.insert(0, BlockId(next_id));
        next_id += 1;

        for op in bytecode {
            let location = match op {
                B::Jump { location } | B::JumpIf { location, .. } | B::Call { location } => {
                    *location
                }
                _ => continue,
            };
            targets.entry(location).or_insert_with(|| {
                let id = BlockId(next_id);
                next_id += 1;
                id
            });
        }

        Self { targets }
    }

    /// Returns the [`BlockId`] for `index`, if it is a block entry point.
    pub(crate) fn get(&self, index: Label) -> Option<BlockId> {
        self.targets.get(&index).copied()
    }

    /// Number of distinct [`BlockId`]s allocated.
    pub(crate) fn len(&self) -> usize {
        self.targets.len()
    }
}
