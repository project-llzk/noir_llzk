//! Brillig memory model.
//!
//! Wraps the SSA-valued register file and the integer-constant tracker into
//! a single chokepoint for every memory access. Today this is a thin wrapper
//! over two in-memory `HashMap`s; future milestones will migrate the backing
//! store to LLZK RAM and add Relative-address resolution and frame
//! tracking — handlers will not need to change because they only see this
//! API.

use std::collections::HashMap;

use acir::brillig::MemoryAddress;
use llzk::prelude::Value;

use crate::error::Error;

/// Brillig memory: register file + tracked integer constants.
pub(crate) struct Memory<'c, 'b> {
    regs: HashMap<MemoryAddress, Value<'c, 'b>>,
    known_constants: HashMap<MemoryAddress, usize>,
}

impl<'c, 'b> Memory<'c, 'b> {
    pub(crate) fn new() -> Self {
        Self {
            regs: HashMap::new(),
            known_constants: HashMap::new(),
        }
    }

    /// Records `value` as the current SSA binding for `addr`.
    pub(crate) fn write(&mut self, addr: MemoryAddress, value: Value<'c, 'b>) {
        self.regs.insert(addr, value);
    }

    /// Returns the current SSA binding for `addr`, or
    /// [`Error::UndefinedRegister`] if nothing has been written yet.
    pub(crate) fn read(
        &self,
        addr: MemoryAddress,
        opcode_index: usize,
    ) -> Result<Value<'c, 'b>, Error> {
        self.regs
            .get(&addr)
            .copied()
            .ok_or(Error::UndefinedRegister {
                addr: addr.to_u32() as usize,
                opcode_index,
            })
    }

    /// Records a translation-time integer constant for `addr`.
    ///
    /// Used by handlers that emit a constant write (`Const`) to remember
    /// the integer value, so that later opcodes which need a compile-time
    /// integer (e.g. `CalldataCopy` size/offset, `Stop` return_data
    /// pointer/size) can look it back up via [`Self::get_const`].
    pub(crate) fn record_const(&mut self, addr: MemoryAddress, value: usize) {
        self.known_constants.insert(addr, value);
    }

    /// Returns the translation-time integer constant for `addr`, if any.
    pub(crate) fn get_const(&self, addr: MemoryAddress) -> Option<usize> {
        self.known_constants.get(&addr).copied()
    }
}
