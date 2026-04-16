//! Brillig register file.

use std::collections::HashMap;

use acir::brillig::MemoryAddress;
use llzk::prelude::Value;

use crate::error::Error;

/// SSA-valued Brillig register file, keyed by `MemoryAddress`.
pub(crate) struct RegMap<'c, 'b> {
    map: HashMap<MemoryAddress, Value<'c, 'b>>,
}

impl<'c, 'b> RegMap<'c, 'b> {
    pub(crate) fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Records `value` as the current SSA binding for `addr`.
    pub(crate) fn set(&mut self, addr: MemoryAddress, value: Value<'c, 'b>) {
        self.map.insert(addr, value);
    }

    /// Returns the current SSA binding for `addr`, or [`Error::UndefinedRegister`]
    /// with the supplied `opcode_index` if nothing has been written to the
    /// register yet.
    pub(crate) fn get(
        &self,
        addr: MemoryAddress,
        opcode_index: usize,
    ) -> Result<Value<'c, 'b>, Error> {
        self.map
            .get(&addr)
            .copied()
            .ok_or(Error::UndefinedRegister {
                addr: addr.to_u32() as usize,
                opcode_index,
            })
    }
}
