//! Brillig memory model.
//!
//! Single chokepoint for every register and constant-tracker access —
//! handlers go through this API instead of touching the underlying maps.
//!
//! `Relative(off)` resolves to `Direct(mem[0] + off)` at every access,
//! where `mem[0]` is the Brillig stack pointer. SP must have been written
//! as a known integer constant (via a `Const` to slot 0) before any
//! `Relative` use; otherwise access fails with
//! [`Error::UnresolvedStackPointer`].

use std::collections::HashMap;

use acir::brillig::MemoryAddress;
use llzk::prelude::Value;

use crate::error::Error;

/// Slot 0: the Brillig stack pointer.
const STACK_POINTER_ADDRESS: MemoryAddress = MemoryAddress::Direct(0);

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
    pub(crate) fn write(
        &mut self,
        addr: MemoryAddress,
        value: Value<'c, 'b>,
    ) -> Result<(), Error> {
        let resolved = self.resolve(addr)?;
        self.regs.insert(resolved, value);
        Ok(())
    }

    /// Returns the current SSA binding for `addr`, or
    /// [`Error::UndefinedRegister`] if nothing has been written yet.
    pub(crate) fn read(
        &self,
        addr: MemoryAddress,
        opcode_index: usize,
    ) -> Result<Value<'c, 'b>, Error> {
        let resolved = self.resolve(addr)?;
        self.regs
            .get(&resolved)
            .copied()
            .ok_or(Error::UndefinedRegister {
                addr: resolved.to_u32() as usize,
                opcode_index,
            })
    }

    /// Records a translation-time integer constant for `addr`.
    ///
    /// Used by handlers that emit a constant write (`Const`) to remember
    /// the integer value, so that later opcodes which need a compile-time
    /// integer (e.g. `CalldataCopy` size/offset, `Stop` return_data
    /// pointer/size, `Relative` resolution) can look it back up via
    /// [`Self::get_const`].
    pub(crate) fn record_const(
        &mut self,
        addr: MemoryAddress,
        value: usize,
    ) -> Result<(), Error> {
        let resolved = self.resolve(addr)?;
        self.known_constants.insert(resolved, value);
        Ok(())
    }

    /// Returns the translation-time integer constant for `addr`, if any.
    pub(crate) fn get_const(&self, addr: MemoryAddress) -> Result<Option<usize>, Error> {
        let resolved = self.resolve(addr)?;
        Ok(self.known_constants.get(&resolved).copied())
    }

    /// Resolves `addr` to its canonical [`MemoryAddress::Direct`] form.
    ///
    /// `Direct` passes through unchanged. `Relative(off)` becomes
    /// `Direct(sp + off)` where `sp` is the integer value tracked for
    /// slot 0. Errors if the stack pointer has not been initialised.
    pub(super) fn resolve(&self, addr: MemoryAddress) -> Result<MemoryAddress, Error> {
        match addr {
            MemoryAddress::Direct(_) => Ok(addr),
            MemoryAddress::Relative(offset) => {
                let sp = self
                    .known_constants
                    .get(&STACK_POINTER_ADDRESS)
                    .copied()
                    .ok_or(Error::UnresolvedStackPointer { offset })?;
                Ok(MemoryAddress::Direct((sp + offset as usize) as u32))
            }
        }
    }
}
