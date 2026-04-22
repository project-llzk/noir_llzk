//! Brillig memory model backed by LLZK RAM.

use std::collections::HashMap;

use acir::brillig::MemoryAddress;
use llzk::prelude::Value;

use crate::brillig_writer::BrilligWriter;
use crate::error::Error;

const STACK_POINTER_ADDRESS: MemoryAddress = MemoryAddress::Direct(0);

pub(super) struct Memory {
    known_constants: HashMap<MemoryAddress, usize>,
}

impl Memory {
    pub(super) fn new() -> Self {
        Self {
            known_constants: HashMap::new(),
        }
    }

    // ── Constant-address operations ────────────────────────────────────

    /// Writes `value` (a felt) into the RAM slot identified by `addr`.
    ///
    /// Invalidates any tracked integer constant for `addr`. Callers that
    /// intend to keep tracking a constant should use [`Self::record_const`]
    /// after this (see [`ConstHandler`](super::opcodes) for the pattern).
    pub(super) fn write<'c, 'b>(
        &mut self,
        writer: &mut BrilligWriter<'c, 'b>,
        addr: MemoryAddress,
        value: Value<'c, 'b>,
    ) -> Result<(), Error> {
        let resolved = self.resolve(addr)?;
        self.known_constants.remove(&resolved);
        let slot = writer.insert_integer(self.slot_of(resolved))?;
        writer.insert_ram_store(slot, value);
        Ok(())
    }

    /// Reads the felt stored in the RAM slot identified by `addr`.
    pub(super) fn read<'c, 'b>(
        &self,
        writer: &mut BrilligWriter<'c, 'b>,
        addr: MemoryAddress,
    ) -> Result<Value<'c, 'b>, Error> {
        let resolved = self.resolve(addr)?;
        let slot = writer.insert_integer(self.slot_of(resolved))?;
        writer.insert_ram_load(slot)
    }

    // ── Dynamic-pointer operations ─────────────────────────────────────
    //
    // Destination slot is held as a felt at `pointer_addr`; the actual
    // address is only known at runtime.

    pub(super) fn write_dynamic<'c, 'b>(
        &mut self,
        writer: &mut BrilligWriter<'c, 'b>,
        pointer_addr: MemoryAddress,
        value: Value<'c, 'b>,
    ) -> Result<(), Error> {
        let ptr_val = self.read(writer, pointer_addr)?;
        let ptr_idx = writer.cast_to_index(ptr_val)?;
        writer.insert_ram_store(ptr_idx, value);
        Ok(())
    }

    pub(super) fn read_dynamic<'c, 'b>(
        &self,
        writer: &mut BrilligWriter<'c, 'b>,
        pointer_addr: MemoryAddress,
    ) -> Result<Value<'c, 'b>, Error> {
        let ptr_val = self.read(writer, pointer_addr)?;
        let ptr_idx = writer.cast_to_index(ptr_val)?;
        writer.insert_ram_load(ptr_idx)
    }

    // ── Translation-time integer tracking ──────────────────────────────
    //
    // Only pointers and lengths are tracked here — the stack pointer (slot
    // 0), `CalldataCopy` size/offset, and `Stop` return_data pointer/size.

    pub(super) fn record_const(&mut self, addr: MemoryAddress, value: usize) -> Result<(), Error> {
        let resolved = self.resolve(addr)?;
        self.known_constants.insert(resolved, value);
        Ok(())
    }

    pub(super) fn get_const(&self, addr: MemoryAddress) -> Result<Option<usize>, Error> {
        Ok(self.known_constants.get(&self.resolve(addr)?).copied())
    }

    /// Resolves `addr` to its canonical [`MemoryAddress::Direct`] form.
    /// `Relative(off)` becomes `Direct(sp + off)` where `sp` is the
    /// constant tracked for slot 0.
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

    fn slot_of(&self, resolved: MemoryAddress) -> usize {
        let MemoryAddress::Direct(slot) = resolved else {
            unreachable!("resolve only returns Direct");
        };
        slot as usize
    }
}
