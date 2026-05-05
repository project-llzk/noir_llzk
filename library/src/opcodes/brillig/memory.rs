//! Brillig memory model backed by LLZK RAM.

use std::collections::HashMap;

use acir::brillig::MemoryAddress;
use brillig_vm::STACK_POINTER_ADDRESS;
use llzk::prelude::Value;

use crate::brillig_writer::BrilligWriter;
use crate::error::Error;

#[derive(Clone)]
pub(super) struct Memory {
    known_constants: HashMap<MemoryAddress, usize>,
    /// Tracked stack pointer. `None` until a `Const` (or folded
    /// `BinaryIntOp` prologue) write to slot 0 establishes it, or after
    /// any untracked write to slot 0 clobbers it.
    sp: Option<usize>,
}

impl Memory {
    pub(super) fn new() -> Self {
        Self {
            known_constants: HashMap::new(),
            sp: None,
        }
    }

    // ── Constant-address operations ────────────────────────────────────

    /// Writes `value` (a felt) into the RAM slot identified by `addr`.
    ///
    /// Invalidates any tracked integer constant for `addr` (including the
    /// stack pointer, if `addr` resolves to slot 0). Callers that intend
    /// to keep tracking a constant should use [`Self::record_const`]
    /// after this (see [`ConstHandler`](super::opcodes) for the pattern).
    pub(super) fn write<'c, 'b>(
        &mut self,
        writer: &mut BrilligWriter<'c, 'b>,
        addr: MemoryAddress,
        value: Value<'c, 'b>,
    ) -> Result<(), Error> {
        let resolved = self.resolve(addr)?;
        self.invalidate_const(resolved);
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
        if resolved == STACK_POINTER_ADDRESS {
            self.sp = Some(value);
        } else {
            self.known_constants.insert(resolved, value);
        }
        Ok(())
    }

    /// Sets the stack pointer to `sp`. Called by handlers that
    /// have already established destination == slot 0 (e.g. the
    /// `BinaryIntOp` prologue fold) and want to skip re-resolving the
    /// address.
    pub(super) fn set_sp(&mut self, sp: usize) {
        self.sp = Some(sp);
    }

    pub(super) fn get_const(&self, addr: MemoryAddress) -> Result<Option<usize>, Error> {
        let resolved = self.resolve(addr)?;
        if resolved == STACK_POINTER_ADDRESS {
            Ok(self.sp)
        } else {
            Ok(self.known_constants.get(&resolved).copied())
        }
    }

    /// Resolves `addr` to its canonical [`MemoryAddress::Direct`] form.
    /// `Relative(off)` becomes `Direct(sp + off)` where `sp` is the
    /// tracked stack pointer.
    pub(super) fn resolve(&self, addr: MemoryAddress) -> Result<MemoryAddress, Error> {
        match addr {
            MemoryAddress::Direct(_) => Ok(addr),
            MemoryAddress::Relative(offset) => {
                let sp = self.sp.ok_or(Error::UnresolvedStackPointer { offset })?;
                Ok(MemoryAddress::Direct((sp + offset as usize) as u32))
            }
        }
    }

    /// Replaces `self` with the intersection of `self` and `other`:
    /// retains an entry only when both sides agree on the value, drops
    /// it otherwise. Used at control-flow merge points (e.g. the post-
    /// `scf.if` join) so cache state never claims a value that holds on
    /// only one of the merged paths.
    pub(super) fn meet(&mut self, other: &Memory) {
        if self.sp != other.sp {
            self.sp = None;
        }
        self.known_constants
            .retain(|k, v| other.known_constants.get(k).copied() == Some(*v));
    }

    fn invalidate_const(&mut self, resolved: MemoryAddress) {
        if resolved == STACK_POINTER_ADDRESS {
            self.sp = None;
        } else {
            self.known_constants.remove(&resolved);
        }
    }

    fn slot_of(&self, resolved: MemoryAddress) -> usize {
        let MemoryAddress::Direct(slot) = resolved else {
            unreachable!("resolve only returns Direct");
        };
        slot as usize
    }
}
