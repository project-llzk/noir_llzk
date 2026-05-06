//! Brillig memory model backed by LLZK RAM.
//!
//! [`Memory`] is the shared interface; [`StaticMemory`] tracks the stack
//! pointer at translation time and [`DynamicMemory`] handles relative
//! addressing by emitting runtime SP loads.

use std::collections::HashMap;

use acir::FieldElement;
use acir::brillig::{MemoryAddress, Opcode as BrilligOpcode};
use brillig_vm::STACK_POINTER_ADDRESS;
use llzk::prelude::Value;

use crate::brillig_writer::BrilligWriter;
use crate::error::Error;

/// Constant caches shared by both memory modes.
#[derive(Clone, Default)]
pub(super) struct MemoryCache {
    heap_constants: HashMap<u32, usize>,
    stack_constants: HashMap<u32, usize>,
}

/// Translation-time view of Brillig RAM.
///
/// Implementations supply stack-pointerx / `Relative` behaviour; the rest is
/// defaulted.
pub(super) trait Memory: Clone {
    fn cache(&self) -> &MemoryCache;
    fn cache_mut(&mut self) -> &mut MemoryCache;

    /// Emits an SSA index value for `Relative(offset)`.
    fn compute_relative_idx<'c, 'b>(
        &self,
        writer: &mut BrilligWriter<'c, 'b>,
        offset: u32,
    ) -> Result<Value<'c, 'b>, Error>;

    /// Records a translation-time integer for slot 0.
    fn record_sp_const(&mut self, value: usize);

    /// Returns the currently tracked SP integer constant, if any.
    fn sp_const(&self) -> Option<usize>;

    // ── Defaults ───────────────────────────────────────────────────

    /// Writes `value` into the RAM slot identified by `addr`, invalidating
    /// any tracked integer constant for that slot. Callers wanting to keep
    /// tracking should follow with [`Memory::record_const`].
    fn write<'c, 'b>(
        &mut self,
        writer: &mut BrilligWriter<'c, 'b>,
        addr: MemoryAddress,
        value: Value<'c, 'b>,
    ) -> Result<(), Error> {
        self.invalidate_on_write(addr);
        let target_idx = self.compute_addr_idx(writer, addr)?;
        writer.insert_ram_store(target_idx, value);
        Ok(())
    }

    /// Reads the felt stored in the RAM slot identified by `addr`.
    fn read<'c, 'b>(
        &self,
        writer: &mut BrilligWriter<'c, 'b>,
        addr: MemoryAddress,
    ) -> Result<Value<'c, 'b>, Error> {
        let target_idx = self.compute_addr_idx(writer, addr)?;
        writer.insert_ram_load(target_idx)
    }

    /// Stores `value` to the RAM slot whose address is held as a felt at
    /// `pointer_addr`.
    fn write_dynamic<'c, 'b>(
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

    /// Loads from the RAM slot whose address is held as a felt at
    /// `pointer_addr`.
    fn read_dynamic<'c, 'b>(
        &self,
        writer: &mut BrilligWriter<'c, 'b>,
        pointer_addr: MemoryAddress,
    ) -> Result<Value<'c, 'b>, Error> {
        let ptr_val = self.read(writer, pointer_addr)?;
        let ptr_idx = writer.cast_to_index(ptr_val)?;
        writer.insert_ram_load(ptr_idx)
    }

    /// Records a translation-time integer for `addr`.
    ///
    /// Pointers, lengths, and the SP are tracked here so handlers needing
    /// a translation-time integer (e.g. `CalldataCopy` size, `Stop`
    /// return-data pointer/size) can recover them. Direct slots go in
    /// `heap_constants`; Relative offsets go in `stack_constants` and
    /// survive only within a single SP scope.
    fn record_const(&mut self, addr: MemoryAddress, value: usize) -> Result<(), Error> {
        match addr {
            MemoryAddress::Direct(slot) if slot == STACK_POINTER_ADDRESS_SLOT => {
                self.record_sp_const(value);
            }
            MemoryAddress::Direct(slot) => {
                self.cache_mut().heap_constants.insert(slot, value);
            }
            MemoryAddress::Relative(off) => {
                self.cache_mut().stack_constants.insert(off, value);
            }
        }
        Ok(())
    }

    /// Returns the tracked integer for `addr`, if any.
    fn get_const(&self, addr: MemoryAddress) -> Result<Option<usize>, Error> {
        match addr {
            MemoryAddress::Direct(slot) if slot == STACK_POINTER_ADDRESS_SLOT => {
                Ok(self.sp_const())
            }
            MemoryAddress::Direct(slot) => Ok(self.cache().heap_constants.get(&slot).copied()),
            MemoryAddress::Relative(off) => Ok(self.cache().stack_constants.get(&off).copied()),
        }
    }

    /// Replaces `self` with the intersection of `self` and `other`:
    /// retains a cache entry only when both sides agree, drops it
    /// otherwise. Used at control-flow merges so cache state never claims
    /// a value that holds on only one of the merged paths.
    fn meet(&mut self, other: &Self) {
        let other_heap = &other.cache().heap_constants;
        let other_stack = &other.cache().stack_constants;
        self.cache_mut()
            .heap_constants
            .retain(|k, v| other_heap.get(k).copied() == Some(*v));
        self.cache_mut()
            .stack_constants
            .retain(|k, v| other_stack.get(k).copied() == Some(*v));
    }

    /// Emits an SSA index value naming the RAM slot for `addr`.
    fn compute_addr_idx<'c, 'b>(
        &self,
        writer: &mut BrilligWriter<'c, 'b>,
        addr: MemoryAddress,
    ) -> Result<Value<'c, 'b>, Error> {
        match addr {
            MemoryAddress::Direct(slot) => writer.insert_integer(slot as usize),
            MemoryAddress::Relative(off) => self.compute_relative_idx(writer, off),
        }
    }

    /// Invalidates cached integer constants made stale by a write to
    /// `addr`. A slot-0 write  wipes the stack.
    fn invalidate_on_write(&mut self, addr: MemoryAddress) {
        match addr {
            MemoryAddress::Direct(slot) if slot == STACK_POINTER_ADDRESS_SLOT => {
                self.cache_mut().stack_constants.clear();
            }
            MemoryAddress::Direct(slot) => {
                self.cache_mut().heap_constants.remove(&slot);
            }
            MemoryAddress::Relative(off) => {
                self.cache_mut().stack_constants.remove(&off);
            }
        }
    }
}

/// Memory mode for bytecodes whose SP is statically known at every point
/// — the common case. `Relative(off)` resolves to a constant slot via the
/// tracked SP.
#[derive(Clone, Default)]
pub(super) struct StaticMemory {
    cache: MemoryCache,
    sp: Option<usize>,
}

impl StaticMemory {
    pub(super) fn new() -> Self {
        Self::default()
    }

    fn resolve_relative(&self, offset: u32) -> Result<u32, Error> {
        let sp = self.sp.ok_or(Error::UnresolvedStackPointer { offset })?;
        Ok((sp + offset as usize) as u32)
    }
}

impl Memory for StaticMemory {
    fn cache(&self) -> &MemoryCache {
        &self.cache
    }

    fn cache_mut(&mut self) -> &mut MemoryCache {
        &mut self.cache
    }

    fn compute_relative_idx<'c, 'b>(
        &self,
        writer: &mut BrilligWriter<'c, 'b>,
        offset: u32,
    ) -> Result<Value<'c, 'b>, Error> {
        let slot = self.resolve_relative(offset)?;
        writer.insert_integer(slot as usize)
    }

    fn record_sp_const(&mut self, value: usize) {
        self.sp = Some(value);
    }

    fn sp_const(&self) -> Option<usize> {
        self.sp
    }
}

/// Memory mode for bytecodes that perform frame manipulation on slot 0.
/// SP lives in RAM at runtime; `Relative(off)` lowers to a runtime
/// `cast_to_index(ram.load @0) + off`. A single `initial_sp` is recorded
/// from the program's first SP write so handlers needing the *initial*
/// SP value (e.g. the `Stop` return-data path) can still recover it.
#[derive(Clone, Default)]
pub(super) struct DynamicMemory {
    cache: MemoryCache,
    initial_sp: Option<usize>,
}

impl DynamicMemory {
    pub(super) fn new() -> Self {
        Self::default()
    }
}

impl Memory for DynamicMemory {
    fn cache(&self) -> &MemoryCache {
        &self.cache
    }

    fn cache_mut(&mut self) -> &mut MemoryCache {
        &mut self.cache
    }

    fn compute_relative_idx<'c, 'b>(
        &self,
        writer: &mut BrilligWriter<'c, 'b>,
        offset: u32,
    ) -> Result<Value<'c, 'b>, Error> {
        let sp_addr = writer.insert_integer(0)?;
        let sp_felt = writer.insert_ram_load(sp_addr)?;
        let sp_idx = writer.cast_to_index(sp_felt)?;
        if offset == 0 {
            Ok(sp_idx)
        } else {
            let off_idx = writer.insert_integer(offset as usize)?;
            writer.insert_index_add(sp_idx, off_idx)
        }
    }

    fn record_sp_const(&mut self, value: usize) {
        // First write to slot 0 in dynamic mode locks `initial_sp`; later
        // prologue/restore writes leave it alone.
        if self.initial_sp.is_none() {
            self.initial_sp = Some(value);
        }
    }

    fn sp_const(&self) -> Option<usize> {
        self.initial_sp
    }
}

const STACK_POINTER_ADDRESS_SLOT: u32 = match STACK_POINTER_ADDRESS {
    MemoryAddress::Direct(slot) => slot,
    MemoryAddress::Relative(_) => {
        panic!("STACK_POINTER_ADDRESS is defined as Direct in brillig_vm")
    }
};

/// Returns `true` when the bytecode performs frame manipulation.
pub(super) fn should_be_dynamic(bytecode: &[BrilligOpcode<FieldElement>]) -> bool {
    bytecode.iter().any(|op| {
        matches!(
            op,
            BrilligOpcode::BinaryIntOp { destination, lhs, .. }
                if *destination == STACK_POINTER_ADDRESS && *lhs == STACK_POINTER_ADDRESS
        )
    })
}
