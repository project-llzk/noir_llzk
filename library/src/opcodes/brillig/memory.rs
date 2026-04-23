//! Brillig memory model backed by LLZK RAM.

use std::collections::HashMap;

use acir::brillig::MemoryAddress;
use llzk::prelude::Value;

use crate::brillig_writer::BrilligWriter;
use crate::error::Error;

pub(super) const STACK_POINTER_ADDRESS: MemoryAddress = MemoryAddress::Direct(0);

/// Translation-time call-frame stack tracking the Brillig stack pointer.
///
/// Brillig keeps its stack pointer at RAM slot 0. `Relative(off)` addresses
/// resolve to `Direct(sp + off)` against the current frame's SP. A fresh
/// [`FrameStack`] has one frame with an unset SP; the first write to slot 0
/// initialises it.
///
/// `Call`/`Return` push and pop frames so the callee's `Relative(_)` accesses
/// resolve against the callee's SP and the caller's SP is restored on return.
/// Those wiring points land with Phase 4 of the control-flow work.
struct FrameStack {
    frames: Vec<Frame>,
}

struct Frame {
    /// `None` until a `Const` / folded `BinaryIntOp` write to slot 0
    /// establishes the SP, or again after any untracked write to slot 0
    /// clobbers it.
    sp: Option<usize>,
}

impl FrameStack {
    fn new() -> Self {
        Self {
            frames: vec![Frame { sp: None }],
        }
    }

    fn current_sp(&self) -> Option<usize> {
        self.current_frame().sp
    }

    fn set_sp(&mut self, sp: usize) {
        self.current_frame_mut().sp = Some(sp);
    }

    fn invalidate_sp(&mut self) {
        self.current_frame_mut().sp = None;
    }

    fn current_frame(&self) -> &Frame {
        self.frames
            .last()
            .expect("FrameStack invariant: at least one frame")
    }

    fn current_frame_mut(&mut self) -> &mut Frame {
        self.frames
            .last_mut()
            .expect("FrameStack invariant: at least one frame")
    }
}

pub(super) struct Memory {
    known_constants: HashMap<MemoryAddress, usize>,
    frames: FrameStack,
}

impl Memory {
    pub(super) fn new() -> Self {
        Self {
            known_constants: HashMap::new(),
            frames: FrameStack::new(),
        }
    }

    // ── Constant-address operations ────────────────────────────────────

    /// Writes `value` (a felt) into the RAM slot identified by `addr`.
    ///
    /// Invalidates any tracked integer constant for `addr` (including the
    /// current frame's stack pointer, if `addr` resolves to slot 0). Callers
    /// that intend to keep tracking a constant should use
    /// [`Self::record_const`] after this (see [`ConstHandler`](super::opcodes)
    /// for the pattern).
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
            self.frames.set_sp(value);
        } else {
            self.known_constants.insert(resolved, value);
        }
        Ok(())
    }

    /// Sets the current frame's stack pointer to `sp`. Called by handlers
    /// that have already established destination == slot 0 (e.g. the
    /// `BinaryIntOp` prologue fold) and want to skip re-resolving the
    /// address.
    pub(super) fn set_sp(&mut self, sp: usize) {
        self.frames.set_sp(sp);
    }

    pub(super) fn get_const(&self, addr: MemoryAddress) -> Result<Option<usize>, Error> {
        let resolved = self.resolve(addr)?;
        if resolved == STACK_POINTER_ADDRESS {
            Ok(self.frames.current_sp())
        } else {
            Ok(self.known_constants.get(&resolved).copied())
        }
    }

    /// Resolves `addr` to its canonical [`MemoryAddress::Direct`] form.
    /// `Relative(off)` becomes `Direct(sp + off)` where `sp` is the current
    /// frame's tracked stack pointer.
    pub(super) fn resolve(&self, addr: MemoryAddress) -> Result<MemoryAddress, Error> {
        match addr {
            MemoryAddress::Direct(_) => Ok(addr),
            MemoryAddress::Relative(offset) => {
                let sp = self
                    .frames
                    .current_sp()
                    .ok_or(Error::UnresolvedStackPointer { offset })?;
                Ok(MemoryAddress::Direct((sp + offset as usize) as u32))
            }
        }
    }

    fn invalidate_const(&mut self, resolved: MemoryAddress) {
        if resolved == STACK_POINTER_ADDRESS {
            self.frames.invalidate_sp();
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
