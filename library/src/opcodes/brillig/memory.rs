//! Brillig memory model backed by LLZK RAM.
//!
//! Type tracking is *not* maintained here at translation time. Instead,
//! [`crate::opcodes::brillig::type_inference::infer_types`] runs once over
//! the bytecode before translation begins and produces an
//! [`InferredTypes`] table. `Memory` consults that table for
//! `read_inferred` lookups; the table also propagates types through
//! dynamic stores (when the pointer is a translation-time constant) so
//! follow-up reads see a typed entry. See `type_inference.rs` for the
//! pre-pass details.

use std::collections::HashMap;

use acir::brillig::{BitSize, MemoryAddress};
use llzk::prelude::Value;

use crate::brillig_writer::BrilligWriter;
use crate::error::Error;

use super::type_inference::InferredTypes;

const STACK_POINTER_ADDRESS: MemoryAddress = MemoryAddress::Direct(0);

pub(super) struct Memory {
    inferred: InferredTypes,
    known_constants: HashMap<MemoryAddress, usize>,
}

impl Memory {
    pub(super) fn new(inferred: InferredTypes) -> Self {
        Self {
            inferred,
            known_constants: HashMap::new(),
        }
    }

    // ── Constant-address operations ────────────────────────────────────
    //
    // Destination named directly by `MemoryAddress` (after `Relative`
    // resolution). `iN` values are widened to felt before storage and
    // narrowed back on read.

    pub(super) fn write_constant_address<'c, 'b>(
        &self,
        writer: &mut BrilligWriter<'c, 'b>,
        addr: MemoryAddress,
        value: Value<'c, 'b>,
        bit_size: BitSize,
    ) -> Result<(), Error> {
        let storage = match bit_size {
            BitSize::Field => value,
            BitSize::Integer(_) => {
                let as_index = writer.insert_arith_index_cast(value, writer.index_type())?;
                writer.insert_cast_to_felt(as_index)?
            }
        };
        let slot = writer.insert_integer(self.slot_of(addr)?)?;
        writer.insert_ram_store(slot, storage);
        Ok(())
    }

    pub(super) fn read_constant_address<'c, 'b>(
        &self,
        writer: &mut BrilligWriter<'c, 'b>,
        addr: MemoryAddress,
        expected: BitSize,
    ) -> Result<Value<'c, 'b>, Error> {
        self.load_narrowed(writer, addr, expected)
    }

    pub(super) fn read_inferred<'c, 'b>(
        &self,
        writer: &mut BrilligWriter<'c, 'b>,
        addr: MemoryAddress,
        opcode_index: usize,
    ) -> Result<(Value<'c, 'b>, BitSize), Error> {
        let bit_size =
            self.inferred
                .lookup(opcode_index, addr)
                .ok_or(Error::UndefinedRegister {
                    addr: addr.to_u32() as usize,
                    opcode_index,
                })?;
        let value = self.load_narrowed(writer, addr, bit_size)?;
        Ok((value, bit_size))
    }

    // ── Dynamic-pointer operations ─────────────────────────────────────
    //
    // Destination slot is held as a value at `pointer_addr`; the actual
    // address is only known at runtime. Type propagation for the
    // pointed-to slot lives in the pre-pass, not here.

    pub(super) fn write_dynamic_address<'c, 'b>(
        &self,
        writer: &mut BrilligWriter<'c, 'b>,
        pointer_addr: MemoryAddress,
        value: Value<'c, 'b>,
        opcode_index: usize,
    ) -> Result<(), Error> {
        let ptr_idx = self.dynamic_addr(writer, pointer_addr, opcode_index)?;
        writer.insert_ram_store(ptr_idx, value);
        Ok(())
    }

    pub(super) fn read_dynamic_address<'c, 'b>(
        &self,
        writer: &mut BrilligWriter<'c, 'b>,
        pointer_addr: MemoryAddress,
        opcode_index: usize,
    ) -> Result<Value<'c, 'b>, Error> {
        let ptr_idx = self.dynamic_addr(writer, pointer_addr, opcode_index)?;
        writer.insert_ram_load(ptr_idx)
    }

    // ── Translation-time integer tracking ──────────────────────────────

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

    // ── Private helpers ───────────────────────────────────────────────

    fn slot_of(&self, addr: MemoryAddress) -> Result<usize, Error> {
        let MemoryAddress::Direct(slot) = self.resolve(addr)? else {
            unreachable!("resolve only returns Direct");
        };
        Ok(slot as usize)
    }

    /// Emits `ram.load` at `addr` and narrows the felt back to `bit_size`.
    fn load_narrowed<'c, 'b>(
        &self,
        writer: &mut BrilligWriter<'c, 'b>,
        addr: MemoryAddress,
        bit_size: BitSize,
    ) -> Result<Value<'c, 'b>, Error> {
        let slot = writer.insert_integer(self.slot_of(addr)?)?;
        let raw = writer.insert_ram_load(slot)?;
        match bit_size {
            BitSize::Field => Ok(raw),
            BitSize::Integer(int_size) => {
                let int_ty = writer.integer_type(u32::from(int_size));
                let as_index = writer.insert_cast_to_index(raw)?;
                writer.insert_arith_index_cast(as_index, int_ty)
            }
        }
    }

    /// Loads the pointer held at `pointer_addr` and casts it to `index`
    /// for use as a `ram.load`/`ram.store` address.
    fn dynamic_addr<'c, 'b>(
        &self,
        writer: &mut BrilligWriter<'c, 'b>,
        pointer_addr: MemoryAddress,
        opcode_index: usize,
    ) -> Result<Value<'c, 'b>, Error> {
        let (ptr, _) = self.read_inferred(writer, pointer_addr, opcode_index)?;
        writer.cast_to_index(ptr)
    }
}
