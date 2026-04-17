//! Brillig memory model backed by LLZK RAM.

use std::collections::HashMap;

use acir::brillig::MemoryAddress;
use llzk::prelude::{Type, Value, ValueLike};

use crate::brillig_writer::BrilligWriter;
use crate::error::Error;

const STACK_POINTER_ADDRESS: MemoryAddress = MemoryAddress::Direct(0);

pub(super) struct Memory<'c> {
    /// LLZK type last written at each resolved slot; absent means undefined.
    types: HashMap<MemoryAddress, Type<'c>>,
    /// Translation-time integer constants (SP, calldata sizes, return-data metadata).
    known_constants: HashMap<MemoryAddress, usize>,
}

impl<'c> Memory<'c> {
    pub(super) fn new() -> Self {
        Self {
            types: HashMap::new(),
            known_constants: HashMap::new(),
        }
    }

    /// Emits a `ram.store` at the resolved slot and records the value's
    /// type for later consistency checks.
    pub(super) fn write<'b>(
        &mut self,
        writer: &mut BrilligWriter<'c, 'b>,
        addr: MemoryAddress,
        value: Value<'c, 'b>,
    ) -> Result<(), Error> {
        let resolved = self.resolve(addr)?;
        self.types.insert(resolved, value.r#type());
        emit_store(writer, direct_slot(resolved), value)?;
        Ok(())
    }

    /// Emits a `ram.load` at the resolved slot with the caller-specified
    /// `expected` type.
    ///
    /// In debug builds, asserts that `expected` matches the type the slot
    /// was last written as. Noir is expected to preserve type consistency
    /// at every slot; a mismatch indicates a translator or upstream bug.
    pub(super) fn read<'b>(
        &mut self,
        writer: &mut BrilligWriter<'c, 'b>,
        addr: MemoryAddress,
        expected: Type<'c>,
        opcode_index: usize,
    ) -> Result<Value<'c, 'b>, Error> {
        let resolved = self.resolve(addr)?;
        let stored = self.lookup_type(resolved, opcode_index)?;
        debug_assert!(
            stored == expected,
            "Brillig type consistency violated at {resolved:?}: stored {stored:?}, read as {expected:?}"
        );
        emit_load(writer, direct_slot(resolved), expected)
    }

    /// Emits a `ram.load` using whatever type was last stored at the slot.
    ///
    /// For opcodes that shuttle values without knowing their type
    pub(super) fn read_inferred<'b>(
        &mut self,
        writer: &mut BrilligWriter<'c, 'b>,
        addr: MemoryAddress,
        opcode_index: usize,
    ) -> Result<Value<'c, 'b>, Error> {
        let resolved = self.resolve(addr)?;
        let ty = self.lookup_type(resolved, opcode_index)?;
        emit_load(writer, direct_slot(resolved), ty)
    }

    /// Records a translation-time integer constant for `addr`.
    ///
    /// Independent of the SSA / RAM state: used for slots whose value is
    /// known at compile time and needed for IR emission.
    pub(super) fn record_const(&mut self, addr: MemoryAddress, value: usize) -> Result<(), Error> {
        let resolved = self.resolve(addr)?;
        self.known_constants.insert(resolved, value);
        Ok(())
    }

    /// Returns the translation-time integer constant for `addr`, if any.
    pub(super) fn get_const(&self, addr: MemoryAddress) -> Result<Option<usize>, Error> {
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

    fn lookup_type(&self, resolved: MemoryAddress, opcode_index: usize) -> Result<Type<'c>, Error> {
        self.types
            .get(&resolved)
            .copied()
            .ok_or(Error::UndefinedRegister {
                addr: resolved.to_u32() as usize,
                opcode_index,
            })
    }
}

fn direct_slot(addr: MemoryAddress) -> usize {
    let MemoryAddress::Direct(slot) = addr else {
        unreachable!("resolve() only returns Direct");
    };
    slot as usize
}

fn emit_load<'c, 'b>(
    writer: &mut BrilligWriter<'c, 'b>,
    slot: usize,
    ty: Type<'c>,
) -> Result<Value<'c, 'b>, Error> {
    let idx = writer.insert_integer(slot)?;
    writer.insert_ram_load(idx, ty)
}

fn emit_store<'c, 'b>(
    writer: &mut BrilligWriter<'c, 'b>,
    slot: usize,
    value: Value<'c, 'b>,
) -> Result<(), Error> {
    let idx = writer.insert_integer(slot)?;
    writer.insert_ram_store(idx, value);
    Ok(())
}
