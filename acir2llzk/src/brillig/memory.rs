//! Brillig memory model backed by LLZK RAM.
use std::collections::HashMap;

use acir::AcirField;
use acir::FieldElement;
use acir::brillig::{MemoryAddress, Opcode as BrilligOpcode};
use brillig_vm::STACK_POINTER_ADDRESS;
use llzk::prelude::Value;

use crate::brillig_writer::BrilligWriter;
use crate::error::Error;

impl<'c, 'a> BrilligWriter<'c, 'a> {
    /// Writes `value` into the RAM slot identified by `addr`.
    pub(super) fn insert_write(
        &mut self,
        addr: MemoryAddress,
        value: Value<'c, 'a>,
    ) -> Result<(), Error> {
        let target_idx = self.compute_addr_idx(addr)?;
        self.insert_ram_store(target_idx, value);
        Ok(())
    }

    /// Reads the felt stored in the RAM slot identified by `addr`.
    pub(super) fn insert_read(&mut self, addr: MemoryAddress) -> Result<Value<'c, 'a>, Error> {
        let target_idx = self.compute_addr_idx(addr)?;
        self.insert_ram_load(target_idx)
    }

    /// Stores `value` to the RAM slot whose address is held as a felt at
    /// `pointer_addr`.
    pub(super) fn insert_dynamic_write(
        &mut self,
        pointer_addr: MemoryAddress,
        value: Value<'c, 'a>,
    ) -> Result<(), Error> {
        let ptr_val = self.insert_read(pointer_addr)?;
        let ptr_idx = self.cast_to_index(ptr_val)?;
        self.insert_ram_store(ptr_idx, value);
        Ok(())
    }

    /// Loads from the RAM slot whose address is held as a felt at
    /// `pointer_addr`.
    pub(super) fn insert_dynamic_read(
        &mut self,
        pointer_addr: MemoryAddress,
    ) -> Result<Value<'c, 'a>, Error> {
        let ptr_val = self.insert_read(pointer_addr)?;
        let ptr_idx = self.cast_to_index(ptr_val)?;
        self.insert_ram_load(ptr_idx)
    }

    /// Emits an SSA index value naming the RAM slot for `addr`.
    pub(super) fn compute_addr_idx(&mut self, addr: MemoryAddress) -> Result<Value<'c, 'a>, Error> {
        match addr {
            MemoryAddress::Direct(slot) => self.insert_integer(slot as usize),
            MemoryAddress::Relative(off) => self.compute_relative_idx(off),
        }
    }

    /// Lowers `Relative(offset)` to `cast_to_index(ram.load @0) + offset`.
    pub(super) fn compute_relative_idx(&mut self, offset: u32) -> Result<Value<'c, 'a>, Error> {
        let sp_addr = self.insert_integer(STACK_POINTER_ADDRESS_SLOT as usize)?;
        let sp_felt = self.insert_ram_load(sp_addr)?;
        let sp_idx = self.cast_to_index(sp_felt)?;
        if offset == 0 {
            Ok(sp_idx)
        } else {
            let off_idx = self.insert_integer(offset as usize)?;
            self.insert_index_add(sp_idx, off_idx)
        }
    }
}

const STACK_POINTER_ADDRESS_SLOT: u32 = match STACK_POINTER_ADDRESS {
    MemoryAddress::Direct(slot) => slot,
    MemoryAddress::Relative(_) => {
        panic!("STACK_POINTER_ADDRESS is defined as Direct in brillig_vm")
    }
};

// ── CalldataCopy compile-time resolver ─────────────────────────────────

/// Walks `bytecode` linearly and records every `Const` write into a
/// flat slot → value map; when a `CalldataCopy` is reached, looks up
/// its `size`, `offset`, and `destination_address` against the map and returns call data.
pub(super) fn precompute_calldata_copy_params(
    bytecode: &[BrilligOpcode<FieldElement>],
) -> Result<(u32, usize, usize), Error> {
    let mut sp: Option<u32> = None;
    let mut slots: HashMap<u32, u32> = HashMap::new();

    for (i, op) in bytecode.iter().enumerate() {
        match op {
            BrilligOpcode::Const {
                destination, value, ..
            } => {
                let Some(v) = value.try_to_u32() else {
                    continue;
                };
                let Some(slot) = resolve_slot(*destination, sp) else {
                    continue;
                };
                slots.insert(slot, v);
                if slot == STACK_POINTER_ADDRESS_SLOT {
                    sp = Some(v);
                }
            }
            BrilligOpcode::CalldataCopy {
                destination_address,
                size_address,
                offset_address,
            } => {
                let size = read(&slots, *size_address, sp, "size", i)? as usize;
                let offset = read(&slots, *offset_address, sp, "offset", i)? as usize;
                let destination_slot = resolve_slot(*destination_address, sp).ok_or_else(|| {
                    Error::UnsupportedBrillig {
                        reason: format!(
                            "CalldataCopy at bytecode index {i}: cannot resolve \
                             destination_address {destination_address:?} — \
                             slot 0 (stack pointer) has no tracked Const value"
                        ),
                    }
                })?;
                return Ok((destination_slot, size, offset));
            }
            _ => {}
        }
    }

    Err(Error::UnsupportedBrillig {
        reason: "Brillig functions must allocate their call data".to_string(),
    })
}

fn resolve_slot(addr: MemoryAddress, sp: Option<u32>) -> Option<u32> {
    match addr {
        MemoryAddress::Direct(slot) => Some(slot),
        MemoryAddress::Relative(off) => sp.map(|sp| sp + off),
    }
}

fn read(
    slots: &HashMap<u32, u32>,
    addr: MemoryAddress,
    sp: Option<u32>,
    field_name: &str,
    opcode_index: usize,
) -> Result<u32, Error> {
    let slot = resolve_slot(addr, sp).ok_or_else(|| Error::UnsupportedBrillig {
        reason: format!(
            "CalldataCopy at bytecode index {opcode_index}: cannot resolve \
             {field_name} address {addr:?} — slot 0 (stack pointer) has \
             no tracked Const value"
        ),
    })?;
    slots
        .get(&slot)
        .copied()
        .ok_or_else(|| Error::UnsupportedBrillig {
            reason: format!(
                "CalldataCopy at bytecode index {opcode_index}: {field_name} \
                 register ({addr:?}, resolved slot {slot}) has no tracked \
                 Const value"
            ),
        })
}
