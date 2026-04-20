//! Translation-time type inference over a Brillig function body.
//!
//! Brillig opcodes are partially typed: `Const`, `Cast`, `BinaryIntOp`,
//! `Not` and `IndirectConst` carry an explicit `BitSize`, while `Mov`,
//! `Load` and `Store` are type-erased — the runtime VM relies on tagged
//! `MemoryValue` cells to recover types. Our LLZK lowering uses a
//! monomorphic felt-only RAM, so we have no runtime tag and must instead
//! pre-compute the bit size of every slot at every program point.
//!
//! [`infer_types`] walks the bytecode once, threading a transient type
//! state through it, and records the inferred bit size at every
//! `read_inferred` call site (currently `Mov` source, `Cast` source,
//! `Load` source pointer, `Store` destination pointer + source, and
//! `IndirectConst` destination pointer). [`Memory::read_inferred`]
//! consults the resulting [`InferredTypes`] table — no runtime type map
//! is maintained anymore.
//!
//! The pre-pass mirrors [`Memory`]'s constant tracking internally so that
//! `Relative` addresses resolve through SP and dynamic stores via a known
//! pointer propagate the source's bit size to the destination slot — the
//! same rule [`Memory::write_dynamic`] used to apply at translation time.
//!
//! Today's bytecode is straight-line; once `Jump`/`JumpIf`/`Call`/`Return`
//! handlers land this pass needs to become a forward dataflow with merges
//! at join points.

use std::collections::HashMap;

use acir::brillig::{BitSize, MemoryAddress, Opcode as B};
use acir::{AcirField, FieldElement};

use crate::error::Error;

const STACK_POINTER_ADDRESS: MemoryAddress = MemoryAddress::Direct(0);

/// Bit size of every slot read at every `read_inferred` call site.
///
/// Keyed by the *raw* (unresolved) `MemoryAddress` from the opcode, so a
/// translation-time caller can query with the same address it passes to
/// [`Memory::read_inferred`].
#[derive(Default)]
pub(super) struct InferredTypes {
    reads: HashMap<(usize, MemoryAddress), BitSize>,
}

impl InferredTypes {
    pub(super) fn lookup(&self, opcode_index: usize, addr: MemoryAddress) -> Option<BitSize> {
        self.reads.get(&(opcode_index, addr)).copied()
    }
}

/// Pre-walks `bytecode`, returning the inferred bit size at every
/// `read_inferred` site. Errors mirror [`Memory`]'s runtime errors —
/// `UndefinedRegister` for a read of a never-written slot and
/// `UnresolvedStackPointer` for a `Relative` address before SP is set.
pub(super) fn infer_types(bytecode: &[B<FieldElement>]) -> Result<InferredTypes, Error> {
    let mut state = TypeState::default();
    let mut out = InferredTypes::default();
    for (i, op) in bytecode.iter().enumerate() {
        process(i, op, &mut state, &mut out)?;
    }
    Ok(out)
}

#[derive(Default)]
struct TypeState {
    types: HashMap<MemoryAddress, BitSize>,
    known_constants: HashMap<MemoryAddress, usize>,
}

impl TypeState {
    fn resolve(&self, addr: MemoryAddress) -> Result<MemoryAddress, Error> {
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

    fn type_at(&self, addr: MemoryAddress, opcode_index: usize) -> Result<BitSize, Error> {
        let resolved = self.resolve(addr)?;
        self.types
            .get(&resolved)
            .copied()
            .ok_or(Error::UndefinedRegister {
                addr: resolved.to_u32() as usize,
                opcode_index,
            })
    }

    fn set_type(&mut self, addr: MemoryAddress, bit_size: BitSize) -> Result<(), Error> {
        let resolved = self.resolve(addr)?;
        self.types.insert(resolved, bit_size);
        Ok(())
    }
}

fn record_inferred_read(
    out: &mut InferredTypes,
    state: &TypeState,
    opcode_index: usize,
    addr: MemoryAddress,
) -> Result<(), Error> {
    let bit_size = state.type_at(addr, opcode_index)?;
    out.reads.insert((opcode_index, addr), bit_size);
    Ok(())
}

fn process(
    i: usize,
    op: &B<FieldElement>,
    state: &mut TypeState,
    out: &mut InferredTypes,
) -> Result<(), Error> {
    match op {
        B::Const {
            destination,
            bit_size,
            value,
        } => {
            state.set_type(*destination, *bit_size)?;
            if matches!(bit_size, BitSize::Integer(_))
                && let Some(v) = value.try_into_u128()
            {
                let resolved = state.resolve(*destination)?;
                state.known_constants.insert(resolved, v as usize);
            }
        }

        B::Mov {
            destination,
            source,
        } => {
            record_inferred_read(out, state, i, *source)?;
            let bit_size = state.type_at(*source, i)?;
            state.set_type(*destination, bit_size)?;
        }

        B::Cast {
            destination,
            source,
            bit_size,
        } => {
            record_inferred_read(out, state, i, *source)?;
            state.set_type(*destination, *bit_size)?;
        }

        B::BinaryFieldOp {
            destination,
            lhs,
            rhs,
            ..
        } => {
            // Operand reads aren't `read_inferred` (the handler passes
            // `BitSize::Field` to `read_constant`), but they must still
            // reference defined slots — validate so undefined-register
            // bugs surface at translation time, not silently as a bad
            // `ram.load`.
            state.type_at(*lhs, i)?;
            state.type_at(*rhs, i)?;
            state.set_type(*destination, BitSize::Field)?;
        }

        B::BinaryIntOp {
            destination,
            bit_size,
            lhs,
            rhs,
            ..
        } => {
            state.type_at(*lhs, i)?;
            state.type_at(*rhs, i)?;
            state.set_type(*destination, BitSize::Integer(*bit_size))?;
        }

        B::Not {
            destination,
            source,
            bit_size,
        } => {
            state.type_at(*source, i)?;
            state.set_type(*destination, BitSize::Integer(*bit_size))?;
        }

        B::Load {
            destination,
            source_pointer,
        } => {
            record_inferred_read(out, state, i, *source_pointer)?;
            // `LoadHandler` writes the destination as `BitSize::Field` (the
            // raw felt yielded by `ram.load`).
            state.set_type(*destination, BitSize::Field)?;
        }

        B::Store {
            destination_pointer,
            source,
        } => {
            record_inferred_read(out, state, i, *destination_pointer)?;
            record_inferred_read(out, state, i, *source)?;
            // Mirrors `Memory::write_dynamic`: when the destination pointer
            // is a known constant, propagate the source bit size to the
            // pointed-to slot.
            let ptr_resolved = state.resolve(*destination_pointer)?;
            if let Some(slot) = state.known_constants.get(&ptr_resolved).copied() {
                let src_bit_size = state.type_at(*source, i)?;
                state
                    .types
                    .insert(MemoryAddress::Direct(slot as u32), src_bit_size);
            }
        }

        B::IndirectConst {
            destination_pointer,
            bit_size,
            ..
        } => {
            record_inferred_read(out, state, i, *destination_pointer)?;
            let ptr_resolved = state.resolve(*destination_pointer)?;
            if let Some(slot) = state.known_constants.get(&ptr_resolved).copied() {
                state
                    .types
                    .insert(MemoryAddress::Direct(slot as u32), *bit_size);
            }
        }

        B::CalldataCopy {
            destination_address,
            size_address,
            ..
        } => {
            let size_resolved = state.resolve(*size_address)?;
            let size = state
                .known_constants
                .get(&size_resolved)
                .copied()
                .ok_or_else(|| Error::UnsupportedBrillig {
                    reason: format!(
                        "CalldataCopy at bytecode index {i}: size register {} \
                         is not a known integer constant",
                        size_address.to_u32()
                    ),
                })?;
            let MemoryAddress::Direct(dst_base) = state.resolve(*destination_address)? else {
                unreachable!("resolve only returns Direct");
            };
            for j in 0..size {
                state
                    .types
                    .insert(MemoryAddress::Direct(dst_base + j as u32), BitSize::Field);
            }
        }

        B::Stop { .. } => {
            // `emit_return_data` reads via `read_constant`; the caller passes
            // the expected bit size, so no inferred-read entry is needed.
        }

        // Opcodes the translator doesn't yet support are intentionally a
        // no-op for the type pass — translation will surface the error
        // (with full opcode debug info) when it actually reaches them.
        // Critically, this keeps `Stop` short-circuiting working: a `Stop`
        // at index N must terminate translation cleanly even if an
        // unsupported opcode sits at index N+1.
        _ => {}
    }
    Ok(())
}
