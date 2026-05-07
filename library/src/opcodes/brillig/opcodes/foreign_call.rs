//! Handler for Brillig's `ForeignCall` (oracle escape hatch).
//!
//! Inputs and `function` name carry no soundness role and emit nothing.
//! Each `Simple` destination slot becomes one `llzk.nondet` + raw
//! `ram.store`. Heap destinations walk Brillig's semi-flattened layout
//! (`value_types` repeated `semantic_size` times); nested `Array`
//! slots hold a pointer and recurse via `ram.load` + `cast.toindex`,
//! nested `Vector`s are rejected.

use acir::brillig::{HeapArray, HeapValueType, HeapVector, MemoryAddress, ValueOrArray};
use llzk::prelude::{Block, BlockLike, Value};

use crate::error::Error;

use super::super::memory::Memory;
use super::super::translator::TranslationCtx;
use super::{BrilligHandler, read_pointer_as_index, slot_at_offset};

pub(super) struct ForeignCallHandler<'a> {
    pub destinations: &'a [ValueOrArray],
    pub destination_value_types: &'a [HeapValueType],
}

impl<'a, M: Memory> BrilligHandler<'a, M> for ForeignCallHandler<'a> {
    fn execute(
        &self,
        ctx: &mut TranslationCtx<'_, '_, '_, M>,
        _opcode_index: usize,
    ) -> Result<(), Error> {
        for (dest, ty) in self
            .destinations
            .iter()
            .zip(self.destination_value_types.iter())
        {
            emit_destination(ctx, dest, ty)?;
        }
        Ok(())
    }
}

fn emit_destination<M: Memory>(
    ctx: &mut TranslationCtx<'_, '_, '_, M>,
    dest: &ValueOrArray,
    ty: &HeapValueType,
) -> Result<(), Error> {
    match (dest, ty) {
        (ValueOrArray::MemoryAddress(addr), HeapValueType::Simple(_)) => {
            let value = emit_leaf_value(ctx)?;
            ctx.memory.write(ctx.writer, *addr, value)?;
        }
        (
            ValueOrArray::HeapArray(HeapArray { pointer, .. }),
            HeapValueType::Array {
                value_types,
                size: semantic_size,
            },
        ) => {
            let base = read_pointer_as_index(ctx, *pointer)?;
            emit_array(ctx, base, semantic_size.0 as usize, value_types)?;
        }
        (
            ValueOrArray::HeapVector(HeapVector {
                pointer,
                size: size_addr,
            }),
            HeapValueType::Vector { value_types },
        ) => {
            emit_heap_vector(ctx, *pointer, *size_addr, value_types)?;
        }
        _ => {
            return Err(Error::UnsupportedBrillig {
                reason: "ForeignCall destination shape and \
                     value-type do not match any supported pairing"
                    .to_string(),
            });
        }
    }
    Ok(())
}

/// Lowers a `HeapVector` destination. Branches on whether the size
/// register holds a tracked compile-time integer:
/// * Yes → unroll into the same per-element walk as `HeapArray`,
///   reusing the static-vs-dynamic base dispatch. Any `value_types`
///   schema `emit_array` accepts — including nested `Array` — works.
/// * No  → emit an `scf.while` whose body walks `value_types` once
///   per iteration via [`emit_runtime_size_loop`].
fn emit_heap_vector<M: Memory>(
    ctx: &mut TranslationCtx<'_, '_, '_, M>,
    pointer: MemoryAddress,
    size_addr: MemoryAddress,
    value_types: &[HeapValueType],
) -> Result<(), Error> {
    let elem_types = value_types.len();
    let base = read_pointer_as_index(ctx, pointer)?;

    if elem_types == 0 {
        // No element schema → no slots. Defensive: the loop would
        // otherwise have stride 0 and never terminate.
        return Ok(());
    }
    let size_val = ctx.memory.read(ctx.writer, size_addr)?;
    let size_idx = ctx.writer.cast_to_index(size_val)?;
    emit_runtime_size_loop(ctx, base, size_idx, value_types)
}

/// Builds an `scf.while` that walks `value_types` once per iteration.
///
/// The loop counter `i` is the slot offset, advancing by `K =
/// value_types.len()` each iteration so position `j` of the schema
/// lives at slot `base + i + j`. `Simple` positions emit one nondet
/// felt + raw `ram.store`; nested `Array` positions read the inner
/// pointer and recurse through [`emit_array_dynamic`]; nested
/// `Vector` is rejected upfront.
fn emit_runtime_size_loop<'c, 'b, M: Memory>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
    base_idx: Value<'c, 'b>,
    size_idx: Value<'c, 'b>,
    value_types: &[HeapValueType],
) -> Result<(), Error> {
    if value_types
        .iter()
        .any(|t| matches!(t, HeapValueType::Vector { .. }))
    {
        return Err(nested_vector_error());
    }

    let stride = value_types.len();
    let index_ty = ctx.writer.index_type();
    let location = ctx.writer.location();
    let zero_idx = ctx.writer.insert_integer(0)?;
    let stride_idx = ctx.writer.insert_integer(stride)?;

    // before-block: arg `i: index`. Yields `scf.condition(i < size, [i])`.
    let before_block = Block::new(&[(index_ty, location)]);
    let i_before: Value<'c, '_> = before_block.argument(0)?.into();
    let saved = ctx.writer.enter_block(&before_block);
    let cond = ctx.writer.insert_cmpi_slt(i_before, size_idx)?;
    ctx.writer.insert_scf_condition(cond, &[i_before]);
    ctx.writer.leave_block(saved);

    // after-block: arg `i: index`. Walks `value_types` once at offsets
    // `base + i + j`, then yields `i + stride`.
    let after_block = Block::new(&[(index_ty, location)]);
    let i_after: Value<'c, '_> = after_block.argument(0)?.into();
    let saved = ctx.writer.enter_block(&after_block);
    let elem_base_idx = ctx.writer.insert_index_add(base_idx, i_after)?;
    for (j, typ) in value_types.iter().enumerate() {
        let slot_idx = slot_at_offset(ctx, elem_base_idx, j)?;
        match typ {
            HeapValueType::Simple(_) => {
                let value = emit_leaf_value(ctx)?;
                ctx.writer.insert_ram_store(slot_idx, value);
            }
            HeapValueType::Array {
                value_types: inner_vts,
                size: inner_size,
            } => {
                let ptr_felt = ctx.writer.insert_ram_load(slot_idx)?;
                let inner_base_idx = ctx.writer.cast_to_index(ptr_felt)?;
                emit_array(ctx, inner_base_idx, inner_size.0 as usize, inner_vts)?;
            }
            HeapValueType::Vector { .. } => unreachable!("rejected above"),
        }
    }
    let next_i = ctx.writer.insert_index_add(i_after, stride_idx)?;
    ctx.writer.insert_scf_yield(&[next_i]);
    ctx.writer.leave_block(saved);

    ctx.writer
        .insert_scf_while(&[zero_idx], &[index_ty], before_block, after_block)
}

fn emit_array<'c, 'b, M: Memory>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
    base: Value<'c, 'b>,
    semantic_size: usize,
    value_types: &[HeapValueType],
) -> Result<(), Error> {
    let mut offset = 0usize;
    for _ in 0..semantic_size {
        for typ in value_types {
            let slot_idx = slot_at_offset(ctx, base, offset)?;
            match typ {
                HeapValueType::Simple(_) => {
                    let value = emit_leaf_value(ctx)?;
                    ctx.writer.insert_ram_store(slot_idx, value);
                }
                HeapValueType::Array {
                    value_types: inner_vts,
                    size: inner_size,
                } => {
                    let ptr_felt = ctx.writer.insert_ram_load(slot_idx)?;
                    let inner_base_idx = ctx.writer.cast_to_index(ptr_felt)?;
                    emit_array(ctx, inner_base_idx, inner_size.0 as usize, inner_vts)?;
                }
                HeapValueType::Vector { .. } => {
                    return Err(nested_vector_error());
                }
            }
            offset += 1;
        }
    }
    Ok(())
}

/// Emits `llzk.nondet`, returning a raw prover-supplied felt.
fn emit_leaf_value<'c, 'b, M: Memory>(
    ctx: &mut TranslationCtx<'c, 'b, '_, M>,
) -> Result<Value<'c, 'b>, Error> {
    let felt_ty = ctx.writer.felt_type();
    ctx.writer.insert_nondet(felt_ty)
}

fn nested_vector_error() -> Error {
    Error::UnsupportedBrillig {
        reason: "ForeignCall nested HeapVector inside an \
             Array destination is unsupported"
            .to_string(),
    }
}
