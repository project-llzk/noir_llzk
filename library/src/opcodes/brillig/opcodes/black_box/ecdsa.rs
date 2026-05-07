//! `BlackBoxOp::EcdsaSecp256{k1,r1}` lowering.

use acir::brillig::{HeapArray, MemoryAddress};
use acir::{AcirField, FieldElement};

use crate::blackboxes::registry::BlackboxFunction;
use crate::error::Error;
use crate::opcodes::brillig::{memory::Memory, translator::TranslationCtx};

use super::{collect_results, read_heap_array};

const ECDSA_PUBLIC_KEY_BYTES: usize = 32;
const ECDSA_SIGNATURE_BYTES: usize = 64;
const ECDSA_HASH_BYTES: usize = 32;

pub(super) fn emit_ecdsa<M: Memory>(
    ctx: &mut TranslationCtx<'_, '_, '_, M>,
    func: BlackboxFunction,
    hashed_msg: &HeapArray,
    public_key_x: &HeapArray,
    public_key_y: &HeapArray,
    signature: &HeapArray,
    result: MemoryAddress,
    opcode_index: usize,
) -> Result<(), Error> {
    validate_array("hashed_msg", hashed_msg, ECDSA_HASH_BYTES, opcode_index)?;
    validate_array(
        "public_key_x",
        public_key_x,
        ECDSA_PUBLIC_KEY_BYTES,
        opcode_index,
    )?;
    validate_array(
        "public_key_y",
        public_key_y,
        ECDSA_PUBLIC_KEY_BYTES,
        opcode_index,
    )?;
    validate_array("signature", signature, ECDSA_SIGNATURE_BYTES, opcode_index)?;

    let mut args = read_heap_array(ctx, public_key_x.pointer, ECDSA_PUBLIC_KEY_BYTES)?;
    args.extend(read_heap_array(
        ctx,
        public_key_y.pointer,
        ECDSA_PUBLIC_KEY_BYTES,
    )?);
    args.extend(read_heap_array(
        ctx,
        signature.pointer,
        ECDSA_SIGNATURE_BYTES,
    )?);
    args.extend(read_heap_array(ctx, hashed_msg.pointer, ECDSA_HASH_BYTES)?);
    args.push(ctx.writer.emit_constant(&FieldElement::one())?);

    let call = ctx.writer.call_blackbox_function(func, &args)?;
    let output = collect_results(call, 1)?;
    ctx.memory.write(ctx.writer, result, output[0])
}

fn validate_array(
    name: &str,
    array: &HeapArray,
    expected: usize,
    opcode_index: usize,
) -> Result<(), Error> {
    if array.size.0 as usize == expected {
        return Ok(());
    }
    Err(Error::UnsupportedBrillig {
        reason: format!(
            "BlackBox at bytecode index {opcode_index}: ECDSA {name} must have size {expected} \
             (got {})",
            array.size.0
        ),
    })
}
