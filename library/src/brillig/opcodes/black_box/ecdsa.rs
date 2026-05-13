//! `BlackBoxOp::EcdsaSecp256{k1,r1}` lowering.

use acir::brillig::{HeapArray, MemoryAddress};
use acir::{AcirField, FieldElement};

use crate::blackboxes::ecdsa::{ECDSA_HASH_BYTES, ECDSA_PK_BYTES, ECDSA_SIG_BYTES};
use crate::blackboxes::registry::BlackboxFunction;
use crate::brillig::translator::TranslationCtx;
use crate::error::Error;

use super::{collect_results, read_heap_array};
use crate::writer::Writer;

pub(super) fn emit_ecdsa(
    ctx: &mut TranslationCtx<'_, '_, '_>,
    func: BlackboxFunction,
    hashed_msg: &HeapArray,
    public_key_x: &HeapArray,
    public_key_y: &HeapArray,
    signature: &HeapArray,
    result: MemoryAddress,
) -> Result<(), Error> {
    validate_array("hashed_msg", hashed_msg, ECDSA_HASH_BYTES)?;
    validate_array("public_key_x", public_key_x, ECDSA_PK_BYTES)?;
    validate_array("public_key_y", public_key_y, ECDSA_PK_BYTES)?;
    validate_array("signature", signature, ECDSA_SIG_BYTES)?;

    let mut args = read_heap_array(ctx, public_key_x.pointer, ECDSA_PK_BYTES)?;
    args.extend(read_heap_array(ctx, public_key_y.pointer, ECDSA_PK_BYTES)?);
    args.extend(read_heap_array(ctx, signature.pointer, ECDSA_SIG_BYTES)?);
    args.extend(read_heap_array(ctx, hashed_msg.pointer, ECDSA_HASH_BYTES)?);
    // Brillig calls are unconditional; the helper still expects a predicate slot.
    args.push(ctx.writer.emit_constant(&FieldElement::one())?);

    let call = ctx.writer.call_blackbox_function(func, &args)?;
    let output = collect_results(call, 1)?;
    ctx.writer.insert_write(result, output[0])
}

fn validate_array(name: &str, array: &HeapArray, expected: usize) -> Result<(), Error> {
    if array.size.0 as usize == expected {
        return Ok(());
    }
    Err(Error::UnsupportedBrillig {
        reason: format!(
            "Brillig BlackBox ECDSA {name} must have size {expected} \
             (got {})",
            array.size.0
        ),
    })
}
