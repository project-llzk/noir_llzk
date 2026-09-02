use acir::brillig::HeapArray;
use llzk::prelude::Value;

use crate::blackboxes::{hash::poseidon2::STATE_WIDTH, registry::BlackboxFunction};
use crate::error::Error;

use super::{read_heap_array, write_heap_array};
use crate::brillig::translator::TranslationCtx;
use crate::writer::Writer;
pub(super) fn emit_poseidon2(
    ctx: &mut TranslationCtx<'_, '_, '_>,
    message: &HeapArray,
    output: &HeapArray,
    opcode_index: usize,
) -> Result<(), Error> {
    if message.size.0 as usize != STATE_WIDTH || output.size.0 as usize != STATE_WIDTH {
        return Err(Error::UnsupportedBrillig {
            reason: format!(
                "BlackBox at bytecode index {opcode_index}: Poseidon2Permutation requires \
                 message and output of size {STATE_WIDTH} (got {} / {})",
                message.size.0, output.size.0,
            ),
        });
    }

    let inputs = read_heap_array(ctx, message.pointer, STATE_WIDTH)?;

    let call = ctx
        .writer
        .call_blackbox_function(BlackboxFunction::Poseidon2Permutation, &inputs)?;
    let results: Vec<Value<'_, '_>> = (0..STATE_WIDTH)
        .map(|i| call.result(i).map(Into::into).map_err(Error::from))
        .collect::<Result<_, _>>()?;

    write_heap_array(ctx, output.pointer, STATE_WIDTH, &results)
}
