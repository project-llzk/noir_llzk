//! Tests that the `@compute` function can directly emit `ram` dialect ops.
//!
//! `@compute` is created with `allow_witness = true` (set by
//! `dialect::r#struct::helpers::compute_fn`), which is the scope required by
//! the RAM dialect. This is the foundation for Brillig lowering: brillig
//! bytecode will lower into `@compute` and use these same helpers.

use acir::FieldElement;
use llzk::prelude::LlzkContext;

use super::{
    make_circuit, print_and_verify_module, translate_single_circuit, wrap_struct_in_module,
};
use crate::block_writer::BlockWriter;

/// `@compute` directly emits `ram.alloc` / `ram.store` / `ram.load` and the
/// resulting module verifies. Proves the BlockWriter helpers work inside the
/// existing `@compute` scope without any new `@allow_witness` plumbing.
#[test]
fn compute_directly_calls_ram() {
    let context = LlzkContext::new();
    // Empty circuit: no witnesses, no opcodes.
    let circuit = make_circuit(0, &[], &[], &[]);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();

    {
        let mut writer = BlockWriter::for_compute(&context, &struct_def, &[]).unwrap();

        let size = writer.insert_integer(16).unwrap();
        let mem = writer.insert_ram_alloc(size).unwrap();

        let addr = writer.insert_integer(0).unwrap();
        let val = writer.emit_constant(&FieldElement::from(42u32)).unwrap();

        writer.insert_ram_store(mem, addr, val);

        let felt_ty = writer.felt_type();
        let _loaded = writer.insert_ram_load(mem, addr, felt_ty).unwrap();
    }

    let module = wrap_struct_in_module(&context, struct_def);
    print_and_verify_module(&module, "compute_directly_calls_ram");
}
