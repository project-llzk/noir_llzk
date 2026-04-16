//! Tests that the `@compute` function can directly emit `ram` dialect ops.
//!
//! `@compute` is created with `allow_witness = true` (set by
//! `dialect::r#struct::helpers::compute_fn`), which is the scope required by
//! the RAM dialect. This is the foundation for Brillig lowering: brillig
//! bytecode will lower into `@compute` and use these same helpers.
//!
//! The dialect models a single flat memory region — there is no `ram.alloc`
//! and no memory-handle operand on `ram.load` / `ram.store`.

use acir::FieldElement;
use llzk::prelude::{LlzkContext, OperationLike};

use super::{
    make_circuit, print_and_verify_module, translate_single_circuit, wrap_struct_in_module,
};
use crate::block_writer::BlockWriter;

/// `@compute` directly emits `ram.store` / `ram.load` and the resulting
/// module verifies.
#[test]
fn compute_directly_calls_ram() {
    let context = LlzkContext::new();
    let circuit = make_circuit(0, &[], &[], &[]);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();

    {
        let mut writer = BlockWriter::for_compute(&context, &struct_def, &[]).unwrap();

        let addr = writer.insert_integer(0).unwrap();
        let val = writer.emit_constant(&FieldElement::from(42u32)).unwrap();

        writer.insert_ram_store(addr, val);

        let felt_ty = writer.felt_type();
        let _loaded = writer.insert_ram_load(addr, felt_ty).unwrap();
    }

    let module = wrap_struct_in_module(&context, struct_def);
    print_and_verify_module(&module, "compute_directly_calls_ram");
}

/// `@constrain` is not `allow_witness = true`, so emitting RAM ops there
/// produces an invalid module. Confirms the scope restriction is actually
/// enforced by verification.
#[test]
fn constrain_calls_ram_fails_verification() {
    let context = LlzkContext::new();
    let circuit = make_circuit(0, &[], &[], &[]);
    let struct_def = translate_single_circuit(&context, circuit).unwrap();

    {
        let mut writer = BlockWriter::for_constrain(&context, &struct_def, &[]).unwrap();

        let addr = writer.insert_integer(0).unwrap();
        let val = writer.emit_constant(&FieldElement::from(42u32)).unwrap();

        writer.insert_ram_store(addr, val);

        let felt_ty = writer.felt_type();
        let _loaded = writer.insert_ram_load(addr, felt_ty).unwrap();
    }

    let module = wrap_struct_in_module(&context, struct_def);
    let ir = format!("{}", module.as_operation());
    println!("constrain_calls_ram_fails_verification:\n{ir}");
    assert!(
        !module.as_operation().verify(),
        "module should fail verification — ram ops require allow_witness scope"
    );
}
