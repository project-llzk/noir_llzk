use acir::brillig::IntegerBitSize;
use llzk::prelude::{LlzkContext, OperationLike};

use super::super::print_and_verify_module;
use super::{brillig_stop, const_field, const_int, count_op, to_radix, translate_body};

const INPUT_ADDR: u32 = 1;
const RADIX_ADDR: u32 = 2;
const NUM_LIMBS_ADDR: u32 = 3;
const OUTPUT_BITS_ADDR: u32 = 4;
const OUTPUT_PTR_ADDR: u32 = 5;
const OUTPUT_BUFFER_BASE: u128 = 100;

fn prelude(
    input_felt: u128,
    radix: u128,
    num_limbs: u128,
    output_bits: u128,
) -> Vec<acir::brillig::Opcode<acir::FieldElement>> {
    vec![
        const_field(INPUT_ADDR, input_felt),
        const_int(RADIX_ADDR, IntegerBitSize::U32, radix),
        const_int(NUM_LIMBS_ADDR, IntegerBitSize::U32, num_limbs),
        const_int(OUTPUT_BITS_ADDR, IntegerBitSize::U1, output_bits),
        const_field(OUTPUT_PTR_ADDR, OUTPUT_BUFFER_BASE),
    ]
}

#[test]
fn to_radix_base10_two_limbs_emits_per_limb_ops() {
    let context = LlzkContext::new();
    let mut ops = prelude(13, 10, 2, 0);
    ops.push(to_radix(
        INPUT_ADDR,
        RADIX_ADDR,
        OUTPUT_PTR_ADDR,
        NUM_LIMBS_ADDR,
        OUTPUT_BITS_ADDR,
    ));
    ops.push(brillig_stop());

    let module = translate_body(&context, ops).expect("translation should succeed");
    print_and_verify_module(&module, "to_radix base10");
    assert!(module.as_operation().verify());
    let limb_stores = 2;
    let prelude_stores = 5;

    assert_eq!(
        count_op(&module, 0, "felt.uintdiv"),
        2,
        "one uintdiv per limb"
    );
    assert_eq!(count_op(&module, 0, "felt.umod"), 2, "one umod per limb");
    assert_eq!(
        count_op(&module, 0, "ram.store"),
        limb_stores + prelude_stores,
        "one ram.store per output limb, plus each prelude Const's store"
    );
}

#[test]
fn to_radix_base2_output_bits_validates() {
    let context = LlzkContext::new();
    let mut ops = prelude(5, 2, 3, 1);
    ops.push(to_radix(
        INPUT_ADDR,
        RADIX_ADDR,
        OUTPUT_PTR_ADDR,
        NUM_LIMBS_ADDR,
        OUTPUT_BITS_ADDR,
    ));
    ops.push(brillig_stop());

    let module = translate_body(&context, ops).expect("translation should succeed");
    assert!(module.as_operation().verify());
    assert_eq!(count_op(&module, 0, "felt.uintdiv"), 3);
}

#[test]
fn to_radix_rejects_out_of_range_radix() {
    let context = LlzkContext::new();
    let mut ops = prelude(0, 257, 1, 0);
    ops.push(to_radix(
        INPUT_ADDR,
        RADIX_ADDR,
        OUTPUT_PTR_ADDR,
        NUM_LIMBS_ADDR,
        OUTPUT_BITS_ADDR,
    ));
    ops.push(brillig_stop());

    let err = translate_body(&context, ops).expect_err("should reject radix=257");
    assert!(
        matches!(err, crate::Error::UnsupportedBrillig { .. }),
        "expected UnsupportedBrillig, got {err:?}"
    );
}

#[test]
fn to_radix_rejects_output_bits_with_non_binary_radix() {
    let context = LlzkContext::new();
    let mut ops = prelude(0, 10, 1, 1);
    ops.push(to_radix(
        INPUT_ADDR,
        RADIX_ADDR,
        OUTPUT_PTR_ADDR,
        NUM_LIMBS_ADDR,
        OUTPUT_BITS_ADDR,
    ));
    ops.push(brillig_stop());

    let err = translate_body(&context, ops).expect_err("should reject output_bits + radix=10");
    assert!(matches!(err, crate::Error::UnsupportedBrillig { .. }));
}
