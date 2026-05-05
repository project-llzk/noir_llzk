//! End-to-end tests: ACIR → LLZK → [`llzk_interpreter::Interpreter`].

use std::collections::BTreeMap;

use acir::circuit::{Circuit, Program};
use acir::{AcirField, FieldElement};
use llzk::prelude::LlzkContext;
pub(super) use llzk_interpreter::Interpreter;
use llzk_interpreter::{Felt, StructInstance, Value};
use num_bigint::BigUint;

use super::make_program;
use crate::program::translate_program;

mod blackboxes;
mod brillig;

// ── Felt construction helpers ───────────────────────────────────────────

pub(super) fn felt_from_decimal(s: &str) -> Value {
    Value::Felt(Felt::from_decimal(s).unwrap_or_else(|e| panic!("bad decimal {s}: {e}")))
}

pub(super) fn felt_from_hex(s: &str) -> Value {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    let big =
        BigUint::parse_bytes(hex.as_bytes(), 16).unwrap_or_else(|| panic!("invalid hex: {s}"));
    Value::Felt(Felt::new(big))
}

pub(super) fn felt_from_field_element(fe: FieldElement) -> Value {
    let bytes = fe.to_be_bytes();
    Value::Felt(Felt::new(BigUint::from_bytes_be(&bytes)))
}

pub(super) fn felt_u64(v: u64) -> Value {
    Value::Felt(Felt::from_u64(v))
}

// ── Pipeline helpers ────────────────────────────────────────────────────

/// Runs the full pipeline: translate, compute, constrain. Returns the computed struct.
pub(super) fn run_e2e(circuit: Circuit<FieldElement>, inputs: &[Value]) -> StructInstance {
    run_e2e_with_nondet(circuit, inputs, &[])
}

/// Like [`run_e2e`], but supplies pre-computed values for `llzk.nondet` ops.
/// The same nondet sequence is replayed for both compute and constrain phases.
pub(super) fn run_e2e_with_nondet(
    circuit: Circuit<FieldElement>,
    inputs: &[Value],
    nondet: &[Felt],
) -> StructInstance {
    let program = make_program(vec![circuit]);
    run_e2e_program(&program, inputs, nondet)
}

pub(super) fn run_e2e_program(
    program: &Program<FieldElement>,
    inputs: &[Value],
    nondet: &[Felt],
) -> StructInstance {
    let context = LlzkContext::new();
    let module = translate_program(&context, program).expect("translation should succeed");
    println!("{:?}", module.as_operation());
    let mut interpreter = Interpreter::new(&module);

    interpreter.set_nondet_values(nondet.iter().cloned());
    let computed = interpreter
        .run_compute("Circuit0", inputs)
        .expect("compute should succeed");

    interpreter.set_nondet_values(nondet.iter().cloned());
    interpreter
        .run_constrain("Circuit0", computed.clone(), inputs)
        .expect("constrain should succeed");
    computed
}

pub(super) fn assert_witness_eq(
    members: &BTreeMap<String, Value>,
    key: &str,
    expected_decimal: &str,
) {
    let Some(Value::Felt(got)) = members.get(key) else {
        panic!("missing or non-felt member {key}: {members:?}");
    };
    let expected = Felt::from_decimal(expected_decimal)
        .unwrap_or_else(|e| panic!("bad decimal {expected_decimal}: {e}"));
    assert_eq!(got, &expected, "witness {key}");
}
