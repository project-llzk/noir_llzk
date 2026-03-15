use std::collections::HashSet;

use acir::circuit::Opcode;
use acir::native_types::Expression;
use acir::{AcirField, FieldElement};
use llzk::dialect::felt::FeltConstAttribute;
use llzk::prelude::LlzkContext;
use num_bigint::BigUint;

use crate::FIELD_NAME;

/// Returns a human-readable name for an opcode variant.
pub(crate) fn opcode_name(opcode: &Opcode<FieldElement>) -> String {
    match opcode {
        Opcode::AssertZero(_) => "AssertZero".to_string(),
        Opcode::BlackBoxFuncCall(_) => "BlackBoxFuncCall".to_string(),
        Opcode::MemoryOp { .. } => "MemoryOp".to_string(),
        Opcode::MemoryInit { .. } => "MemoryInit".to_string(),
        Opcode::BrilligCall { .. } => "BrilligCall".to_string(),
        Opcode::Call { .. } => "Call".to_string(),
    }
}

/// Converts an ACIR `FieldElement` to an LLZK `FeltConstAttribute`.
pub(crate) fn field_to_felt_const<'c>(
    context: &'c LlzkContext,
    fe: &FieldElement,
) -> FeltConstAttribute<'c> {
    let bytes = fe.to_le_bytes();
    let biguint = BigUint::from_bytes_le(&bytes);
    FeltConstAttribute::from_biguint(context, &biguint, Some(FIELD_NAME))
}

/// Collects all unique witness indices referenced in an expression.
pub(crate) fn collect_witnesses(expr: &Expression<FieldElement>) -> HashSet<u32> {
    let mut witnesses = HashSet::new();
    for (_, w_i, w_j) in &expr.mul_terms {
        witnesses.insert(w_i.0);
        witnesses.insert(w_j.0);
    }
    for (_, w_k) in &expr.linear_combinations {
        witnesses.insert(w_k.0);
    }
    witnesses
}
