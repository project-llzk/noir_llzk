use std::collections::BTreeSet;

use acir::{
    FieldElement,
    circuit::{Opcode, Program, opcodes::BlackBoxFuncCall},
};
use llzk::prelude::{FuncDefOp, LlzkContext, Type};

use crate::error::Error;

use super::common::felt_type;
use super::grumpkin::embedded_curve_add::{
    EMBEDDED_CURVE_ADD_HELPER_NAME, emit_embedded_curve_add_helper,
};
use super::grumpkin::multi_scalar_mul::{
    emit_multi_scalar_mul_helper, multi_scalar_mul_helper_name, used_arities,
};
use super::hash::{
    blake2s::{BLAKE2S_DIGEST_BYTES, blake2s_helper_name, emit_blake2s_helper},
    poseidon2::{POSEIDON2_HELPER_NAME, emit_poseidon2_helper},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlackboxFunction {
    EmbeddedCurveAdd,
    MultiScalarMul { num_points: usize },
    Poseidon2Permutation,
    Blake2s { num_inputs: usize },
}

impl BlackboxFunction {
    pub(crate) fn used_in_program(program: &Program<FieldElement>) -> Vec<Self> {
        let mut helpers = used_fixed_helpers(program);
        helpers.extend(used_shaped_helpers(program));
        helpers
    }

    pub(crate) fn symbol_name(self) -> String {
        match self {
            Self::EmbeddedCurveAdd => EMBEDDED_CURVE_ADD_HELPER_NAME.to_string(),
            Self::MultiScalarMul { num_points } => multi_scalar_mul_helper_name(num_points),
            Self::Poseidon2Permutation => POSEIDON2_HELPER_NAME.to_string(),
            Self::Blake2s { num_inputs } => blake2s_helper_name(num_inputs),
        }
    }

    pub(crate) fn emit<'c>(self, context: &'c LlzkContext) -> Result<FuncDefOp<'c>, Error> {
        match self {
            Self::EmbeddedCurveAdd => emit_embedded_curve_add_helper(context),
            Self::MultiScalarMul { num_points } => {
                emit_multi_scalar_mul_helper(context, num_points)
            }
            Self::Poseidon2Permutation => emit_poseidon2_helper(context),
            Self::Blake2s { num_inputs } => emit_blake2s_helper(context, num_inputs),
        }
    }

    pub(crate) fn result_types<'c>(self, context: &'c LlzkContext) -> Vec<Type<'c>> {
        let felt = felt_type(context);
        match self {
            Self::EmbeddedCurveAdd | Self::MultiScalarMul { .. } => vec![felt; 3],
            Self::Poseidon2Permutation => vec![felt; 4],
            Self::Blake2s { .. } => vec![felt; BLAKE2S_DIGEST_BYTES],
        }
    }
}

fn used_fixed_helpers(program: &Program<FieldElement>) -> Vec<BlackboxFunction> {
    let mut helpers = Vec::new();
    if uses_blackbox(program, |op| {
        matches!(
            op,
            Opcode::BlackBoxFuncCall(BlackBoxFuncCall::EmbeddedCurveAdd { .. })
        )
    }) {
        helpers.push(BlackboxFunction::EmbeddedCurveAdd);
    }
    if uses_blackbox(program, |op| {
        matches!(
            op,
            Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Poseidon2Permutation { .. })
        )
    }) {
        helpers.push(BlackboxFunction::Poseidon2Permutation);
    }
    helpers
}

fn used_shaped_helpers(program: &Program<FieldElement>) -> Vec<BlackboxFunction> {
    let mut helpers: Vec<BlackboxFunction> = used_arities(program)
        .into_iter()
        .map(|num_points| BlackboxFunction::MultiScalarMul { num_points })
        .collect();

    let mut blake2s_input_lengths = BTreeSet::new();
    for circuit in &program.functions {
        for opcode in &circuit.opcodes {
            if let Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Blake2s { inputs, .. }) = opcode {
                blake2s_input_lengths.insert(inputs.len());
            }
        }
    }
    helpers.extend(
        blake2s_input_lengths
            .into_iter()
            .map(|num_inputs| BlackboxFunction::Blake2s { num_inputs }),
    );

    helpers
}

fn uses_blackbox(
    program: &Program<FieldElement>,
    predicate: impl Fn(&Opcode<FieldElement>) -> bool,
) -> bool {
    program
        .functions
        .iter()
        .any(|circuit| circuit.opcodes.iter().any(&predicate))
}
