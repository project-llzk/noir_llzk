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
    blake2s::{
        BLAKE2S_DIGEST_BYTES, blake2s_helper_name, blake2s_num_blocks_for_len, emit_blake2s_helper,
    },
    blake3::{
        BLAKE3_DIGEST_BYTES, blake3_helper_name, blake3_num_blocks_for_len, emit_blake3_helper,
    },
    poseidon2::{POSEIDON2_HELPER_NAME, emit_poseidon2_helper},
    sha256::{SHA256_HELPER_NAME, SHA256_STATE_WORDS, emit_sha256_helper},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlackboxFunction {
    EmbeddedCurveAdd,
    MultiScalarMul { num_points: usize },
    Poseidon2Permutation,
    Blake2s { num_blocks: usize },
    Blake3 { num_blocks: usize },
    Sha256Compression,
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
            Self::Blake2s { num_blocks } => blake2s_helper_name(num_blocks),
            Self::Blake3 { num_blocks } => blake3_helper_name(num_blocks),
            Self::Sha256Compression => SHA256_HELPER_NAME.to_string(),
        }
    }

    pub(crate) fn emit<'c>(self, context: &'c LlzkContext) -> Result<FuncDefOp<'c>, Error> {
        match self {
            Self::EmbeddedCurveAdd => emit_embedded_curve_add_helper(context),
            Self::MultiScalarMul { num_points } => {
                emit_multi_scalar_mul_helper(context, num_points)
            }
            Self::Poseidon2Permutation => emit_poseidon2_helper(context),
            Self::Blake2s { num_blocks } => emit_blake2s_helper(context, num_blocks),
            Self::Blake3 { num_blocks } => emit_blake3_helper(context, num_blocks),
            Self::Sha256Compression => emit_sha256_helper(context),
        }
    }

    pub(crate) fn result_types<'c>(self, context: &'c LlzkContext) -> Vec<Type<'c>> {
        let felt = felt_type(context);
        match self {
            Self::EmbeddedCurveAdd | Self::MultiScalarMul { .. } => vec![felt; 3],
            Self::Poseidon2Permutation => vec![felt; 4],
            Self::Blake2s { .. } => vec![felt; BLAKE2S_DIGEST_BYTES],
            Self::Blake3 { .. } => vec![felt; BLAKE3_DIGEST_BYTES],
            Self::Sha256Compression => vec![felt; SHA256_STATE_WORDS],
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
    if uses_blackbox(program, |op| {
        matches!(
            op,
            Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Sha256Compression { .. })
        )
    }) {
        helpers.push(BlackboxFunction::Sha256Compression);
    }
    helpers
}

fn used_shaped_helpers(program: &Program<FieldElement>) -> Vec<BlackboxFunction> {
    let mut helpers: Vec<BlackboxFunction> = used_arities(program)
        .into_iter()
        .map(|num_points| BlackboxFunction::MultiScalarMul { num_points })
        .collect();

    let mut blake2s_input_lengths = BTreeSet::new();
    let mut blake3_input_lengths = BTreeSet::new();
    for circuit in &program.functions {
        for opcode in &circuit.opcodes {
            match opcode {
                Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Blake2s { inputs, .. }) => {
                    blake2s_input_lengths.insert(blake2s_num_blocks_for_len(inputs.len()));
                }
                Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Blake3 { inputs, .. }) => {
                    blake3_input_lengths.insert(blake3_num_blocks_for_len(inputs.len()));
                }
                _ => {}
            }
        }
    }
    helpers.extend(
        blake2s_input_lengths
            .into_iter()
            .map(|num_blocks| BlackboxFunction::Blake2s { num_blocks }),
    );
    helpers.extend(
        blake3_input_lengths
            .into_iter()
            .map(|num_blocks| BlackboxFunction::Blake3 { num_blocks }),
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
