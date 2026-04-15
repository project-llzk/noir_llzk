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
use super::hash::poseidon2::{POSEIDON2_HELPER_NAME, emit_poseidon2_helper};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlackboxFunction {
    EmbeddedCurveAdd,
    MultiScalarMul { num_points: usize },
    Poseidon2Permutation,
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
        }
    }

    pub(crate) fn emit<'c>(self, context: &'c LlzkContext) -> Result<FuncDefOp<'c>, Error> {
        match self {
            Self::EmbeddedCurveAdd => emit_embedded_curve_add_helper(context),
            Self::MultiScalarMul { num_points } => {
                emit_multi_scalar_mul_helper(context, num_points)
            }
            Self::Poseidon2Permutation => emit_poseidon2_helper(context),
        }
    }

    pub(crate) fn result_types<'c>(self, context: &'c LlzkContext) -> Vec<Type<'c>> {
        let felt = felt_type(context);
        match self {
            Self::EmbeddedCurveAdd | Self::MultiScalarMul { .. } => vec![felt, felt, felt],
            Self::Poseidon2Permutation => vec![felt, felt, felt, felt],
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
    used_arities(program)
        .into_iter()
        .map(|num_points| BlackboxFunction::MultiScalarMul { num_points })
        .collect()
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
