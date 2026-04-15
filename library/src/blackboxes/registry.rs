use acir::{
    FieldElement,
    circuit::{Opcode, Program, opcodes::BlackBoxFuncCall},
};
use llzk::prelude::{FeltType, FuncDefOp, LlzkContext, Type};

use crate::{FIELD_NAME, error::Error};

use super::grumpkin::embedded_curve_add::{
    EMBEDDED_CURVE_ADD_HELPER_NAME, emit_embedded_curve_add_helper,
};
use super::grumpkin::multi_scalar_mul::{
    emit_multi_scalar_mul_helper, multi_scalar_mul_helper_name, used_arities,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlackboxFunction {
    EmbeddedCurveAdd,
    MultiScalarMul { num_points: usize },
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
        }
    }

    pub(crate) fn emit<'c>(self, context: &'c LlzkContext) -> Result<FuncDefOp<'c>, Error> {
        match self {
            Self::EmbeddedCurveAdd => emit_embedded_curve_add_helper(context),
            Self::MultiScalarMul { num_points } => {
                emit_multi_scalar_mul_helper(context, num_points)
            }
        }
    }

    pub(crate) fn result_types<'c>(self, context: &'c LlzkContext) -> Vec<Type<'c>> {
        point_result_types(context)
    }
}

fn point_result_types<'c>(context: &'c LlzkContext) -> Vec<Type<'c>> {
    let felt: Type<'c> = FeltType::with_field(context, FIELD_NAME).into();
    vec![felt, felt, felt]
}

fn used_fixed_helpers(program: &Program<FieldElement>) -> Vec<BlackboxFunction> {
    let mut helpers = Vec::new();
    if uses_embedded_curve_add(program) {
        helpers.push(BlackboxFunction::EmbeddedCurveAdd);
    }
    helpers
}

fn used_shaped_helpers(program: &Program<FieldElement>) -> Vec<BlackboxFunction> {
    used_arities(program)
        .into_iter()
        .map(|num_points| BlackboxFunction::MultiScalarMul { num_points })
        .collect()
}

fn uses_embedded_curve_add(program: &Program<FieldElement>) -> bool {
    program.functions.iter().any(|circuit| {
        circuit.opcodes.iter().any(|opcode| {
            matches!(
                opcode,
                Opcode::BlackBoxFuncCall(BlackBoxFuncCall::EmbeddedCurveAdd { .. })
            )
        })
    })
}
