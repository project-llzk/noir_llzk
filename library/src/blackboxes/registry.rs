use acir::{
    FieldElement,
    circuit::{Opcode, Program, opcodes::BlackBoxFuncCall},
};
use llzk::prelude::{FeltType, FuncDefOp, LlzkContext, Type};

use crate::{FIELD_NAME, error::Error};

use super::grumpkin::embedded_curve_add::{
    EMBEDDED_CURVE_ADD_HELPER_NAME, emit_embedded_curve_add_helper,
};

type EmitHelperFn = for<'c> fn(&'c LlzkContext) -> Result<FuncDefOp<'c>, Error>;
type ResultTypesFn = for<'c> fn(&'c LlzkContext) -> Vec<Type<'c>>;
type MatchesOpcodeFn = fn(&Opcode<FieldElement>) -> bool;

struct BlackboxDescriptor {
    symbol_name: &'static str,
    emit: EmitHelperFn,
    result_types: ResultTypesFn,
    matches_opcode: MatchesOpcodeFn,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlackboxFunction {
    EmbeddedCurveAdd,
}

impl BlackboxFunction {
    pub(crate) const ALL: [Self; 1] = [Self::EmbeddedCurveAdd];

    pub(crate) fn symbol_name(self) -> &'static str {
        self.descriptor().symbol_name
    }

    pub(crate) fn is_used(self, program: &Program<FieldElement>) -> bool {
        program.functions.iter().any(|circuit| {
            circuit
                .opcodes
                .iter()
                .any(|opcode| self.matches_opcode(opcode))
        })
    }

    pub(crate) fn emit<'c>(self, context: &'c LlzkContext) -> Result<FuncDefOp<'c>, Error> {
        (self.descriptor().emit)(context)
    }

    pub(crate) fn result_types<'c>(self, context: &'c LlzkContext) -> Vec<Type<'c>> {
        (self.descriptor().result_types)(context)
    }

    fn matches_opcode(self, opcode: &Opcode<FieldElement>) -> bool {
        (self.descriptor().matches_opcode)(opcode)
    }

    fn descriptor(self) -> BlackboxDescriptor {
        match self {
            Self::EmbeddedCurveAdd => BlackboxDescriptor {
                symbol_name: EMBEDDED_CURVE_ADD_HELPER_NAME,
                emit: emit_embedded_curve_add_helper,
                result_types: embedded_curve_add_result_types,
                matches_opcode: is_embedded_curve_add,
            },
        }
    }
}

fn embedded_curve_add_result_types<'c>(context: &'c LlzkContext) -> Vec<Type<'c>> {
    let felt: Type<'c> = FeltType::with_field(context, FIELD_NAME).into();
    vec![felt, felt, felt]
}

fn is_embedded_curve_add(opcode: &Opcode<FieldElement>) -> bool {
    matches!(
        opcode,
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::EmbeddedCurveAdd { .. })
    )
}
