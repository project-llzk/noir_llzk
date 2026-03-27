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
struct BlackboxDescriptor {
    symbol_name: &'static str,
    emit: EmitHelperFn,
    result_types: ResultTypesFn,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlackboxFunction {
    EmbeddedCurveAdd,
}

impl BlackboxFunction {
    pub(crate) fn used_in_program(program: &Program<FieldElement>) -> Vec<Self> {
        if program.functions.iter().any(|circuit| {
            circuit.opcodes.iter().any(|opcode| {
                matches!(
                    opcode,
                    Opcode::BlackBoxFuncCall(BlackBoxFuncCall::EmbeddedCurveAdd { .. })
                )
            })
        }) {
            vec![Self::EmbeddedCurveAdd]
        } else {
            vec![]
        }
    }

    pub(crate) fn symbol_name(self) -> String {
        self.descriptor().symbol_name.to_string()
    }

    pub(crate) fn emit<'c>(self, context: &'c LlzkContext) -> Result<FuncDefOp<'c>, Error> {
        (self.descriptor().emit)(context)
    }

    pub(crate) fn result_types<'c>(self, context: &'c LlzkContext) -> Vec<Type<'c>> {
        (self.descriptor().result_types)(context)
    }
    fn descriptor(self) -> BlackboxDescriptor {
        match self {
            Self::EmbeddedCurveAdd => BlackboxDescriptor {
                symbol_name: EMBEDDED_CURVE_ADD_HELPER_NAME,
                emit: emit_embedded_curve_add_helper,
                result_types: embedded_curve_add_result_types,
            },
        }
    }
}

fn embedded_curve_add_result_types<'c>(context: &'c LlzkContext) -> Vec<Type<'c>> {
    let felt: Type<'c> = FeltType::with_field(context, FIELD_NAME).into();
    vec![felt, felt, felt]
}
