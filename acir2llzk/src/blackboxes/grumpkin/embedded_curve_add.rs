use acir::{AcirField, FieldElement};
use llzk::{
    builder::{BlockInsertPointLike, OpBuilder},
    prelude::{
        dialect::{bool, function},
        BlockLike, BlockRef, FuncDefOpLike, LlzkContext, Location, Type,
    },
};

use crate::{
    blackboxes::{
        common::{append_felt_constant, create_helper_function},
        grumpkin::common::EmbeddedPointValue,
    },
    common::{append_if_with_results, as_value},
    error::Error,
};

pub(in crate::blackboxes) const EMBEDDED_CURVE_ADD_HELPER_NAME: &str = "embedded_curve_add";

pub(crate) fn emit_embedded_curve_add_helper<'c>(
    context: &'c LlzkContext,
    parent: BlockRef<'c, '_>,
) -> Result<(), Error> {
    let location = Location::unknown(context);
    let felt = Type::from(context.felt_type());
    let (function, block) = create_helper_function(
        context,
        parent,
        location,
        EMBEDDED_CURVE_ADD_HELPER_NAME,
        7,
        3,
    )?;
    function.set_allow_non_native_field_ops_attr(true);

    let builder = OpBuilder::new(context, block.at_end());
    let output = append_if_with_results(
        &builder,
        location,
        as_value(bool::eq(
            &builder,
            location,
            block.argument(6)?.into(),
            append_felt_constant(&builder, context, location, &FieldElement::one())?,
        )?)?,
        &[felt, felt, felt],
        |builder| {
            EmbeddedPointValue::new(
                block.argument(0)?.into(),
                block.argument(1)?.into(),
                block.argument(2)?.into(),
            )
            .add(
                EmbeddedPointValue::new(
                    block.argument(3)?.into(),
                    block.argument(4)?.into(),
                    block.argument(5)?.into(),
                ),
                builder,
                context,
                location,
            )
        },
        |builder| EmbeddedPointValue::infinity(builder, context, location),
    )?;
    function::r#return(&builder, location, &output);
    Ok(())
}
