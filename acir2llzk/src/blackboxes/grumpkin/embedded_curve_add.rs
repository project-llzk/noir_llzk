use acir::{AcirField, FieldElement};
use llzk::{
    builder::{BlockInsertPointLike, OpBuilder},
    dialect::empty_region,
    prelude::{
        dialect::{bool, function},
        Block, BlockLike, BlockRef, FuncDefOpLike, FunctionType, LlzkContext, Location, RegionLike,
        Type, Value,
    },
};

use crate::{
    blackboxes::common::append_felt_constant,
    common::{append_if_with_results, as_value},
    error::Error,
};

use super::common::{emit_curve_add_result, emit_infinity_point, point_to_array};

pub(in crate::blackboxes) const EMBEDDED_CURVE_ADD_HELPER_NAME: &str = "embedded_curve_add";

pub(crate) fn emit_embedded_curve_add_helper<'c>(
    context: &'c LlzkContext,
    block: BlockRef<'c, '_>,
) -> Result<(), Error> {
    let location = Location::unknown(context);
    let felt = Type::from(context.felt_type());
    let inputs = vec![(felt, location); 7];
    let function_type = FunctionType::new(context, &[felt; 7], &[felt, felt, felt]);
    let function = function::def(
        &OpBuilder::new(context, block.at_end()),
        location,
        EMBEDDED_CURVE_ADD_HELPER_NAME,
        function_type,
        &[],
        None,
        empty_region,
    )?;
    function.set_allow_non_native_field_ops_attr(true);

    let body = function.body()?;
    let block = body
        .first_block()
        .unwrap_or_else(|| body.append_block(Block::new(&inputs)));
    let input1_x: Value<'c, '_> = block.argument(0)?.into();
    let input1_y: Value<'c, '_> = block.argument(1)?.into();
    let input1_infinite: Value<'c, '_> = block.argument(2)?.into();
    let input2_x: Value<'c, '_> = block.argument(3)?.into();
    let input2_y: Value<'c, '_> = block.argument(4)?.into();
    let input2_infinite: Value<'c, '_> = block.argument(5)?.into();
    let predicate: Value<'c, '_> = block.argument(6)?.into();

    let builder = OpBuilder::new(context, block.at_end());
    let one = append_felt_constant(&builder, context, location, &FieldElement::one())?;
    let predicate_is_true = as_value(bool::eq(&builder, location, predicate, one)?)?;
    let result_types = [felt, felt, felt];
    let [output_x, output_y, output_infinite] = append_if_with_results(
        &builder,
        location,
        predicate_is_true,
        &result_types,
        |builder| {
            emit_curve_add_result(
                builder,
                context,
                location,
                (input1_x, input1_y, input1_infinite),
                (input2_x, input2_y, input2_infinite),
            )
            .map(point_to_array)
        },
        |builder| emit_infinity_point(builder, context, location).map(point_to_array),
    )?;
    function::r#return(&builder, location, &[output_x, output_y, output_infinite]);
    Ok(())
}
