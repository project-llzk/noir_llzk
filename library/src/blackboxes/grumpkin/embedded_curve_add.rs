use acir::{AcirField, FieldElement};
use llzk::prelude::{
    Block, BlockLike, FuncDefOp, FuncDefOpLike, FunctionType, Location, OperationLike, RegionLike,
    Value, dialect,
};

use crate::{
    blackboxes::common::{append_felt_constant, append_op_with_result, felt_type},
    common::append_if_with_results,
    error::Error,
};

use super::common::{emit_curve_add_result, emit_infinity_point, point_to_array};

pub(in crate::blackboxes) const EMBEDDED_CURVE_ADD_HELPER_NAME: &str = "embedded_curve_add";

pub(crate) fn emit_embedded_curve_add_helper<'c>(
    context: &'c llzk::prelude::LlzkContext,
) -> Result<FuncDefOp<'c>, Error> {
    let location = Location::unknown(context);
    let felt = felt_type(context);
    let inputs = vec![(felt, location); 7];
    let function_type = FunctionType::new(context, &[felt; 7], &[felt, felt, felt]);
    let function = dialect::function::def(
        location,
        EMBEDDED_CURVE_ADD_HELPER_NAME,
        function_type,
        &[],
        None,
    )?;
    function.set_allow_non_native_field_ops_attr(true);

    let block = Block::new(&inputs);
    let input1_x: Value<'c, '_> = block.argument(0)?.into();
    let input1_y: Value<'c, '_> = block.argument(1)?.into();
    let input1_infinite: Value<'c, '_> = block.argument(2)?.into();
    let input2_x: Value<'c, '_> = block.argument(3)?.into();
    let input2_y: Value<'c, '_> = block.argument(4)?.into();
    let input2_infinite: Value<'c, '_> = block.argument(5)?.into();
    let predicate: Value<'c, '_> = block.argument(6)?.into();

    let one = append_felt_constant(&block, context, location, &FieldElement::one())?;
    let predicate_is_true =
        append_op_with_result(&block, dialect::bool::eq(location, predicate, one)?)?;
    let result_types = [felt, felt, felt];
    let [output_x, output_y, output_infinite] = append_if_with_results(
        &block,
        location,
        predicate_is_true,
        &result_types,
        |then_block| {
            emit_curve_add_result(
                then_block,
                context,
                location,
                (input1_x, input1_y, input1_infinite),
                (input2_x, input2_y, input2_infinite),
            )
            .map(point_to_array)
        },
        |else_block| emit_infinity_point(else_block, context, location).map(point_to_array),
    )?;
    block.append_operation(dialect::function::r#return(
        location,
        &[output_x, output_y, output_infinite],
    ));
    function.region(0)?.append_block(block);
    Ok(function)
}
