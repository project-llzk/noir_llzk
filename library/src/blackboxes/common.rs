use acir::FieldElement;
use llzk::prelude::{Block, BlockLike, FeltType, Location, Operation, Type, Value, dialect};

use crate::{FIELD_NAME, error::Error};

pub(in crate::blackboxes) fn append_felt_constant<'c, 'a>(
    block: &'a Block<'c>,
    context: &'c llzk::prelude::LlzkContext,
    location: Location<'c>,
    value: &FieldElement,
) -> Result<Value<'c, 'a>, Error> {
    let attr = crate::common::field_to_felt_const(context, value);
    append_op_with_result(block, dialect::felt::constant(location, attr)?)
}

pub(in crate::blackboxes) fn append_op_with_result<'c, 'a>(
    block: &'a Block<'c>,
    op: Operation<'c>,
) -> Result<Value<'c, 'a>, Error> {
    Ok(block.append_operation(op).result(0)?.into())
}

pub(in crate::blackboxes) fn felt_type<'c>(context: &'c llzk::prelude::LlzkContext) -> Type<'c> {
    FeltType::with_field(context, FIELD_NAME).into()
}

pub(in crate::blackboxes) fn block_args<'c, 'a, const N: usize>(
    block: &'a Block<'c>,
    offset: usize,
) -> Result<[Value<'c, 'a>; N], Error> {
    let vec: Vec<Value<'c, 'a>> = (0..N)
        .map(|i| {
            block
                .argument(offset + i)
                .map(Into::into)
                .map_err(Error::from)
        })
        .collect::<Result<_, _>>()?;
    Ok(vec.try_into().unwrap_or_else(|_: Vec<_>| unreachable!()))
}
