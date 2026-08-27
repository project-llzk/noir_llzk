use std::collections::BTreeSet;

use acir::{
    brillig::{BlackBoxOp, Opcode as BrilligOpcode},
    circuit::{opcodes::BlackBoxFuncCall, Opcode, Program},
    AcirField, FieldElement,
};
use llzk::{
    builder::OpBuilder,
    prelude::{
        dialect::{bool, function},
        BlockLike, BlockRef, FuncDefOpLike, LlzkContext, Location, Type, Value,
    },
};

use crate::{
    blackboxes::common::{append_felt_constant, create_helper_function},
    common::{append_if_with_results, as_value},
    error::Error,
};

use super::common::EmbeddedPointValue;

pub(crate) const SCALAR_LOW_BITS: usize = 128;
pub(crate) const SCALAR_HIGH_BITS: usize = 126;
pub(crate) const SCALAR_TOTAL_BITS: usize = SCALAR_LOW_BITS + SCALAR_HIGH_BITS;

pub(crate) fn used_arities(program: &Program<FieldElement>) -> BTreeSet<usize> {
    let acir_arities = program
        .functions
        .iter()
        .flat_map(|circuit| circuit.opcodes.iter())
        .filter_map(multi_scalar_mul_arity);
    let brillig_arities = program
        .unconstrained_functions
        .iter()
        .flat_map(|func| func.bytecode.iter())
        .filter_map(brillig_multi_scalar_mul_arity);
    acir_arities.chain(brillig_arities).collect()
}

pub(in crate::blackboxes) fn multi_scalar_mul_helper_name(num_points: usize) -> String {
    format!("multi_scalar_mul_{num_points}")
}

/// Computes the offsets to the input arguments of the helper from the number of points.
///
/// The layout is as follows:
/// ```text
/// | points: num_points * 3 | scalar_bits: num_points * SCALAR_TOTAL_BITS | predicate: 1 |
/// ```
#[derive(Clone, Copy)]
struct HelperInputOffsets {
    num_points: usize,
}

impl HelperInputOffsets {
    fn new(num_points: usize) -> Self {
        Self { num_points }
    }

    fn num_inputs(self) -> usize {
        self.predicate_offset() + 1
    }

    fn predicate_offset(self) -> usize {
        self.scalar_bits_offset() + self.num_points * SCALAR_TOTAL_BITS
    }

    fn scalar_bits_offset(self) -> usize {
        self.num_points * 3
    }

    fn points<R>(
        self,
        mut f: impl FnMut(usize, usize, usize) -> Result<R, Error>,
    ) -> Result<Vec<R>, Error> {
        (0..self.num_points)
            .map(|index| {
                let base = index * 3;
                f(base, base + 1, base + 2)
            })
            .collect()
    }

    fn scalar_bits<R>(
        self,
        mut f: impl FnMut(usize) -> Result<R, Error>,
    ) -> Result<Vec<Vec<R>>, Error> {
        (0..self.num_points)
            .map(|index| {
                (0..SCALAR_TOTAL_BITS)
                    .map(|bit_index| {
                        f(self.scalar_bits_offset() + index * SCALAR_TOTAL_BITS + bit_index)
                    })
                    .collect()
            })
            .collect()
    }
}

struct HelperInputs<'c, 'v> {
    points: Vec<EmbeddedPointValue<'c, 'v>>,
    scalar_bits: Vec<Vec<Value<'c, 'v>>>,
    predicate: Value<'c, 'v>,
}

impl<'c, 'v> HelperInputs<'c, 'v> {
    fn collect_points_input(
        block: BlockRef<'c, 'v>,
        offsets: HelperInputOffsets,
    ) -> Result<Vec<EmbeddedPointValue<'c, 'v>>, Error> {
        offsets.points(|p0, p1, p2| {
            Ok(EmbeddedPointValue::new(
                block.argument(p0)?.into(),
                block.argument(p1)?.into(),
                block.argument(p2)?.into(),
            ))
        })
    }

    fn collect_scalar_bits(
        block: BlockRef<'c, 'v>,
        offsets: HelperInputOffsets,
    ) -> Result<Vec<Vec<Value<'c, 'v>>>, Error> {
        offsets.scalar_bits(|index| Ok(block.argument(index)?.into()))
    }

    fn new(block: BlockRef<'c, 'v>, offsets: HelperInputOffsets) -> Result<Self, Error> {
        Ok(Self {
            points: Self::collect_points_input(block, offsets)?,
            scalar_bits: Self::collect_scalar_bits(block, offsets)?,
            predicate: block.argument(offsets.predicate_offset())?.into(),
        })
    }
}

pub(in crate::blackboxes) fn emit_multi_scalar_mul_helper<'c>(
    context: &'c LlzkContext,
    parent: BlockRef<'c, '_>,
    num_points: usize,
) -> Result<(), Error> {
    let location = Location::unknown(context);
    let felt = Type::from(context.felt_type());
    let offsets = HelperInputOffsets::new(num_points);

    let (function, block) = create_helper_function(
        context,
        parent,
        location,
        &multi_scalar_mul_helper_name(num_points),
        offsets.num_inputs(),
        3,
    )?;
    function.set_allow_non_native_field_ops_attr(true);
    let builder = OpBuilder::at_block_end(context, block);
    let inputs = HelperInputs::new(block, offsets)?;

    let one = append_felt_constant(&builder, context, location, &FieldElement::one())?;
    let output = append_if_with_results(
        &builder,
        location,
        as_value(bool::eq(&builder, location, inputs.predicate, one)?)?,
        &[felt, felt, felt],
        |builder| {
            emit_multi_scalar_mul_result(
                builder,
                context,
                location,
                &inputs.points,
                &inputs.scalar_bits,
            )
        },
        |builder| EmbeddedPointValue::infinity(builder, context, location),
    )?;
    function::r#return(&builder, location, &output);
    Ok(())
}

fn emit_multi_scalar_mul_result<'c: 'a, 'a>(
    builder: &OpBuilder<'c, '_>,
    context: &'c LlzkContext,
    location: Location<'c>,
    points: &[EmbeddedPointValue<'c, 'a>],
    scalar_bits: &[Vec<Value<'c, 'a>>],
) -> Result<EmbeddedPointValue<'c, 'a>, Error> {
    debug_assert_eq!(points.len(), scalar_bits.len());

    points.iter().zip(scalar_bits).try_fold(
        EmbeddedPointValue::infinity(builder, context, location)?,
        |acc, (&point, bits)| {
            acc.add(
                point.scalar_mul(bits, builder, context, location)?,
                builder,
                context,
                location,
            )
        },
    )
}

impl<'c: 'a, 'a> EmbeddedPointValue<'c, 'a> {
    fn scalar_mul(
        self,
        scalar_bits: &[Value<'c, 'a>],
        builder: &OpBuilder<'c, '_>,
        context: &'c LlzkContext,
        location: Location<'c>,
    ) -> Result<Self, Error> {
        let felt = Type::from(context.felt_type());
        let result_types = [felt, felt, felt];
        let one = append_felt_constant(builder, context, location, &FieldElement::one())?;

        scalar_bits.iter().rev().try_fold(
            EmbeddedPointValue::infinity(builder, context, location)?,
            |acc, &bit| {
                let acc = acc.add(acc, builder, context, location)?;
                Ok(append_if_with_results(
                    builder,
                    location,
                    as_value(bool::eq(builder, location, bit, one)?)?,
                    &result_types,
                    |builder| acc.add(self, builder, context, location),
                    |_| Ok(acc),
                )?
                .into())
            },
        )
    }
}

fn multi_scalar_mul_arity(opcode: &Opcode<FieldElement>) -> Option<usize> {
    match opcode {
        Opcode::BlackBoxFuncCall(BlackBoxFuncCall::MultiScalarMul { points, .. }) => {
            Some(points.len() / 3)
        }
        _ => None,
    }
}

fn brillig_multi_scalar_mul_arity(opcode: &BrilligOpcode<FieldElement>) -> Option<usize> {
    match opcode {
        BrilligOpcode::BlackBox(BlackBoxOp::MultiScalarMul { points, .. }) => {
            Some(points.size.0 as usize / 3)
        }
        _ => None,
    }
}
