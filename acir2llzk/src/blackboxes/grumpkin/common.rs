use acir::{AcirField, FieldElement};
use llzk::{
    builder::OpBuilder,
    prelude::{
        LlzkContext, Location, Type, Value,
        dialect::{bool, felt},
    },
};

use crate::{
    blackboxes::common::append_felt_constant,
    block_writer::BlockWriter,
    common::{
        append_if_with_results, as_value, constrain_bool, emit_gated_eq, insert_if_with_results,
    },
    error::Error,
    writer::Writer,
};

const GRUMPKIN_B: i128 = -17;

/// Wrapper around a tuple of SSA values that together represent an affine point.
#[derive(Clone, Copy)]
pub(crate) struct AffinePointValue<'c, 'a>(Value<'c, 'a>, Value<'c, 'a>);

impl<'c, 'a> AffinePointValue<'c, 'a> {
    pub(crate) fn x(&self) -> Value<'c, 'a> {
        self.0
    }

    pub(crate) fn y(&self) -> Value<'c, 'a> {
        self.1
    }
}

impl<'c: 'a, 'a> AffinePointValue<'c, 'a> {
    /// Computes the elliptic-curve sum of two finite affine points.
    ///
    /// Handles the exceptional cases of affine addition, including point doubling
    /// and addition of inverse points. Returns the point at infinity when the points
    /// are inverses, or when doubling a point with y-coordinate zero.
    /// Otherwise, emits the appropriate affine addition or doubling formula (see
    /// [`formula`](AffinePointValue::formula) for more details).
    ///
    /// Both input points are assumed to be finite and valid points on the curve.
    pub(crate) fn add<'b>(
        self,
        other: Self,
        builder: &OpBuilder<'c, '_>,
        context: &'c LlzkContext,
        location: Location<'c>,
    ) -> Result<EmbeddedPointValue<'c, 'b>, Error>
    where
        'c: 'b,
    {
        let zero = append_felt_constant(builder, context, location, &FieldElement::zero())?;
        let felt_type = Type::from(context.felt_type());

        let result_types = [felt_type, felt_type, felt_type];
        append_if_with_results(
            builder,
            location,
            as_value(bool::eq(builder, location, self.x(), other.x())?)?,
            &result_types,
            |builder| {
                append_if_with_results(
                    builder,
                    location,
                    as_value(bool::eq(builder, location, self.y(), other.y())?)?,
                    &result_types,
                    |builder| {
                        append_if_with_results(
                            builder,
                            location,
                            as_value(bool::eq(builder, location, self.y(), zero)?)?,
                            &result_types,
                            |builder| EmbeddedPointValue::infinity(builder, context, location),
                            |builder| self.formula(other, builder, context, location, true),
                        )
                    },
                    |builder| EmbeddedPointValue::infinity(builder, context, location),
                )
            },
            |builder| self.formula(other, builder, context, location, false),
        )
        .map(Into::into)
    }

    /// Emits the non-exceptional affine elliptic-curve addition or doubling formula.
    ///
    /// The caller must handle point-at-infinity and vertical-line cases.
    ///
    /// The emitted IR represents the following equations for a new non-infinite point `(x',
    /// y')` given two points `(x1, y1)` and `(x2, y2)`, represented by `self` and `other` respectively.
    ///
    /// When `is_doubling == true`:
    ///
    /// ```
    /// λ  = (3 * x1^2) / (2 * y1)
    /// x' = λ^2 - 2 * x1
    /// y' = λ(x1 - x') - y1
    /// ```
    ///
    /// When `is_doubling == false`:
    ///
    /// ```
    /// λ = (y2 - y1) / (x2 - x1)
    /// x' = λ^2 - x1 + x2
    /// y' = λ(x1 - x') - y1
    /// ```
    pub(crate) fn formula<'b>(
        self,
        other: Self,
        builder: &OpBuilder<'c, '_>,
        context: &'c LlzkContext,
        location: Location<'c>,
        is_doubling: bool,
    ) -> Result<EmbeddedPointValue<'c, 'b>, Error>
    where
        'c: 'b,
    {
        let lambda = if is_doubling {
            as_value(felt::div(
                builder,
                location,
                as_value(felt::mul(
                    builder,
                    location,
                    append_felt_constant(builder, context, location, &FieldElement::from(3_u128))?,
                    as_value(felt::mul(builder, location, self.x(), self.x())?)?,
                )?)?,
                as_value(felt::mul(
                    builder,
                    location,
                    append_felt_constant(builder, context, location, &FieldElement::from(2_u128))?,
                    self.y(),
                )?)?,
            )?)?
        } else {
            as_value(felt::div(
                builder,
                location,
                as_value(felt::sub(builder, location, other.y(), self.y())?)?,
                as_value(felt::sub(builder, location, other.x(), self.x())?)?,
            )?)?
        };

        let output_x = as_value(felt::sub(
            builder,
            location,
            as_value(felt::mul(builder, location, lambda, lambda)?)?,
            as_value(felt::add(
                builder,
                location,
                self.x(),
                if is_doubling { self.x() } else { other.x() },
            )?)?,
        )?)?;
        Ok(EmbeddedPointValue::new(
            output_x,
            as_value(felt::sub(
                builder,
                location,
                as_value(felt::mul(
                    builder,
                    location,
                    lambda,
                    as_value(felt::sub(builder, location, self.x(), output_x)?)?,
                )?)?,
                self.y(),
            )?)?,
            append_felt_constant(builder, context, location, &FieldElement::zero())?,
        ))
    }
}

/// Wrapper around a triple of SSA values that together represent a point embedded in a curve.
#[derive(Clone, Copy)]
pub(crate) struct EmbeddedPointValue<'c, 'a>(Value<'c, 'a>, Value<'c, 'a>, Value<'c, 'a>);

impl<'c, 'a> EmbeddedPointValue<'c, 'a> {
    pub(crate) fn new(x: Value<'c, 'a>, y: Value<'c, 'a>, inf: Value<'c, 'a>) -> Self {
        Self(x, y, inf)
    }

    pub(crate) fn x(&self) -> Value<'c, 'a> {
        self.0
    }

    pub(crate) fn y(&self) -> Value<'c, 'a> {
        self.1
    }

    pub(crate) fn inf(&self) -> Value<'c, 'a> {
        self.2
    }
}

impl<'c: 'a, 'a> EmbeddedPointValue<'c, 'a> {
    /// Emits IR representing an infinite point.
    pub(crate) fn infinity(
        builder: &OpBuilder<'c, '_>,
        context: &'c LlzkContext,
        location: Location<'c>,
    ) -> Result<Self, Error> {
        let zero = append_felt_constant(builder, context, location, &FieldElement::zero())?;
        Ok(Self(
            zero,
            zero,
            append_felt_constant(builder, context, location, &FieldElement::one())?,
        ))
    }

    /// Emits IR representing the addition between two embedded points.
    ///
    /// The IR corresponds to the following pseudo-code, where `self`
    /// is `p1 = (x1, y1, i1)`, `other` is `p2 = (x2, y2, i2)`, and
    /// [`AffinePointValue::add`] is `(+)`.
    ///
    /// ```
    /// if i1 == 0:
    ///   if i2 == 0:
    ///     yield (x1, y1) (+) (x2, y2)
    ///   else:
    ///     yield p1
    /// else:
    ///   yield p2
    /// ```
    pub(crate) fn add(
        self,
        other: Self,
        builder: &OpBuilder<'c, '_>,
        context: &'c LlzkContext,
        location: Location<'c>,
    ) -> Result<Self, Error> {
        let felt_type = Type::from(context.felt_type());
        let result_types = [felt_type, felt_type, felt_type];

        let zero = append_felt_constant(builder, context, location, &FieldElement::zero())?;

        Ok(append_if_with_results(
            builder,
            location,
            as_value(bool::eq(builder, location, self.inf(), zero)?)?,
            &result_types,
            |builder| {
                append_if_with_results(
                    builder,
                    location,
                    as_value(bool::eq(builder, location, other.inf(), zero)?)?,
                    &result_types,
                    |builder| {
                        AffinePointValue::from(self).add(other.into(), builder, context, location)
                    },
                    |_| Ok(self),
                )
            },
            |_| Ok(other),
        )?
        .into())
    }
}

impl<'c, 'a> From<EmbeddedPointValue<'c, 'a>> for [Value<'c, 'a>; 3] {
    fn from(p: EmbeddedPointValue<'c, 'a>) -> Self {
        [p.x(), p.y(), p.inf()]
    }
}

impl<'c, 'a> From<[Value<'c, 'a>; 3]> for EmbeddedPointValue<'c, 'a> {
    fn from(p: [Value<'c, 'a>; 3]) -> Self {
        Self(p[0], p[1], p[2])
    }
}

impl<'c, 'a> From<EmbeddedPointValue<'c, 'a>> for AffinePointValue<'c, 'a> {
    fn from(p: EmbeddedPointValue<'c, 'a>) -> Self {
        Self(p.x(), p.y())
    }
}

pub(crate) fn emit_gated_on_curve<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    predicate: Value<'c, 'b>,
    x: Value<'c, 'b>,
    y: Value<'c, 'b>,
) -> Result<(), Error> {
    let y_sq = writer.insert_mul(y, y)?;
    let x_sq = writer.insert_mul(x, x)?;
    let x_cu = writer.insert_mul(x_sq, x)?;
    let curve_b = writer.emit_constant(&FieldElement::from(GRUMPKIN_B))?;
    let rhs = writer.insert_add(x_cu, curve_b)?;
    emit_gated_eq(writer, predicate, y_sq, rhs)
}

pub(crate) fn emit_is_one<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    value: Value<'c, 'b>,
) -> Result<Value<'c, 'b>, Error> {
    let one = writer.emit_constant(&FieldElement::one())?;
    as_value(bool::eq(
        &OpBuilder::new(writer.context(), writer.insertion_point()),
        writer.location(),
        value,
        one,
    )?)
}

/// Constrains `value` to be in `{0, 1}` when `gate` is `1`.
pub(crate) fn emit_gated_boolean<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    gate: Value<'c, 'b>,
    value: Value<'c, 'b>,
    one: Value<'c, 'b>,
    zero: Value<'c, 'b>,
) -> Result<(), Error> {
    let neg_value = writer.insert_neg(value)?;
    let one_minus_value = writer.insert_add(one, neg_value)?;
    let product = writer.insert_mul(value, one_minus_value)?;
    emit_gated_eq(writer, gate, product, zero)
}

pub(crate) fn emit_predicate_gate<'c, 'b>(
    writer: &mut BlockWriter<'c, 'b>,
    predicate: Value<'c, 'b>,
) -> Result<(Value<'c, 'b>, Value<'c, 'b>), Error> {
    // Constrain predicate to have boolean evaluation
    constrain_bool(writer, predicate)?;
    let predicate_is_true = emit_is_one(writer, predicate)?;
    let context = writer.context();
    let location = writer.location();
    let result_types = [Type::from(context.felt_type())];
    let [predicate_gate] = insert_if_with_results(
        writer,
        predicate_is_true,
        &result_types,
        |then_block| {
            Ok([append_felt_constant(
                then_block,
                context,
                location,
                &FieldElement::one(),
            )?])
        },
        |else_block| {
            Ok([append_felt_constant(
                else_block,
                context,
                location,
                &FieldElement::zero(),
            )?])
        },
    )?;
    Ok((predicate_is_true, predicate_gate))
}
