use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul};

fn main(lo: Field, hi: Field) -> pub EmbeddedCurvePoint {
    let generator = EmbeddedCurvePoint::generator();
    let scalar = EmbeddedCurveScalar { lo, hi };
    multi_scalar_mul([generator], [scalar])
}
