use std::embedded_curve_ops::{embedded_curve_add, EmbeddedCurvePoint};

fn main(x: Field, y: Field, is_active: bool) -> pub EmbeddedCurvePoint {
    let p = EmbeddedCurvePoint { x, y, is_infinite: false };
    if is_active {
        embedded_curve_add(p, p)
    } else {
        p
    }
}
