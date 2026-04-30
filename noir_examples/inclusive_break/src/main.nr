// `for i in 0..=u8::MAX` - the upper bound IS the type's max, so noir
// can't increment past it without overflow. The lowering emits an
// exclusive loop followed by a "should-execute-final-iteration"
// diamond. We add a `break` inside the body: if the break jumps to
// the diamond's merge while the loop's natural exit goes through the
// diamond's head, walk_to_canonical resolves to two different
// canonicals and structuring should error.
unconstrained fn first_zero_inclusive(xs: [u8; 256]) -> u32 {
    let mut idx: u32 = 256;
    for i in 0..=255_u8 {
        if xs[i as u32] == 0 {
            idx = i as u32;
            break;
        }
    }
    idx
}

fn main(xs: [u8; 256], expected: pub u32) {
    // Safety: result is bound by the assert below.
    let r = unsafe { first_zero_inclusive(xs) };
    assert(r == expected);
}
