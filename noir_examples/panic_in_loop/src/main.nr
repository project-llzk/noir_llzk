// Forces `assert(_, "msg")` (a `Call <RevertWithString>` to a divergent
// procedure) inside an unrolled loop body. Noir's loop unrolling places
// the panic dispatch at the end of the user function's bytecode, so the
// last divergent Call's continuation byte coincides with the next
// procedure's entry: the layout that exposes the procedure-walker
// divergence bug in CFG recovery.
unconstrained fn check(xs: [u32; 4]) -> u32 {
    let mut acc: u32 = 0;
    for i in 0..4 {
        if xs[i] == 13 {
            // Safety: not actually reached at runtime.
            assert(false, "bad value");
        }
        acc = acc + xs[i];
    }
    acc
}

fn main(xs: [u32; 4], expected: pub u32) {
    // Safety: result is constrained.
    let r = unsafe { check(xs) };
    assert(r == expected);
}
