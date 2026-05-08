// Two `break`s in a Brillig loop force the multi-exit shape: Noir's
// unrolling pass refuses any loop containing `break` or `continue`, so
// the `for` survives codegen as a runtime loop with two body-internal
// exit edges converging on the post-loop block.
unconstrained fn classify(xs: [u32; 8]) -> u32 {
    let mut result: u32 = 0;
    for i in 0..8 {
        if xs[i] == 99 {
            if xs[i +2] == 99 {
            result = 1;
            break;
            }
            if xs[i +2 ] == 9 {
            result = 3;
            break;
            }
        }
        if xs[i] == 100 {
            result = 2;
            break;
        }
    }
    result
}

fn main(xs: [u32; 8], expected: pub u32) {
    // Safety: result is constrained by the assert below.
    let result = unsafe { classify(xs) };
    assert(result == expected);
}
