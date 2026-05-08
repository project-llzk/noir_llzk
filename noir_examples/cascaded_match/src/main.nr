// Cascaded if/else-if chain with each branch panicking on a sentinel
// value. Each `if` lowers to a JumpIf whose then-arm panics (divergent)
// and whose else-arm continues into the next check. The structurer
// must produce nested IfThenElse via the half-joining dispatch at
// every level of the cascade.
unconstrained fn classify(x: u32) -> u32 {
    if x == 0 {
        assert(false, "zero");
    } else if x == 1 {
        assert(false, "one");
    } else if x == 2 {
        assert(false, "two");
    } else if x == 3 {
        assert(false, "three");
    }
    x * 2
}

fn main(x: pub u32, expected: pub u32) {
    // Safety: x and expected are public and bind r below.
    let r = unsafe { classify(x) };
    assert(r == expected);
    assert(x == expected / 2);
}
