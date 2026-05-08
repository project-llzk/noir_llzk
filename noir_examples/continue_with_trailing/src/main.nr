// `continue` followed by trailing iteration body. Mirrors
// `break_with_trailing` but uses `continue` instead of `break`.
//
// Noir lowers `continue` to a Jmp back to the loop header, so both arms
// of the if/continue terminate at the natural back-edge:
//   then-arm:  Jmp header  (continue)
//   else-arm:  Linear(count = count + 1); Jmp header  (fall-through)
//
// The structurer should emit a Loop region whose body is a single
// IfThenElse with NO escape flag -- continue uses the natural back-edge,
// not an early exit.
unconstrained fn count_non_target(xs: [u32; 8], target: u32) -> u32 {
    let mut count: u32 = 0;
    for i in 0..8 {
        if xs[i] == target {
            continue;
        }
        count = count + 1;
    }
    count
}

fn main(xs: [u32; 8], target: pub u32, expected: pub u32) {
    // Safety: target/expected are public; assert binds the brillig output.
    let r = unsafe { count_non_target(xs, target) };
    assert(r == expected);
}
