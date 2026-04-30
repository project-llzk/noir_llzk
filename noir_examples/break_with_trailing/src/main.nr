// Minimal "break followed by more iteration body" pattern. The
// iteration body becomes [IfThenElse(cond, [SetEscapeFlag], []),
// Linear(count = count + 1)] - the IfThenElse is not the last node,
// so SetEscapeFlag at its tail is at a non-tail position relative
// to the loop body. validate_escape_flag_positions rejects.
unconstrained fn count_until(xs: [u32; 8], target: u32) -> u32 {
    let mut count: u32 = 0;
    for i in 0..8 {
        if xs[i] == target {
            break;
        }
        count = count + 1;
    }
    count
}

fn main(xs: [u32; 8], target: pub u32, expected: pub u32) {
    // Safety: target/expected are public; assert binds the brillig output.
    let r = unsafe { count_until(xs, target) };
    assert(r == expected);
    assert(target == expected);
}
