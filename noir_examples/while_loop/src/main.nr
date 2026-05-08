// `while` keyword in unconstrained Noir. The condition `sum < target`
// uses a runtime input, preventing constant-folding the loop. The
// structurer should recognise the JumpIf-headed loop (a `while` shape)
// with a continuation condition and no escape flag (no break).
unconstrained fn count_iterations_to_reach(target: u32) -> u32 {
    let mut i: u32 = 0;
    let mut sum: u32 = 0;
    while sum < target {
        i = i + 1;
        sum = sum + i;
    }
    i
}

fn main(target: pub u32, expected: pub u32) {
    // Safety: target/expected are public; assert binds the brillig output.
    let r = unsafe { count_iterations_to_reach(target) };
    assert(r == expected);
}
