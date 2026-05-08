// Direct recursion in an unconstrained function.
unconstrained fn count_down(n: u32) -> u32 {
    if n == 0 {
        0
    } else {
        count_down(n - 1) + 1
    }
}

fn main(input: pub u32, expected: pub u32) {
    // Safety: input is public; the assert binds the brillig output.
    let r = unsafe { count_down(input) };
    assert(r == expected);
    assert(input == expected);
}
