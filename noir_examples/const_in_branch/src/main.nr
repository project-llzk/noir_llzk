unconstrained fn branchy(x: u32) -> u32 {
    if x > 10 {
        x + 42
    } else {
        x + 7
    }
}

fn main(x: u32) -> pub u32 {
    // Safety: demo
    unsafe { branchy(x) }
}
