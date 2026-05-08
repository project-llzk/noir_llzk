// Header-level trap-peephole (`assert`) followed by a joining branch
// (if/else with a common post-dominator), then the real break decision.
// Exercises interleaving the two `find_effective_header` skip rules.

unconstrained fn search(target: u32, flag: bool) -> u32 {
    let mut i: u32 = 0;
    loop {
        assert(i < 1_000);
        if flag {
            i = i + 2;
        } else {
            i = i + 1;
        }
        if i >= target {
            break;
        }
    }
    i
}

fn main(target: pub u32, flag: pub bool, expected: pub u32) {
    // Safety: bound by assert.
    let r = unsafe { search(target, flag) };
    assert(r == expected);
}
