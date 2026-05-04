// User-defined divergent helper called from inside a loop body. The
// helper is a regular `unconstrained fn` that always panics, distinct
// from the inline `assert(_, "msg")` panic shape. Tests that:
//   - The CFG correctly classifies the helper as divergent.
//   - The dead `JumpIf` Noir emits inside panic-string lowering (whose
//     dead arm targets another procedure's entry) doesn't pollute the
//     calling procedure's body via `procedure_body`'s walk.
//   - The structurer treats the call site as a divergent leaf.
#[inline_never]
unconstrained fn fail_loud() -> u32 {
    panic(f"explicit failure")
}

unconstrained fn process(xs: [u32; 8], banned: u32) -> u32 {
    let mut acc: u32 = 0;
    for i in 0..8 {
        if xs[i] == banned {
            let _ = fail_loud();
        }
        acc = acc + xs[i];
    }
    acc
}

fn main(xs: [u32; 8], banned: pub u32, expected: pub u32) {
    // Safety: result is constrained.
    let r = unsafe { process(xs, banned) };
    assert(r == expected);
}
