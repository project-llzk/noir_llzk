// Mutually recursive unconstrained helpers. `is_even` calls `is_odd`
// which calls `is_even`. Stress-tests:
//   - Procedure detection on a co-recursive call graph.
//   - The procedure-entry fence: each helper is its own procedure;
//     calling another procedure is via `Call` (legitimate), not via
//     non-Call edges (which would be the artifact case).
//   - The walker's procedure-table lookup when each procedure has its
//     own loop-context-free body.
unconstrained fn is_even(n: u32) -> bool {
    if n == 0 {
        true
    } else {
        is_odd(n - 1)
    }
}

unconstrained fn is_odd(n: u32) -> bool {
    if n == 0 {
        false
    } else {
        is_even(n - 1)
    }
}

unconstrained fn classify_parity(x: u32) -> u32 {
    if is_even(x) {
        100
    } else {
        200
    }
}

fn main(x: pub u32, expected: pub u32) {
    // Safety: result is constrained.
    let r = unsafe { classify_parity(x) };
    assert(r == expected);
}
