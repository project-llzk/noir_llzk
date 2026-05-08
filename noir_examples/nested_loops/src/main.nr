// Nested `for` loops where the inner loop has a `break`. The inner
// loop's escape flag should be isolated from the outer loop's
// structuring -- breaking out of the inner loop must not affect the
// outer loop's iteration.
//
// Source:
//   for i in 0..4 {
//       for j in 0..4 {
//           if matrix[i][j] == sentinel { found += 1; break; }   // inner break
//       }
//       // outer loop continues normally regardless of inner break
//   }
unconstrained fn count_first_per_row(matrix: [[u32; 4]; 4], sentinel: u32) -> u32 {
    let mut found: u32 = 0;
    for i in 0..4 {
        for j in 0..4 {
            if matrix[i][j] == sentinel {
                found = found + 1;
                break;
            }
        }
    }
    found
}

fn main(matrix: [[u32; 4]; 4], sentinel: pub u32, expected: pub u32) {
    // Safety: result is constrained.
    let r = unsafe { count_first_per_row(matrix, sentinel) };
    assert(r == expected);
}
