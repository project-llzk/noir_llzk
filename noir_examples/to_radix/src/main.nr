// Decomposes a `Field` into 4 big-endian byte limbs from unconstrained
// code, exercising the runtime `BlackBoxOp::ToRadix` lowering path.
unconstrained fn decompose(x: Field) -> [u8; 4] {
    x.to_be_bytes::<4>()
}

fn main(input: pub Field) -> pub [u8; 4] {
    // Safety: the recomposition assert below binds the brillig output
    // to `input`, so any tampering with the limbs fails verification.
    let limbs = unsafe { decompose(input) };
    let mut acc: Field = 0;
    for i in 0..4 {
        acc = acc * 256 + (limbs[i] as Field);
    }
    assert(acc == input);
    limbs
}
