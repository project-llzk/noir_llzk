use std::hash::poseidon2_permutation;

fn main(a: Field, b: Field, c: Field, d: Field) -> pub [Field; 4] {
    poseidon2_permutation([a, b, c, d], 4)
}
