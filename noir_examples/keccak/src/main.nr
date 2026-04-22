use std::hash::keccakf1600;

fn main(state: [u64; 25]) -> pub [u64; 25] {
    keccakf1600(state)
}
