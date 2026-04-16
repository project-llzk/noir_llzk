use std::hash::blake2s;

fn main(x: [u8; 3]) -> pub [u8; 32] {
    blake2s(x)
}
