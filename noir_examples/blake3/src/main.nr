use std::hash::blake3;

fn main(x: [u8; 3]) -> pub [u8; 32] {
    blake3(x)
}
