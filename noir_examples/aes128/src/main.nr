use std::aes128::aes128_encrypt;

fn main(input: [u8; 12], iv: [u8; 16], key: [u8; 16]) -> pub [u8; 16] {
    aes128_encrypt(input, iv, key)
}
