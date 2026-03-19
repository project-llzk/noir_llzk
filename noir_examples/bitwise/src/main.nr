fn main(a: u8, b: u8, and_expected: pub u8, xor_expected: pub u8) {
    let and_result = a & b;
    let xor_result = a ^ b;

    assert(and_result == and_expected);
    assert(xor_result == xor_expected);
}
