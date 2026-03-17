global N: u32 = 5;

fn pow(base: Field, exp: u32) -> Field {
    let mut result: Field = 1;
    for _ in 0..exp {
        result *= base;
    }
    result
}

fn main(coefficients: [Field; N], x : Field, y: pub Field) {
    let mut result: Field = 0;

    for i in 0..N {
        result += 3 * coefficients[i] * pow(x, i as u32);
    }

    assert(result == y);
}
