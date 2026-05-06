use llzk::prelude::{
    Block, BlockLike, FuncDefOp, FuncDefOpLike, FunctionType, Location, OperationLike, RegionLike,
    Value, dialect,
};

use crate::{
    blackboxes::common::{block_args, felt_type},
    error::Error,
};

use crate::blackboxes::common::{
    ConstantCache, emit_and, emit_rotr, emit_shr, emit_wrapping_add, emit_wrapping_sum, emit_xor,
};

pub(crate) const SHA256_STATE_WORDS: usize = 8;
const SHA256_MESSAGE_WORDS: usize = 16;
const SHA256_SCHEDULE_WORDS: usize = 64;
const SHA256_HELPER_INPUTS: usize = SHA256_MESSAGE_WORDS + SHA256_STATE_WORDS;

pub(in crate::blackboxes) const SHA256_HELPER_NAME: &str = "sha256_compression";

/// SHA-256 round constants (first 32 bits of the fractional parts of the cube roots
/// of the first 64 primes).
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub(in crate::blackboxes) fn emit_sha256_helper<'c>(
    context: &'c llzk::prelude::LlzkContext,
) -> Result<FuncDefOp<'c>, Error> {
    let location = Location::unknown(context);
    let felt = felt_type(context);
    let inputs = vec![(felt, location); SHA256_HELPER_INPUTS];
    let input_types = vec![felt; SHA256_HELPER_INPUTS];
    let output_types = vec![felt; SHA256_STATE_WORDS];
    let function_type = FunctionType::new(context, &input_types, &output_types);
    let function = dialect::function::def(location, SHA256_HELPER_NAME, function_type, &[], None)?;
    function.set_allow_non_native_field_ops_attr(true);

    let block = Block::new(&inputs);
    let msg: [Value<'c, '_>; SHA256_MESSAGE_WORDS] = block_args(&block, 0)?;
    let state: [Value<'c, '_>; SHA256_STATE_WORDS] = block_args(&block, SHA256_MESSAGE_WORDS)?;

    let mut cache = ConstantCache::new(&block, context, location);
    let outputs = emit_sha256_compress(&mut cache, &msg, &state)?;
    block.append_operation(dialect::function::r#return(location, &outputs));
    function.region(0)?.append_block(block);
    Ok(function)
}

fn emit_sha256_compress<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    msg: &[Value<'c, 'a>; 16],
    state: &[Value<'c, 'a>; 8],
) -> Result<[Value<'c, 'a>; 8], Error> {
    let mut w = Vec::with_capacity(SHA256_SCHEDULE_WORDS);
    w.extend_from_slice(msg);
    for i in SHA256_MESSAGE_WORDS..SHA256_SCHEDULE_WORDS {
        let s0 = emit_sigma0(cache, w[i - 15])?;
        let s1 = emit_sigma1(cache, w[i - 2])?;
        let wi = emit_wrapping_sum(cache, &[w[i - 16], s0, w[i - 7], s1])?;
        w.push(wi);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for i in 0..SHA256_SCHEDULE_WORDS {
        let big_s1 = emit_big_sigma1(cache, e)?;
        let ch = emit_ch(cache, e, f, g)?;
        let ki = cache.u32(K[i])?;
        let temp1 = emit_wrapping_sum(cache, &[h, big_s1, ch, ki, w[i]])?;

        let big_s0 = emit_big_sigma0(cache, a)?;
        let maj = emit_maj(cache, a, b, c)?;

        h = g;
        g = f;
        f = e;
        e = emit_wrapping_add(cache, d, temp1)?;
        d = c;
        c = b;
        b = a;
        // Fuse `temp2 = big_s0 + maj` into the final sum to save one mask per round.
        a = emit_wrapping_sum(cache, &[temp1, big_s0, maj])?;
    }

    Ok([
        emit_wrapping_add(cache, state[0], a)?,
        emit_wrapping_add(cache, state[1], b)?,
        emit_wrapping_add(cache, state[2], c)?,
        emit_wrapping_add(cache, state[3], d)?,
        emit_wrapping_add(cache, state[4], e)?,
        emit_wrapping_add(cache, state[5], f)?,
        emit_wrapping_add(cache, state[6], g)?,
        emit_wrapping_add(cache, state[7], h)?,
    ])
}

// ── SHA-256 helper functions ────────────────────────────────────────────

/// σ0(x) = ROTR(7, x) ^ ROTR(18, x) ^ SHR(3, x)
fn emit_sigma0<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    x: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    let r7 = emit_rotr(cache, x, 7)?;
    let r18 = emit_rotr(cache, x, 18)?;
    let s3 = emit_shr(cache, x, 3)?;
    let xor1 = emit_xor(cache.block, cache.location, r7, r18)?;
    emit_xor(cache.block, cache.location, xor1, s3)
}

/// σ1(x) = ROTR(17, x) ^ ROTR(19, x) ^ SHR(10, x)
fn emit_sigma1<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    x: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    let r17 = emit_rotr(cache, x, 17)?;
    let r19 = emit_rotr(cache, x, 19)?;
    let s10 = emit_shr(cache, x, 10)?;
    let xor1 = emit_xor(cache.block, cache.location, r17, r19)?;
    emit_xor(cache.block, cache.location, xor1, s10)
}

/// Σ0(x) = ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x)
fn emit_big_sigma0<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    x: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    let r2 = emit_rotr(cache, x, 2)?;
    let r13 = emit_rotr(cache, x, 13)?;
    let r22 = emit_rotr(cache, x, 22)?;
    let xor1 = emit_xor(cache.block, cache.location, r2, r13)?;
    emit_xor(cache.block, cache.location, xor1, r22)
}

/// Σ1(x) = ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x)
fn emit_big_sigma1<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    x: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    let r6 = emit_rotr(cache, x, 6)?;
    let r11 = emit_rotr(cache, x, 11)?;
    let r25 = emit_rotr(cache, x, 25)?;
    let xor1 = emit_xor(cache.block, cache.location, r6, r11)?;
    emit_xor(cache.block, cache.location, xor1, r25)
}

/// Ch(e, f, g) = (e AND f) XOR (NOT e AND g) = g XOR (e AND (f XOR g)).
fn emit_ch<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    e: Value<'c, 'a>,
    f: Value<'c, 'a>,
    g: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    let f_xor_g = emit_xor(cache.block, cache.location, f, g)?;
    let e_and = emit_and(cache.block, cache.location, e, f_xor_g)?;
    emit_xor(cache.block, cache.location, g, e_and)
}

/// Maj(a, b, c) = (a AND b) XOR (a AND c) XOR (b AND c) = (a AND b) XOR (c AND (a XOR b)).
fn emit_maj<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    a: Value<'c, 'a>,
    b: Value<'c, 'a>,
    c: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    let ab = emit_and(cache.block, cache.location, a, b)?;
    let a_xor_b = emit_xor(cache.block, cache.location, a, b)?;
    let c_and = emit_and(cache.block, cache.location, c, a_xor_b)?;
    emit_xor(cache.block, cache.location, ab, c_and)
}

#[cfg(test)]
mod tests {
    use super::K;

    /// SHA-256 initial hash values (first 32 bits of fractional parts of
    /// square roots of the first 8 primes).
    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    #[test]
    fn empty_message_matches_known_hash() {
        // SHA-256("") — single block with padding.
        let mut msg = [0u32; 16];
        // Padding: 0x80 byte, then zeros, then length in bits (0) as big-endian u64.
        msg[0] = 0x80000000;
        let result = compress(&H0, &msg);
        assert_eq!(
            words_to_hex(&result),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn abc_matches_known_hash() {
        // SHA-256("abc") — single block with padding.
        let mut msg = [0u32; 16];
        // "abc" = 0x61626380 (with padding bit)
        msg[0] = 0x61626380;
        // Length in bits = 24 = 0x18, stored at the end as big-endian u64.
        msg[15] = 24;
        let result = compress(&H0, &msg);
        assert_eq!(
            words_to_hex(&result),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    fn compress(state: &[u32; 8], msg: &[u32; 16]) -> [u32; 8] {
        // Message schedule.
        let mut w = [0u32; 64];
        w[..16].copy_from_slice(msg);
        for i in 16..64 {
            let s0 = sigma0(w[i - 15]);
            let s1 = sigma1(w[i - 2]);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

        for i in 0..64 {
            let big_s1 = big_sigma1(e);
            let ch = ch(e, f, g);
            let temp1 = h
                .wrapping_add(big_s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let big_s0 = big_sigma0(a);
            let maj = maj(a, b, c);
            let temp2 = big_s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        [
            state[0].wrapping_add(a),
            state[1].wrapping_add(b),
            state[2].wrapping_add(c),
            state[3].wrapping_add(d),
            state[4].wrapping_add(e),
            state[5].wrapping_add(f),
            state[6].wrapping_add(g),
            state[7].wrapping_add(h),
        ]
    }

    fn sigma0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }
    fn sigma1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }
    fn big_sigma0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }
    fn big_sigma1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }
    fn ch(e: u32, f: u32, g: u32) -> u32 {
        (e & f) ^ (!e & g)
    }
    fn maj(a: u32, b: u32, c: u32) -> u32 {
        (a & b) ^ (a & c) ^ (b & c)
    }

    fn words_to_hex(words: &[u32; 8]) -> String {
        words.iter().map(|w| format!("{w:08x}")).collect()
    }
}
