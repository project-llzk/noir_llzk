use llzk::{
    builder::{BlockInsertPointLike as _, OpBuilder},
    prelude::{BlockRef, FuncDefOpLike, LlzkContext, Location, Value, dialect::function},
};

use crate::{
    blackboxes::common::{WordArithEmitter, block_args, create_helper_function},
    error::Error,
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

pub(in crate::blackboxes) fn emit_sha256_helper<'c, 'b>(
    context: &'c LlzkContext,
    block: BlockRef<'c, 'b>,
) -> Result<(), Error> {
    let location = Location::unknown(context);
    let (function, block) = create_helper_function(
        context,
        block,
        location,
        SHA256_HELPER_NAME,
        SHA256_HELPER_INPUTS,
        SHA256_STATE_WORDS,
    )?;
    function.set_allow_non_native_field_ops_attr(true);

    let msg: [Value<'c, '_>; SHA256_MESSAGE_WORDS] = block_args(block, 0)?;
    let state: [Value<'c, '_>; SHA256_STATE_WORDS] = block_args(block, SHA256_MESSAGE_WORDS)?;

    let mut emitter = WordArithEmitter::new(block, context, location);
    let outputs = emit_sha256_compress(&mut emitter, &msg, &state)?;
    function::r#return(&OpBuilder::new(context, block.at_end()), location, &outputs);
    Ok(())
}

fn emit_sha256_compress<'c: 'a, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
    msg: &[Value<'c, 'a>; 16],
    state: &[Value<'c, 'a>; 8],
) -> Result<[Value<'c, 'a>; 8], Error> {
    let mut w = Vec::with_capacity(SHA256_SCHEDULE_WORDS);
    w.extend_from_slice(msg);
    for i in SHA256_MESSAGE_WORDS..SHA256_SCHEDULE_WORDS {
        let s0 = emit_sigma0(emitter, w[i - 15])?;
        let s1 = emit_sigma1(emitter, w[i - 2])?;
        let wi = emitter.emit_wrapping_sum(&[w[i - 16], s0, w[i - 7], s1])?;
        w.push(wi);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for i in 0..SHA256_SCHEDULE_WORDS {
        let big_s1 = emit_big_sigma1(emitter, e)?;
        let ch = emit_ch(emitter, e, f, g)?;
        let ki = emitter.u32(K[i])?;
        let temp1 = emitter.emit_wrapping_sum(&[h, big_s1, ch, ki, w[i]])?;

        let big_s0 = emit_big_sigma0(emitter, a)?;
        let maj = emit_maj(emitter, a, b, c)?;

        h = g;
        g = f;
        f = e;
        e = emitter.emit_wrapping_add(d, temp1)?;
        d = c;
        c = b;
        b = a;
        // Fuse `temp2 = big_s0 + maj` into the final sum to save one mask per round.
        a = emitter.emit_wrapping_sum(&[temp1, big_s0, maj])?;
    }

    Ok([
        emitter.emit_wrapping_add(state[0], a)?,
        emitter.emit_wrapping_add(state[1], b)?,
        emitter.emit_wrapping_add(state[2], c)?,
        emitter.emit_wrapping_add(state[3], d)?,
        emitter.emit_wrapping_add(state[4], e)?,
        emitter.emit_wrapping_add(state[5], f)?,
        emitter.emit_wrapping_add(state[6], g)?,
        emitter.emit_wrapping_add(state[7], h)?,
    ])
}

// ── SHA-256 helper functions ────────────────────────────────────────────

/// σ0(x) = ROTR(7, x) ^ ROTR(18, x) ^ SHR(3, x)
fn emit_sigma0<'c: 'a, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
    x: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    let r7 = emitter.emit_rotr(x, 7)?;
    let r18 = emitter.emit_rotr(x, 18)?;
    let s3 = emitter.emit_shr(x, 3)?;
    let xor1 = emitter.emit_xor(r7, r18)?;
    emitter.emit_xor(xor1, s3)
}

/// σ1(x) = ROTR(17, x) ^ ROTR(19, x) ^ SHR(10, x)
fn emit_sigma1<'c: 'a, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
    x: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    let r17 = emitter.emit_rotr(x, 17)?;
    let r19 = emitter.emit_rotr(x, 19)?;
    let s10 = emitter.emit_shr(x, 10)?;
    let xor1 = emitter.emit_xor(r17, r19)?;
    emitter.emit_xor(xor1, s10)
}

/// Σ0(x) = ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x)
fn emit_big_sigma0<'c: 'a, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
    x: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    let r2 = emitter.emit_rotr(x, 2)?;
    let r13 = emitter.emit_rotr(x, 13)?;
    let r22 = emitter.emit_rotr(x, 22)?;
    let xor1 = emitter.emit_xor(r2, r13)?;
    emitter.emit_xor(xor1, r22)
}

/// Σ1(x) = ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x)
fn emit_big_sigma1<'c: 'a, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
    x: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    let r6 = emitter.emit_rotr(x, 6)?;
    let r11 = emitter.emit_rotr(x, 11)?;
    let r25 = emitter.emit_rotr(x, 25)?;
    let xor1 = emitter.emit_xor(r6, r11)?;
    emitter.emit_xor(xor1, r25)
}

/// Ch(e, f, g) = (e AND f) XOR (NOT e AND g) = g XOR (e AND (f XOR g)).
fn emit_ch<'c: 'a, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
    e: Value<'c, 'a>,
    f: Value<'c, 'a>,
    g: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    let f_xor_g = emitter.emit_xor(f, g)?;
    let e_and = emitter.emit_and(e, f_xor_g)?;
    emitter.emit_xor(g, e_and)
}

/// Maj(a, b, c) = (a AND b) XOR (a AND c) XOR (b AND c) = (a AND b) XOR (c AND (a XOR b)).
fn emit_maj<'c: 'a, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
    a: Value<'c, 'a>,
    b: Value<'c, 'a>,
    c: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    let ab = emitter.emit_and(a, b)?;
    let a_xor_b = emitter.emit_xor(a, b)?;
    let c_and = emitter.emit_and(c, a_xor_b)?;
    emitter.emit_xor(ab, c_and)
}
