use llzk::{
    builder::{BlockInsertPointLike, OpBuilder},
    dialect::array::{ArrayCtor, ArrayType},
    prelude::{
        dialect::{self, array, cast, felt, function},
        Block, BlockLike, BlockRef, FuncDefOp, FuncDefOpLike, FunctionType, LlzkContext, Location,
        OperationLike, RegionLike, Value,
    },
};

use crate::{
    blackboxes::common::{
        append_op_with_result, block_args, block_args_slice, create_helper_function, felt_type,
        ConstantCache, WordArithEmitter,
    },
    common::as_value,
    error::Error,
};

pub(crate) const AES_BLOCK_SIZE: usize = 16;
const AES128_ROUNDS: usize = 10;
const AES_COLUMNS: usize = 4;
const AES_WORD_BYTES: usize = 4;
const AES128_EXPANDED_KEY_WORDS: usize = AES_COLUMNS * (AES128_ROUNDS + 1);
const SBOX_SIZE: usize = 256;
const BYTE_MASK: u32 = 0xFF;
// GF(2^8) reduction polynomial x^8 + x^4 + x^3 + x + 1.
const GF_REDUCTION: u32 = 0x1B;

pub(in crate::blackboxes) fn aes128_helper_name(num_inputs: usize) -> String {
    format!("aes128_encrypt_{num_inputs}")
}

pub(in crate::blackboxes) fn emit_aes128_helper<'c>(
    context: &'c LlzkContext,
    block: BlockRef<'c, '_>,
    num_inputs: usize,
) -> Result<(), Error> {
    let location = Location::unknown(context);
    let total_inputs = num_inputs + AES_BLOCK_SIZE + AES_BLOCK_SIZE;
    let (function, block) = create_helper_function(
        context,
        block,
        location,
        &aes128_helper_name(num_inputs),
        total_inputs,
        num_inputs,
    )?;
    function.set_allow_non_native_field_ops_attr(true);

    let plaintext = block_args_slice(block, 0..num_inputs)?;
    let iv = block_args::<AES_BLOCK_SIZE>(&block, num_inputs)?;
    let key = block_args::<AES_BLOCK_SIZE>(&block, num_inputs + AES_BLOCK_SIZE)?;

    let mut emitter = WordArithEmitter::new(block, context, location);
    let sbox_array = emit_sbox_array(&mut emitter)?;
    let round_keys = emit_key_expansion(&mut emitter, &key, sbox_array)?;
    let outputs = emit_cbc_encrypt(&mut emitter, &plaintext, &iv, &round_keys, sbox_array)?;

    function::r#return(&OpBuilder::at_block_end(context, block), location, &outputs);
    Ok(())
}

// ── S-box ───────────────────────────────────────────────────────────────

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const RCON: [u32; 10] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000,
];

fn emit_sbox_array<'c: 'a, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
) -> Result<Value<'c, 'a>, Error> {
    let felt = emitter.context.felt_type();
    let array_type = ArrayType::new_with_dims(felt.into(), &[SBOX_SIZE as i64]);
    let values = emitter.u32s(SBOX)?;
    as_value(array::new(
        emitter.builder(),
        emitter.location,
        array_type,
        ArrayCtor::Values(&values),
    ))
}

fn emit_sbox_lookup<'c: 'a, 'a>(
    cache: &ConstantCache<'c, 'a, '_>,
    sbox_array: Value<'c, 'a>,
    input: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    let idx = as_value(cast::toindex(cache.builder(), cache.location, input, None))?;
    let felt = cache.context.felt_type();
    as_value(array::read(
        cache.builder(),
        cache.location,
        felt.into(),
        sbox_array,
        &[idx],
    ))
}

// ── Byte/word helpers ───────────────────────────────────────────────────

fn emit_byte<'c: 'a, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
    word: Value<'c, 'a>,
    pos: u32,
) -> Result<Value<'c, 'a>, Error> {
    let shifted = if pos == 0 {
        word
    } else {
        emitter.emit_shr(word, pos * 8)?
    };
    let mask = emitter.u32(BYTE_MASK)?;
    emitter.emit_and(shifted, mask)
}

fn emit_pack_u32<'c: 'a, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
    bytes: [Value<'c, 'a>; AES_WORD_BYTES],
) -> Result<Value<'c, 'a>, Error> {
    let [b0, b1, b2, b3] = bytes;
    let s0 = emitter.emit_shl(b0, 24)?;
    let s1 = emitter.emit_shl(b1, 16)?;
    let s2 = emitter.emit_shl(b2, 8)?;
    let r = emitter.emit_xor(s0, s1)?;
    let r = emitter.emit_xor(r, s2)?;
    emitter.emit_xor(r, b3)
}

// ── xtime (GF(2^8) multiply by 2) ──────────────────────────────────────

fn emit_xtime<'c: 'a, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
    value: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    let shifted = emitter.emit_shl(value, 1)?;
    let byte_mask = emitter.u32(BYTE_MASK)?;
    let shifted = emitter.emit_and(shifted, byte_mask)?;
    let high_bit = emitter.emit_shr(value, 7)?;
    let one = emitter.u32(1)?;
    let high_bit = emitter.emit_and(high_bit, one)?;
    let reduction_const = emitter.u32(GF_REDUCTION)?;
    let reduction = as_value(felt::mul(
        emitter.builder(),
        emitter.location,
        high_bit,
        reduction_const,
    )?)?;
    emitter.emit_xor(shifted, reduction)
}

// Precomputed GF(2^8) products of a byte b: [b*1, b*2, b*3]. MixColumns uses
// only coefficients 1/2/3, so precomputing x2 and x3 once amortises `emit_xtime`
// across the four rows of `emit_mix_byte`.
#[derive(Clone, Copy)]
struct GfProducts<'c, 'a> {
    x1: Value<'c, 'a>,
    x2: Value<'c, 'a>,
    x3: Value<'c, 'a>,
}

fn emit_gf_products<'c: 'a, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
    x1: Value<'c, 'a>,
) -> Result<GfProducts<'c, 'a>, Error> {
    let x2 = emit_xtime(emitter, x1)?;
    let x3 = emitter.emit_xor(x2, x1)?;
    Ok(GfProducts { x1, x2, x3 })
}

fn gf_pick<'c, 'a>(products: GfProducts<'c, 'a>, coeff: u8) -> Value<'c, 'a> {
    match coeff {
        1 => products.x1,
        2 => products.x2,
        3 => products.x3,
        _ => unreachable!("AES MixColumns coefficients are 1, 2, or 3"),
    }
}

// ── Key expansion ───────────────────────────────────────────────────────

// Computes 11 byte-form round keys (16 bytes each) from the 16-byte key.
// Internally builds 44 u32 words for efficient wide XORs during expansion,
// then extracts to bytes once so AddRoundKey can stay on byte state.
fn emit_key_expansion<'c: 'a, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
    key: &[Value<'c, 'a>],
    sbox: Value<'c, 'a>,
) -> Result<Vec<[Value<'c, 'a>; AES_BLOCK_SIZE]>, Error> {
    let mut rk = Vec::with_capacity(AES128_EXPANDED_KEY_WORDS);
    for i in 0..AES_COLUMNS {
        rk.push(emit_pack_u32(
            emitter,
            [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]],
        )?);
    }

    for i in 0..AES128_ROUNDS {
        let temp = rk[3 + i * 4];
        let byte2 = emit_byte(emitter, temp, 2)?;
        let b0 = emit_sbox_lookup(emitter, sbox, byte2)?;
        let byte1 = emit_byte(emitter, temp, 1)?;
        let b1 = emit_sbox_lookup(emitter, sbox, byte1)?;
        let byte0 = emit_byte(emitter, temp, 0)?;
        let b2 = emit_sbox_lookup(emitter, sbox, byte0)?;
        let byte3 = emit_byte(emitter, temp, 3)?;
        let b3 = emit_sbox_lookup(emitter, sbox, byte3)?;
        let sub_rot = emit_pack_u32(emitter, [b0, b1, b2, b3])?;
        let rcon = emitter.u32(RCON[i])?;
        let w = emitter.emit_xor(rk[i * 4], sub_rot)?;
        let w = emitter.emit_xor(w, rcon)?;
        rk.push(w);
        for j in 1..AES_COLUMNS {
            let prev = rk[i * 4 + j];
            let last = *rk.last().unwrap();
            let w = emitter.emit_xor(prev, last)?;
            rk.push(w);
        }
    }

    let mut round_keys = Vec::with_capacity(AES128_ROUNDS + 1);
    for round in 0..=AES128_ROUNDS {
        let mut bytes = [rk[0]; AES_BLOCK_SIZE];
        for col in 0..AES_COLUMNS {
            let word = rk[round * 4 + col];
            bytes[4 * col] = emit_byte(emitter, word, 3)?;
            bytes[4 * col + 1] = emit_byte(emitter, word, 2)?;
            bytes[4 * col + 2] = emit_byte(emitter, word, 1)?;
            bytes[4 * col + 3] = emit_byte(emitter, word, 0)?;
        }
        round_keys.push(bytes);
    }
    Ok(round_keys)
}

// ── AES block encrypt ───────────────────────────────────────────────────

// State layout: state[4 * col + row], i.e. byte index = row + 4*col (FIPS 197 §3.4).
fn emit_aes_block_encrypt<'c: 'a, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
    block_bytes: &[Value<'c, 'a>; AES_BLOCK_SIZE],
    round_keys: &[[Value<'c, 'a>; AES_BLOCK_SIZE]],
    sbox: Value<'c, 'a>,
) -> Result<[Value<'c, 'a>; AES_BLOCK_SIZE], Error> {
    let mut s = add_round_key(emitter, block_bytes, &round_keys[0])?;

    for round_key in round_keys.iter().take(AES128_ROUNDS).skip(1) {
        let mut t = [s[0]; AES_BLOCK_SIZE];
        for col in 0..AES_COLUMNS {
            let [r0, r1, r2, r3] = emit_mix_column(emitter, sbox, &s, col)?;
            t[4 * col] = r0;
            t[4 * col + 1] = r1;
            t[4 * col + 2] = r2;
            t[4 * col + 3] = r3;
        }
        s = add_round_key(emitter, &t, round_key)?;
    }

    let mut out = [s[0]; AES_BLOCK_SIZE];
    for col in 0..AES_COLUMNS {
        let [b0, b1, b2, b3] = emit_sub_shift_column(emitter, sbox, &s, col)?;
        out[4 * col] = b0;
        out[4 * col + 1] = b1;
        out[4 * col + 2] = b2;
        out[4 * col + 3] = b3;
    }
    add_round_key(emitter, &out, &round_keys[AES128_ROUNDS])
}

fn add_round_key<'c: 'a, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
    state: &[Value<'c, 'a>; AES_BLOCK_SIZE],
    round_key: &[Value<'c, 'a>; AES_BLOCK_SIZE],
) -> Result<[Value<'c, 'a>; AES_BLOCK_SIZE], Error> {
    let mut out = [state[0]; AES_BLOCK_SIZE];
    for i in 0..AES_BLOCK_SIZE {
        out[i] = emitter.emit_xor(state[i], round_key[i])?;
    }
    Ok(out)
}

// SubBytes + ShiftRows for one output column: pulls bytes from the diagonal
// pre-shift positions and S-boxes each. state[4*c + r] is column c, row r.
fn emit_sub_shift_column<'c: 'a, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
    sbox: Value<'c, 'a>,
    state: &[Value<'c, 'a>; AES_BLOCK_SIZE],
    col: usize,
) -> Result<[Value<'c, 'a>; AES_COLUMNS], Error> {
    let s0 = emit_sbox_lookup(emitter, sbox, state[4 * col])?;
    let s1 = emit_sbox_lookup(emitter, sbox, state[4 * ((col + 1) % AES_COLUMNS) + 1])?;
    let s2 = emit_sbox_lookup(emitter, sbox, state[4 * ((col + 2) % AES_COLUMNS) + 2])?;
    let s3 = emit_sbox_lookup(emitter, sbox, state[4 * ((col + 3) % AES_COLUMNS) + 3])?;
    Ok([s0, s1, s2, s3])
}

fn emit_mix_column<'c: 'a, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
    sbox: Value<'c, 'a>,
    state: &[Value<'c, 'a>; AES_BLOCK_SIZE],
    col: usize,
) -> Result<[Value<'c, 'a>; AES_COLUMNS], Error> {
    let state_bytes = emit_sub_shift_column(emitter, sbox, state, col)?;
    let products = [
        emit_gf_products(emitter, state_bytes[0])?,
        emit_gf_products(emitter, state_bytes[1])?,
        emit_gf_products(emitter, state_bytes[2])?,
        emit_gf_products(emitter, state_bytes[3])?,
    ];
    // MixColumns matrix: [2,3,1,1; 1,2,3,1; 1,1,2,3; 3,1,1,2]
    let r0 = emit_mix_byte(emitter, &products, [2, 3, 1, 1])?;
    let r1 = emit_mix_byte(emitter, &products, [1, 2, 3, 1])?;
    let r2 = emit_mix_byte(emitter, &products, [1, 1, 2, 3])?;
    let r3 = emit_mix_byte(emitter, &products, [3, 1, 1, 2])?;
    Ok([r0, r1, r2, r3])
}

fn emit_mix_byte<'c: 'a, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
    products: &[GfProducts<'c, 'a>; AES_COLUMNS],
    coeffs: [u8; AES_COLUMNS],
) -> Result<Value<'c, 'a>, Error> {
    let t0 = gf_pick(products[0], coeffs[0]);
    let t1 = gf_pick(products[1], coeffs[1]);
    let t2 = gf_pick(products[2], coeffs[2]);
    let t3 = gf_pick(products[3], coeffs[3]);
    let r = emitter.emit_xor(t0, t1)?;
    let r = emitter.emit_xor(r, t2)?;
    emitter.emit_xor(r, t3)
}

// ── CBC encrypt ─────────────────────────────────────────────────────────

fn emit_cbc_encrypt<'c: 'a, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
    plaintext: &[Value<'c, 'a>],
    iv: &[Value<'c, 'a>],
    round_keys: &[[Value<'c, 'a>; AES_BLOCK_SIZE]],
    sbox: Value<'c, 'a>,
) -> Result<Vec<Value<'c, 'a>>, Error> {
    let num_blocks = plaintext.len() / AES_BLOCK_SIZE;
    let mut prev_block: [Value<'c, 'a>; AES_BLOCK_SIZE] =
        iv.try_into().expect("IV must be 16 bytes");
    let mut ciphertext = Vec::with_capacity(plaintext.len());

    for block_idx in 0..num_blocks {
        let start = block_idx * AES_BLOCK_SIZE;
        let mut block = [prev_block[0]; AES_BLOCK_SIZE];
        for i in 0..AES_BLOCK_SIZE {
            block[i] = emitter.emit_xor(plaintext[start + i], prev_block[i])?;
        }
        let encrypted = emit_aes_block_encrypt(emitter, &block, round_keys, sbox)?;
        ciphertext.extend_from_slice(&encrypted);
        prev_block = encrypted;
    }
    Ok(ciphertext)
}
