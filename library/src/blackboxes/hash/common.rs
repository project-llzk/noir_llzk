use llzk::prelude::Value;

use crate::{
    blackboxes::common::{
        ConstantCache, emit_rotr, emit_wrapping_add, emit_wrapping_sum, emit_xor,
    },
    error::Error,
};

// ── G mixing function (shared by Blake2s and Blake3) ────────────────────

pub(super) fn emit_g<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    v: &mut [Value<'c, 'a>; 16],
    (a, b, c, d): (usize, usize, usize, usize),
    x: Value<'c, 'a>,
    y: Value<'c, 'a>,
) -> Result<(), Error> {
    v[a] = emit_wrapping_sum(cache, &[v[a], v[b], x])?;
    v[d] = emit_rotr(
        cache,
        emit_xor(cache.block, cache.location, v[d], v[a])?,
        16,
    )?;
    v[c] = emit_wrapping_add(cache, v[c], v[d])?;
    v[b] = emit_rotr(
        cache,
        emit_xor(cache.block, cache.location, v[b], v[c])?,
        12,
    )?;
    v[a] = emit_wrapping_sum(cache, &[v[a], v[b], y])?;
    v[d] = emit_rotr(cache, emit_xor(cache.block, cache.location, v[d], v[a])?, 8)?;
    v[c] = emit_wrapping_add(cache, v[c], v[d])?;
    v[b] = emit_rotr(cache, emit_xor(cache.block, cache.location, v[b], v[c])?, 7)?;
    Ok(())
}

/// Runs one round of column + diagonal mixing on the work vector.
pub(super) fn emit_round<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    v: &mut [Value<'c, 'a>; 16],
    m: &[Value<'c, 'a>; 16],
    schedule: &[usize; 16],
) -> Result<(), Error> {
    emit_g(cache, v, (0, 4, 8, 12), m[schedule[0]], m[schedule[1]])?;
    emit_g(cache, v, (1, 5, 9, 13), m[schedule[2]], m[schedule[3]])?;
    emit_g(cache, v, (2, 6, 10, 14), m[schedule[4]], m[schedule[5]])?;
    emit_g(cache, v, (3, 7, 11, 15), m[schedule[6]], m[schedule[7]])?;
    emit_g(cache, v, (0, 5, 10, 15), m[schedule[8]], m[schedule[9]])?;
    emit_g(cache, v, (1, 6, 11, 12), m[schedule[10]], m[schedule[11]])?;
    emit_g(cache, v, (2, 7, 8, 13), m[schedule[12]], m[schedule[13]])?;
    emit_g(cache, v, (3, 4, 9, 14), m[schedule[14]], m[schedule[15]])?;
    Ok(())
}

// ── IV constants (shared by Blake2s and Blake3) ─────────────────────────

pub(super) const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

pub(super) fn iv_values<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
) -> Result<[Value<'c, 'a>; 8], Error> {
    let mut values = Vec::with_capacity(8);
    for word in IV {
        values.push(cache.u32(word)?);
    }
    Ok(values.try_into().expect("exactly eight IV words"))
}
