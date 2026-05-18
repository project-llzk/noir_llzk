use llzk::prelude::{
    Block, BlockLike, FuncDefOp, FuncDefOpLike, FunctionType, Location, OperationLike, RegionLike,
    Value, dialect,
};

use crate::{
    blackboxes::common::{ConstantCache, block_args, emit_and, emit_rotl64, emit_xor, felt_type},
    error::Error,
};

pub(crate) const KECCAK_STATE_WORDS: usize = 25;
const KECCAK_ROUNDS: usize = 24;
const LANE_DIM: usize = 5;

pub(in crate::blackboxes) const KECCAK_HELPER_NAME: &str = "keccakf1600";

const RC: [u64; KECCAK_ROUNDS] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

const ROT_OFFSETS: [[u32; LANE_DIM]; LANE_DIM] = [
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14],
];

pub(in crate::blackboxes) fn emit_keccak_helper<'c>(
    context: &'c llzk::prelude::LlzkContext,
) -> Result<FuncDefOp<'c>, Error> {
    let location = Location::unknown(context);
    let felt = felt_type(context);
    let inputs = vec![(felt, location); KECCAK_STATE_WORDS];
    let input_types = vec![felt; KECCAK_STATE_WORDS];
    let output_types = vec![felt; KECCAK_STATE_WORDS];
    let function_type = FunctionType::new(context, &input_types, &output_types);
    let function = dialect::function::def(location, KECCAK_HELPER_NAME, function_type, &[], None)?;
    function.set_allow_non_native_field_ops_attr(true);

    let block = Block::new(&inputs);
    let state: [Value<'c, '_>; KECCAK_STATE_WORDS] = block_args(&block, 0)?;

    let mut cache = ConstantCache::new(&block, context, location);
    let outputs = emit_keccak_permutation(&mut cache, &state)?;
    block.append_operation(dialect::function::r#return(location, &outputs));
    function.region(0)?.append_block(block);
    Ok(function)
}

#[allow(clippy::needless_range_loop)]
fn emit_keccak_permutation<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    state: &[Value<'c, 'a>],
) -> Result<Vec<Value<'c, 'a>>, Error> {
    let mut a: [[Value<'c, 'a>; LANE_DIM]; LANE_DIM] = {
        let zero = cache.u64(0)?;
        [[zero; LANE_DIM]; LANE_DIM]
    };
    for y in 0..LANE_DIM {
        for x in 0..LANE_DIM {
            a[x][y] = state[x + LANE_DIM * y];
        }
    }

    for round in 0..KECCAK_ROUNDS {
        a = emit_round(cache, a, round)?;
    }

    let mut out = Vec::with_capacity(KECCAK_STATE_WORDS);
    for y in 0..LANE_DIM {
        for x in 0..LANE_DIM {
            out.push(a[x][y]);
        }
    }
    Ok(out)
}

#[allow(clippy::needless_range_loop)]
fn emit_round<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    mut a: [[Value<'c, 'a>; LANE_DIM]; LANE_DIM],
    round: usize,
) -> Result<[[Value<'c, 'a>; LANE_DIM]; LANE_DIM], Error> {
    let mask = cache.u64_mask()?;

    let mut c = [cache.u64(0)?; LANE_DIM];
    for x in 0..LANE_DIM {
        c[x] = a[x][0];
        for y in 1..LANE_DIM {
            c[x] = emit_xor(cache.block, cache.location, c[x], a[x][y])?;
        }
    }
    let mut d = [cache.u64(0)?; LANE_DIM];
    for x in 0..LANE_DIM {
        let rot = emit_rotl64(cache, c[(x + 1) % LANE_DIM], 1)?;
        d[x] = emit_xor(cache.block, cache.location, c[(x + 4) % LANE_DIM], rot)?;
    }
    for x in 0..LANE_DIM {
        for y in 0..LANE_DIM {
            a[x][y] = emit_xor(cache.block, cache.location, a[x][y], d[x])?;
        }
    }

    let mut b = [[cache.u64(0)?; LANE_DIM]; LANE_DIM];
    for x in 0..LANE_DIM {
        for y in 0..LANE_DIM {
            let rotated = if ROT_OFFSETS[y][x] == 0 {
                a[x][y]
            } else {
                emit_rotl64(cache, a[x][y], ROT_OFFSETS[y][x])?
            };
            b[y][(2 * x + 3 * y) % LANE_DIM] = rotated;
        }
    }

    // χ: a[x][y] = b[x][y] ^ (~b[(x+1)%5][y] & b[(x+2)%5][y])
    for x in 0..LANE_DIM {
        for y in 0..LANE_DIM {
            let not_b1 = emit_not(cache, b[(x + 1) % LANE_DIM][y], mask)?;
            let and_val = emit_and(
                cache.block,
                cache.location,
                not_b1,
                b[(x + 2) % LANE_DIM][y],
            )?;
            a[x][y] = emit_xor(cache.block, cache.location, b[x][y], and_val)?;
        }
    }

    let rc = cache.u64(RC[round])?;
    a[0][0] = emit_xor(cache.block, cache.location, a[0][0], rc)?;

    Ok(a)
}

fn emit_not<'c, 'a>(
    cache: &mut ConstantCache<'c, 'a>,
    value: Value<'c, 'a>,
    mask: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    emit_xor(cache.block, cache.location, value, mask)
}
