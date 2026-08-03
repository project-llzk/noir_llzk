use llzk::{
    builder::OpBuilder,
    prelude::{
        dialect::{self, function},
        Block, BlockLike, FuncDefOp, FuncDefOpLike, FunctionType, LlzkContext, Location,
        OperationLike, RegionLike, Value,
    },
};

use crate::{
    blackboxes::common::{
        block_args, create_helper_function, emit_and, emit_rotl64, emit_xor, felt_type,
        BitwiseEmitter, ConstantCache, WordArithEmitter,
    },
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
    context: &'c LlzkContext,
    block: BlockRef<'c>,
) -> Result<(), Error> {
    let location = Location::unknown(context);
    let (function, block) = create_helper_function(
        context,
        block,
        location,
        KECCAK_HELPER_NAME,
        KECCAK_STATE_WORDS,
        KECCAK_STATE_WORDS,
    )?;
    function.set_allow_non_native_field_ops_attr(true);

    let state: [Value<'c, '_>; KECCAK_STATE_WORDS] = block_args(&block, 0)?;

    let mut cache = WordArithEmitter::new(block, context, location);
    let outputs = emit_keccak_permutation(&mut cache, &state)?;
    function::r#return(&OpBuilder::at_block_end(context, block), location, &outputs);
    Ok(())
}

#[allow(clippy::needless_range_loop)]
fn emit_keccak_permutation<'c: 'a, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
    state: &[Value<'c, 'a>],
) -> Result<Vec<Value<'c, 'a>>, Error> {
    let mut a: [[Value<'c, 'a>; LANE_DIM]; LANE_DIM] = {
        let zero = emitter.u64(0)?;
        [[zero; LANE_DIM]; LANE_DIM]
    };
    for y in 0..LANE_DIM {
        for x in 0..LANE_DIM {
            a[x][y] = state[x + LANE_DIM * y];
        }
    }

    for round in 0..KECCAK_ROUNDS {
        a = emit_round(emitter, a, round)?;
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
fn emit_round<'c: 'a, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
    mut a: [[Value<'c, 'a>; LANE_DIM]; LANE_DIM],
    round: usize,
) -> Result<[[Value<'c, 'a>; LANE_DIM]; LANE_DIM], Error> {
    let mask = emitter.u64_mask()?;

    let mut c = [emitter.u64(0)?; LANE_DIM];
    for x in 0..LANE_DIM {
        c[x] = a[x][0];
        for y in 1..LANE_DIM {
            c[x] = emitter.emit_xor(c[x], a[x][y])?;
        }
    }
    let mut d = [emitter.u64(0)?; LANE_DIM];
    for x in 0..LANE_DIM {
        let rot = emitter.emit_rotl64(c[(x + 1) % LANE_DIM], 1)?;
        d[x] = emitter.emit_xor(c[(x + 4) % LANE_DIM], rot)?;
    }
    for x in 0..LANE_DIM {
        for y in 0..LANE_DIM {
            a[x][y] = emitter.emit_xor(a[x][y], d[x])?;
        }
    }

    let mut b = [[emitter.u64(0)?; LANE_DIM]; LANE_DIM];
    for x in 0..LANE_DIM {
        for y in 0..LANE_DIM {
            let rotated = if ROT_OFFSETS[y][x] == 0 {
                a[x][y]
            } else {
                emitter.emit_rotl64(a[x][y], ROT_OFFSETS[y][x])?
            };
            b[y][(2 * x + 3 * y) % LANE_DIM] = rotated;
        }
    }

    // χ: a[x][y] = b[x][y] ^ (~b[(x+1)%5][y] & b[(x+2)%5][y])
    for x in 0..LANE_DIM {
        for y in 0..LANE_DIM {
            let not_b1 = emit_not(emitter, b[(x + 1) % LANE_DIM][y], mask)?;
            let and_val = emitter.emit_and(not_b1, b[(x + 2) % LANE_DIM][y])?;
            a[x][y] = emitter.emit_xor(b[x][y], and_val)?;
        }
    }

    let rc = emitter.u64(RC[round])?;
    a[0][0] = emitter.emit_xor(a[0][0], rc)?;

    Ok(a)
}

fn emit_not<'c, 'a>(
    emitter: &mut WordArithEmitter<'c, 'a, '_>,
    value: Value<'c, 'a>,
    mask: Value<'c, 'a>,
) -> Result<Value<'c, 'a>, Error> {
    emitter.emit_xor(value, mask)
}
