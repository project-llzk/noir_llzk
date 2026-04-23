//! Unit tests for the Brillig CFG label map ([`crate::opcodes::brillig::cfg`]).

use acir::FieldElement;
use acir::brillig::{Label, MemoryAddress, Opcode as BrilligOpcode};

use crate::opcodes::brillig::cfg::{BlockId, LabelMap};

use super::brillig_stop;

fn jump(location: Label) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Jump { location }
}

fn jump_if(location: Label) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::JumpIf {
        condition: MemoryAddress::Direct(0),
        location,
    }
}

fn call(location: Label) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Call { location }
}

#[test]
fn empty_bytecode_has_only_entry_block() {
    let map = LabelMap::build(&[]);
    assert_eq!(map.len(), 1);
    assert_eq!(map.get(0), Some(BlockId(0)));
}

#[test]
fn straight_line_bytecode_has_only_entry_block() {
    let map = LabelMap::build(&[brillig_stop()]);
    assert_eq!(map.len(), 1);
    assert_eq!(map.get(0), Some(BlockId(0)));
    assert_eq!(map.get(1), None);
}

#[test]
fn jump_target_gets_fresh_block_id() {
    //  0: Jump 2
    //  1: <dead>
    //  2: Stop
    let map = LabelMap::build(&[jump(2), brillig_stop(), brillig_stop()]);
    assert_eq!(map.len(), 2);
    assert_eq!(map.get(0), Some(BlockId(0)));
    assert_eq!(map.get(2), Some(BlockId(1)));
    assert_eq!(map.get(1), None);
}

#[test]
fn jump_if_pair_allocates_both_targets() {
    //  0: JumpIf cond, 3    (then)
    //  1: Jump 5            (else)
    //  2..4: then-body
    //  5..: join
    let map = LabelMap::build(&[
        jump_if(3),
        jump(5),
        brillig_stop(),
        brillig_stop(),
        brillig_stop(),
        brillig_stop(),
    ]);
    assert_eq!(map.len(), 3);
    assert_eq!(map.get(0), Some(BlockId(0)));
    assert_eq!(map.get(3), Some(BlockId(1)));
    assert_eq!(map.get(5), Some(BlockId(2)));
}

#[test]
fn call_target_gets_fresh_block_id() {
    let map = LabelMap::build(&[call(2), brillig_stop(), brillig_stop()]);
    assert_eq!(map.len(), 2);
    assert_eq!(map.get(2), Some(BlockId(1)));
}

#[test]
fn duplicate_targets_share_a_single_block_id() {
    //  0: Jump 3
    //  1: Jump 3
    //  2: JumpIf cond, 3
    //  3: Stop
    let map = LabelMap::build(&[jump(3), jump(3), jump_if(3), brillig_stop()]);
    assert_eq!(map.len(), 2);
    let id = map.get(3).expect("target 3 must be mapped");
    assert_eq!(id, BlockId(1));
}

#[test]
fn jump_to_entry_reuses_entry_block_id() {
    //  0: Stop
    //  1: Jump 0     // back-edge to entry
    let map = LabelMap::build(&[brillig_stop(), jump(0)]);
    assert_eq!(map.len(), 1);
    assert_eq!(map.get(0), Some(BlockId(0)));
}

#[test]
fn block_ids_allocated_in_first_seen_order() {
    //  0: Jump 4
    //  1: Jump 2
    //  2: Jump 3
    //  3: Stop
    //  4: Jump 1
    let map = LabelMap::build(&[jump(4), jump(2), jump(3), brillig_stop(), jump(1)]);
    assert_eq!(map.get(0), Some(BlockId(0)));
    assert_eq!(map.get(4), Some(BlockId(1)));
    assert_eq!(map.get(2), Some(BlockId(2)));
    assert_eq!(map.get(3), Some(BlockId(3)));
    assert_eq!(map.get(1), Some(BlockId(4)));
}
