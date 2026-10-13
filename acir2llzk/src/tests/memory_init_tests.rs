use acir::{
    FieldElement,
    circuit::opcodes::{BlockId, BlockType, MemOp},
    circuit::{Circuit, Opcode},
    native_types::{Expression, Witness},
};
use llzk::prelude::{LlzkContext, LlzkModuleBuilder, StructType};

use crate::{FIELD_NAME, tests::print_and_verify_module};

use super::{make_circuit_with_opcodes, translate_single_circuit, with_public_constant_output};

fn memory_init(block_id: u32, init: &[u32], block_type: BlockType) -> Opcode<FieldElement> {
    Opcode::MemoryInit {
        block_id: BlockId(block_id),
        init: init.iter().map(|&w| Witness(w)).collect(),
        block_type,
    }
}

// Initialization-only fixtures use an independent constant public output, so
// the memory stays unread while the circuit remains PCL-compatible.

/// Returns the first initialized slot of each block as a public output, keeping
/// the initialization observable when the circuit is lowered to PCL.
fn circuit_with_memory_outputs(
    inputs: &[u32],
    mut opcodes: Vec<Opcode<FieldElement>>,
) -> Circuit<FieldElement> {
    let mut witness_index = *inputs.iter().max().unwrap();
    let mut outputs = Vec::new();
    let reads: Vec<_> = opcodes
        .iter()
        .map(|opcode| {
            let Opcode::MemoryInit { block_id, .. } = opcode else {
                panic!("expected a memory initialization");
            };
            witness_index += 1;
            outputs.push(witness_index);
            Opcode::MemoryOp {
                block_id: *block_id,
                op: MemOp::read_at_mem_index(Expression::zero(), Witness(witness_index)),
            }
        })
        .collect();
    opcodes.extend(reads);
    make_circuit_with_opcodes(witness_index, inputs, &[], &outputs, opcodes)
}

/// Single `MemoryInit` with 3 witnesses initializes all three slots.
#[test]
fn single_memory_init_three_witnesses() {
    let mut context = LlzkContext::new();
    context.set_field(FIELD_NAME);
    let module = LlzkModuleBuilder::new(&context)
        .with_language("Noir")
        .with_main(StructType::from_str(&context, "Circuit0"))
        .build();
    let opcodes = vec![memory_init(0, &[2, 3, 4], BlockType::Memory)];
    // witnesses 2, 3, 4 are inputs (private parameters)
    let circuit =
        with_public_constant_output(make_circuit_with_opcodes(4, &[2, 3, 4], &[], &[], opcodes));
    translate_single_circuit(&context, circuit, module.body()).unwrap();
    print_and_verify_module(&module, "single_memory_init_three_witnesses");
}

/// Two `MemoryInit` blocks with different `block_id`s → two distinct arrays.
#[test]
fn two_memory_init_blocks() {
    let mut context = LlzkContext::new();
    context.set_field(FIELD_NAME);
    let module = LlzkModuleBuilder::new(&context)
        .with_language("Noir")
        .with_main(StructType::from_str(&context, "Circuit0"))
        .build();
    let opcodes = vec![
        memory_init(0, &[2, 3], BlockType::Memory),
        memory_init(1, &[4, 5, 6], BlockType::Memory),
    ];
    let circuit = with_public_constant_output(make_circuit_with_opcodes(
        6,
        &[2, 3, 4, 5, 6],
        &[],
        &[],
        opcodes,
    ));
    translate_single_circuit(&context, circuit, module.body()).unwrap();
    print_and_verify_module(&module, "two_memory_init_blocks");
}

/// `MemoryInit` where init witnesses overlap with input parameters → values are read
/// from the function-argument cache, not from struct members.
#[test]
fn memory_init_witnesses_overlap_with_inputs() {
    let mut context = LlzkContext::new();
    context.set_field(FIELD_NAME);
    let module = LlzkModuleBuilder::new(&context)
        .with_language("Noir")
        .with_main(StructType::from_str(&context, "Circuit0"))
        .build();
    // Witnesses 0, 1, 2 are private inputs AND the init vector; no struct members for them.
    let opcodes = vec![memory_init(0, &[0, 1, 2], BlockType::Memory)];
    let circuit =
        with_public_constant_output(make_circuit_with_opcodes(2, &[0, 1, 2], &[], &[], opcodes));
    translate_single_circuit(&context, circuit, module.body()).unwrap();
    print_and_verify_module(&module, "memory_init_witnesses_overlap_with_inputs");
}

/// `BlockType::CallData` → treated identically to `Memory`.
#[test]
fn memory_init_call_data() {
    let mut context = LlzkContext::new();
    context.set_field(FIELD_NAME);
    let module = LlzkModuleBuilder::new(&context)
        .with_language("Noir")
        .with_main(StructType::from_str(&context, "Circuit0"))
        .build();
    let opcodes = vec![memory_init(0, &[0, 1, 2], BlockType::CallData(0))];
    let circuit =
        with_public_constant_output(make_circuit_with_opcodes(2, &[0, 1, 2], &[], &[], opcodes));
    translate_single_circuit(&context, circuit, module.body()).unwrap();
    print_and_verify_module(&module, "memory_init_call_data");
}

/// `BlockType::ReturnData` → treated identically to `Memory`.
#[test]
fn memory_init_return_data() {
    let mut context = LlzkContext::new();
    context.set_field(FIELD_NAME);
    let module = LlzkModuleBuilder::new(&context)
        .with_language("Noir")
        .with_main(StructType::from_str(&context, "Circuit0"))
        .build();
    let opcodes = vec![memory_init(0, &[0, 1, 2], BlockType::ReturnData)];
    let circuit =
        with_public_constant_output(make_circuit_with_opcodes(2, &[0, 1, 2], &[], &[], opcodes));
    translate_single_circuit(&context, circuit, module.body()).unwrap();
    print_and_verify_module(&module, "memory_init_return_data");
}

/// Mixed block types coexist — each gets its own array.
#[test]
fn memory_init_mixed_block_types() {
    let mut context = LlzkContext::new();
    context.set_field(FIELD_NAME);
    let module = LlzkModuleBuilder::new(&context)
        .with_language("Noir")
        .with_main(StructType::from_str(&context, "Circuit0"))
        .build();
    let opcodes = vec![
        memory_init(0, &[0, 1], BlockType::CallData(0)),
        memory_init(1, &[2, 3, 4], BlockType::Memory),
        memory_init(2, &[5, 6], BlockType::ReturnData),
    ];
    let circuit = with_public_constant_output(make_circuit_with_opcodes(
        6,
        &[0, 1, 2, 3, 4, 5, 6],
        &[],
        &[],
        opcodes,
    ));
    translate_single_circuit(&context, circuit, module.body()).unwrap();
    print_and_verify_module(&module, "memory_init_mixed_block_types");
}

/// Separately exercise initialization followed by reads for all block types.
#[test]
fn initialized_memory_outputs_lower_to_pcl() {
    let mut context = LlzkContext::new();
    context.set_field(FIELD_NAME);
    let module = LlzkModuleBuilder::new(&context)
        .with_language("Noir")
        .with_main(StructType::from_str(&context, "Circuit0"))
        .build();
    let opcodes = vec![
        memory_init(0, &[0, 1], BlockType::CallData(0)),
        memory_init(1, &[2, 3, 4], BlockType::Memory),
        memory_init(2, &[5, 6], BlockType::ReturnData),
    ];
    let circuit = circuit_with_memory_outputs(&[0, 1, 2, 3, 4, 5, 6], opcodes);
    translate_single_circuit(&context, circuit, module.body()).unwrap();
    print_and_verify_module(&module, "initialized_memory_outputs_lower_to_pcl");
}
