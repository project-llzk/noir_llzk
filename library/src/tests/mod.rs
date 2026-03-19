use acir::circuit::Opcode;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::circuit::{Circuit, Program, PublicInputs};
use acir::native_types::{Expression, Witness};
use acir::{AcirField, FieldElement};
use llzk::prelude::{
    BlockLike, BlockRef, FlatSymbolRefAttribute, LlzkContext, Location, Module, OperationLike,
    OperationMutLike, OperationRef, StringAttribute, StructDefOp, StructDefOpRef, StructType,
    TypeAttribute, llzk_module,
};
use llzk_sys::{LANG_ATTR_NAME, MAIN_ATTR_NAME};

use crate::circuit::CircuitTranslator;

mod bitwise;
mod call_tests;
mod circuit_tests;
mod compute_tests;
mod constrain_tests;
mod integration_tests;
mod memory_init_tests;
mod memory_op_tests;

/// Helper to build a Circuit with specified witness count, private params,
/// public params, and return values.
fn make_circuit(
    current_witness_index: u32,
    private: &[u32],
    public: &[u32],
    returns: &[u32],
) -> Circuit<FieldElement> {
    make_circuit_with_opcodes(current_witness_index, private, public, returns, vec![])
}

fn make_program(circuits: Vec<Circuit<FieldElement>>) -> Program<FieldElement> {
    Program {
        functions: circuits,
        unconstrained_functions: vec![],
    }
}

/// Helper to build a circuit with the given opcodes.
///
/// `current_witness_index` is the **inclusive** upper bound of the witness index range for
/// this circuit, as required by the ACIR `Circuit` struct. It must be at least as large as
/// the highest witness index referenced in `private`, `public`, `returns`, or any opcode
/// operand. Struct members are only emitted for witnesses actually referenced by opcodes.
fn make_circuit_with_opcodes(
    current_witness_index: u32,
    private: &[u32],
    public: &[u32],
    returns: &[u32],
    opcodes: Vec<Opcode<FieldElement>>,
) -> Circuit<FieldElement> {
    Circuit {
        function_name: "test".to_string(),
        current_witness_index,
        opcodes,
        private_parameters: private.iter().map(|&i| Witness(i)).collect(),
        public_parameters: PublicInputs(public.iter().map(|&i| Witness(i)).collect()),
        return_values: PublicInputs(returns.iter().map(|&i| Witness(i)).collect()),
        assert_messages: vec![],
    }
}

/// Convenience wrapper used by tests that translate a single circuit in isolation.
///
/// Creates a single-circuit [`Program`] internally so that [`CircuitTranslator`]
/// has the program reference it needs for future `Call` opcode support.
/// Returns only the circuit struct def (first element of the translation result).
pub(super) fn translate_single_circuit<'c>(
    context: &'c LlzkContext,
    circuit: Circuit<FieldElement>,
) -> Result<StructDefOp<'c>, crate::Error> {
    let program = make_program(vec![circuit]);
    let mut structs =
        CircuitTranslator::new(context, &program.functions[0], &program).translate(0)?;
    // The circuit struct is always the last element; auxiliaries come first.
    Ok(structs.pop().unwrap())
}

/// Translates a single circuit and wraps all resulting struct defs in a module.
///
/// Unlike [`translate_single_circuit`], this includes auxiliary struct defs
/// (`MemRead_{N}`, `MemWrite_{N}`) that memory operations depend on.
fn translate_circuit_to_module<'c>(
    context: &'c LlzkContext,
    circuit: Circuit<FieldElement>,
) -> Result<Module<'c>, crate::Error> {
    let program = make_program(vec![circuit]);
    let struct_defs =
        CircuitTranslator::new(context, &program.functions[0], &program).translate(0)?;
    Ok(wrap_structs_in_module(context, struct_defs))
}

/// Wraps multiple `StructDefOp`s in a new LLZK module with required attributes.
fn wrap_structs_in_module<'c>(
    context: &'c LlzkContext,
    struct_defs: Vec<StructDefOp<'c>>,
) -> Module<'c> {
    let location = Location::unknown(context);
    let mut module = llzk_module(location);
    module.as_operation_mut().set_attribute(
        MAIN_ATTR_NAME.as_ref(),
        TypeAttribute::new(
            StructType::new(FlatSymbolRefAttribute::new(context, "Circuit0"), &[]).into(),
        )
        .into(),
    );
    module.as_operation_mut().set_attribute(
        LANG_ATTR_NAME.as_ref(),
        StringAttribute::new(context, "ACIR").into(),
    );
    for s in struct_defs {
        module.body().append_operation(s.into());
    }
    module
}

/// Wraps a `StructDefOp` in a module, prints the IR, and asserts verification passes.
fn verify_struct_in_module(context: &LlzkContext, struct_def: StructDefOp, label: &str) {
    let module = wrap_struct_in_module(context, struct_def);
    print_and_verify_module(&module, label);
}

/// Wraps a `StructDefOp` in a new LLZK module.
fn wrap_struct_in_module<'c>(context: &'c LlzkContext, struct_def: StructDefOp<'c>) -> Module<'c> {
    let location = Location::unknown(context);
    let module = llzk_module(location);
    module.body().append_operation(struct_def.into());
    module
}

/// Builds an `AssertZero` opcode for `a * b - out = 0`.
pub(super) fn mul_constraint(a: u32, b: u32, out: u32) -> Opcode<FieldElement> {
    Opcode::AssertZero(Expression {
        mul_terms: vec![(FieldElement::one(), Witness(a), Witness(b))],
        linear_combinations: vec![(-FieldElement::one(), Witness(out))],
        q_c: FieldElement::zero(),
    })
}

/// Builds a black-box `AND` opcode over witnesses.
pub(super) fn and_blackbox(lhs: u32, rhs: u32, num_bits: u32, output: u32) -> Opcode<FieldElement> {
    Opcode::BlackBoxFuncCall(BlackBoxFuncCall::AND {
        lhs: FunctionInput::Witness(Witness(lhs)),
        rhs: FunctionInput::Witness(Witness(rhs)),
        num_bits,
        output: Witness(output),
    })
}

/// Builds a black-box `XOR` opcode over witnesses.
pub(super) fn xor_blackbox(lhs: u32, rhs: u32, num_bits: u32, output: u32) -> Opcode<FieldElement> {
    Opcode::BlackBoxFuncCall(BlackBoxFuncCall::XOR {
        lhs: FunctionInput::Witness(Witness(lhs)),
        rhs: FunctionInput::Witness(Witness(rhs)),
        num_bits,
        output: Witness(output),
    })
}

/// Builds a black-box `RANGE` opcode.
pub(super) fn range_blackbox(input: u32, num_bits: u32) -> Opcode<FieldElement> {
    Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
        input: FunctionInput::Witness(Witness(input)),
        num_bits,
    })
}

/// Returns the first `StructDefOp` in the module body.
pub(super) fn first_struct_def<'c, 'a>(module: &'a Module<'c>) -> StructDefOpRef<'c, 'a> {
    let op = module
        .body()
        .first_operation()
        .expect("module should have a first op");
    StructDefOpRef::try_from(op).expect("first op should be a struct def")
}

/// Iterates over all operations in a block in order.
///
/// This is a polyfill for `Block::operations()`, which the LLZK API does not yet expose.
pub(super) fn iter_block_ops<'c, 'a>(
    block: BlockRef<'c, 'a>,
) -> impl Iterator<Item = OperationRef<'c, 'a>> {
    std::iter::successors(block.first_operation(), |op| op.next_in_block())
}

/// Prints the module IR and asserts it verifies successfully.
fn print_and_verify_module(module: &Module, label: &str) {
    let ir = format!("{}", module.as_operation());
    println!("{label}:\n{ir}");
    if let Err(e) = llzk::operation::verify_operation_with_diags(&module.as_operation()) {
        panic!("Module verification failed for {label}: {e}");
    }
}
