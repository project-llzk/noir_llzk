use acir::circuit::Opcode;
use acir::circuit::{Circuit, Program, PublicInputs};
use acir::native_types::{Expression, Witness};
use acir::{AcirField, FieldElement};
use llzk::prelude::{
    BlockLike, BlockRef, FuncDefOpRef, LlzkContext, Location, MemberDefOpLike, Module,
    OperationLike, OperationRef, RegionLike, StructDefOp, StructDefOpLike, StructDefOpRef, Value,
    llzk_module,
};

use crate::circuit::CircuitTranslator;

mod call_tests;
mod circuit_tests;
mod compute_tests;
mod constrain_tests;

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
/// this circuit. Translation iterates `0..=current_witness_index` to emit `struct.member`
/// declarations, so it must be at least as large as the highest index referenced in
/// `private`, `public`, `returns`, or any opcode operand.
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
pub(super) fn translate_single_circuit<'c>(
    context: &'c LlzkContext,
    circuit: Circuit<FieldElement>,
) -> Result<StructDefOp<'c>, crate::Error> {
    let program = make_program(vec![circuit]);
    CircuitTranslator::new(context, &program.functions[0], &program).translate(0)
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

/// Returns the first `StructDefOp` in the module body.
pub(super) fn first_struct_def<'c, 'a>(module: &'a Module<'c>) -> StructDefOpRef<'c, 'a> {
    let op = module
        .body()
        .first_operation()
        .expect("module should have a first op");
    StructDefOpRef::try_from(op).expect("first op should be a struct def")
}

/// Returns the names of all `struct.member` fields in the given struct.
fn member_names(struct_def: &llzk::prelude::StructDefOp) -> Vec<String> {
    struct_def
        .get_member_defs()
        .into_iter()
        .map(|m| m.member_name().to_string())
        .collect()
}

/// Collects the operands of every `func.call` in `func`, one inner `Vec` per call.
fn func_call_operands<'c, 'a>(func: FuncDefOpRef<'c, 'a>) -> Vec<Vec<Value<'c, 'a>>> {
    let block = func.region(0).unwrap().first_block().unwrap();
    iter_block_ops(block)
        .filter(llzk::prelude::dialect::function::is_func_call)
        .map(|op| op.operands().collect())
        .collect()
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
    assert!(module.as_operation().verify(), "Module should verify");
}
