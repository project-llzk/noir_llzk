use acir::FieldElement;
use acir::circuit::Opcode;
use acir::circuit::{Circuit, Program, PublicInputs};
use acir::native_types::Witness;
use llzk::prelude::{
    BlockLike, LlzkContext, Location, Module, OperationLike, StructDefOp, llzk_module,
};

use crate::circuit::CircuitTranslator;

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

/// Prints the module IR and asserts it verifies successfully.
fn print_and_verify_module(module: &Module, label: &str) {
    let ir = format!("{}", module.as_operation());
    println!("{label}:\n{ir}");
    assert!(module.as_operation().verify(), "Module should verify");
}
