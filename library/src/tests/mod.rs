use acir::circuit::Opcode;
use acir::circuit::opcodes::{BlackBoxFuncCall, FunctionInput};
use acir::circuit::{Circuit, Program, PublicInputs};
use acir::native_types::{Expression, Witness};
use acir::{AcirField, FieldElement};
use llzk::prelude::{
    BlockLike, BlockRef, FlatSymbolRefAttribute, LlzkContext, Location, Module, OperationLike,
    OperationMutLike, OperationRef, StructDefOp, StructDefOpRef, StructType, TypeAttribute,
    llzk_module,
};
use llzk_sys::MAIN_ATTR_NAME;

use crate::brillig::BrilligRegistry;
use crate::circuit::CircuitTranslator;

use crate::program::translate_program;

mod blackboxes;
mod call_tests;
mod circuit_tests;
mod compute_tests;
mod constrain_tests;
#[cfg(all(test, feature = "e2e"))]
mod e2e;
mod integration_tests;
mod memory_init_tests;
mod memory_op_tests;
pub(crate) mod noir_helpers;

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

pub(crate) fn make_program_with_brillig(
    circuits: Vec<Circuit<FieldElement>>,
    unconstrained_functions: Vec<acir::circuit::brillig::BrilligBytecode<FieldElement>>,
) -> Program<FieldElement> {
    Program {
        functions: circuits,
        unconstrained_functions,
    }
}

/// Counts occurrences of `needle` in `haystack`.
pub(crate) fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

/// Helper to build a circuit with the given opcodes.
///
/// `current_witness_index` is the **inclusive** upper bound of the witness index range for
/// this circuit, as required by the ACIR `Circuit` struct. It must be at least as large as
/// the highest witness index referenced in `private`, `public`, `returns`, or any opcode
/// operand. Struct members are only emitted for witnesses actually referenced by opcodes.
pub(crate) fn make_circuit_with_opcodes(
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
///
/// Brillig-using circuits are NOT supported by this helper: `BrilligCall`
/// sites will register against a throwaway `BrilligRegistry`, but the
/// `@brillig_{id}` function bodies are never emitted, leaving dangling
/// symbol references. Tests that exercise Brillig should use
/// [`crate::program::translate_program`] directly.
pub(super) fn translate_single_circuit<'c>(
    context: &'c LlzkContext,
    circuit: Circuit<FieldElement>,
) -> Result<StructDefOp<'c>, crate::Error> {
    let program = make_program(vec![circuit]);
    let mut brillig_registry = BrilligRegistry::new();
    CircuitTranslator::new(context, &program.functions[0], &program)
        .translate(0, &mut brillig_registry)
}

/// Convenience wrapper used by tests that need the full module translation,
/// including any top-level helper functions emitted alongside circuits.
pub(super) fn translate_single_circuit_module<'c>(
    context: &'c LlzkContext,
    circuit: Circuit<FieldElement>,
) -> Result<Module<'c>, crate::Error> {
    let program = make_program(vec![circuit]);
    translate_program(context, &program)
}

/// Wraps a `StructDefOp` in a module, prints the IR, and asserts verification passes.
fn verify_struct_in_module(context: &LlzkContext, struct_def: StructDefOp, label: &str) {
    let module = wrap_struct_in_module(context, struct_def);
    print_and_verify_module(&module, label);
}

fn wrap_struct_in_module<'c>(context: &'c LlzkContext, struct_def: StructDefOp<'c>) -> Module<'c> {
    let location = Location::unknown(context);
    let mut module = llzk_module(location, Some("Noir"));
    module.as_operation_mut().set_attribute(
        MAIN_ATTR_NAME.as_ref(),
        TypeAttribute::new(
            StructType::new(FlatSymbolRefAttribute::new(context, "Circuit0"), &[]).into(),
        )
        .into(),
    );
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

/// Builds a black-box `EmbeddedCurveAdd` opcode over witnesses.
pub(super) fn embedded_curve_add_blackbox(
    input1: [u32; 3],
    input2: [u32; 3],
    predicate: u32,
    outputs: (u32, u32, u32),
) -> Opcode<FieldElement> {
    Opcode::BlackBoxFuncCall(BlackBoxFuncCall::EmbeddedCurveAdd {
        input1: Box::new(input1.map(|w| FunctionInput::Witness(Witness(w)))),
        input2: Box::new(input2.map(|w| FunctionInput::Witness(Witness(w)))),
        predicate: FunctionInput::Witness(Witness(predicate)),
        outputs: (Witness(outputs.0), Witness(outputs.1), Witness(outputs.2)),
    })
}

/// Builds a black-box `MultiScalarMul` opcode over witnesses.
pub(super) fn multi_scalar_mul_blackbox(
    points: &[[u32; 3]],
    scalars: &[[u32; 2]],
    predicate: u32,
    outputs: (u32, u32, u32),
) -> Opcode<FieldElement> {
    let points = points
        .iter()
        .flat_map(|point| point.iter().copied())
        .map(|w| FunctionInput::Witness(Witness(w)))
        .collect();
    let scalars = scalars
        .iter()
        .flat_map(|scalar| scalar.iter().copied())
        .map(|w| FunctionInput::Witness(Witness(w)))
        .collect();

    Opcode::BlackBoxFuncCall(BlackBoxFuncCall::MultiScalarMul {
        points,
        scalars,
        predicate: FunctionInput::Witness(Witness(predicate)),
        outputs: (Witness(outputs.0), Witness(outputs.1), Witness(outputs.2)),
    })
}

/// Returns the first `StructDefOp` in the module body.
pub(super) fn first_struct_def<'c, 'a>(module: &'a Module<'c>) -> StructDefOpRef<'c, 'a> {
    iter_block_ops(module.body())
        .find_map(|op| StructDefOpRef::try_from(op).ok())
        .expect("module should contain a struct def")
}

/// Iterates over all operations in a block in order.
///
/// This is a polyfill for `Block::operations()`, which the LLZK API does not yet expose.
pub(super) fn iter_block_ops<'c, 'a>(
    block: BlockRef<'c, 'a>,
) -> impl Iterator<Item = OperationRef<'c, 'a>> {
    std::iter::successors(block.first_operation(), |op| op.next_in_block())
}

/// Prints the module IR, asserts MLIR-structural verification,
/// asserts modules lower successfuly to PCL.
pub(crate) fn print_and_verify_module(module: &Module, label: &str) {
    let ir = format!("{}", module.as_operation());
    println!("{label}:\n{ir}");
    assert!(module.as_operation().verify(), "Module should verify");
    assert_module_lowers_to_pcl(module, label);
}

/// Asserts the module lowers to the PCL backend.
fn assert_module_lowers_to_pcl(module: &Module, label: &str) {
    let ir = format!("{}", module.as_operation());
    let opt = find_llzk_opt().expect("llzk-opt not found — set $LLZK_OPT or $LLZK_SYS_10_PREFIX");
    assert_ir_lowers_with_passes(
        &opt,
        &ir,
        label,
        &["--llzk-full-struct-inlining", "--llzk-to-pcl"],
    );
}

/// Locates the `llzk-opt` binary
fn find_llzk_opt() -> Option<std::path::PathBuf> {
    if let Some(prefix) = std::env::var_os("LLZK_SYS_10_PREFIX") {
        let path = std::path::PathBuf::from(prefix).join("bin/llzk-opt");
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

/// Pipes `ir` through `llzk-opt <passes...>` and asserts the conversion
/// succeeds, returning the lowered IR for further inspection by the caller.
fn assert_ir_lowers_with_passes(
    opt: &std::path::Path,
    ir: &str,
    label: &str,
    passes: &[&str],
) -> String {
    use std::io::Write;

    let mut child = std::process::Command::new(opt)
        .args(passes)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("[{label}] failed to spawn llzk-opt: {e}"));
    child
        .stdin
        .take()
        .unwrap()
        .write_all(ir.as_bytes())
        .unwrap_or_else(|e| panic!("[{label}] failed to write IR to llzk-opt stdin: {e}"));
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("[{label}] llzk-opt wait failed: {e}"));
    assert!(
        out.status.success(),
        "[{label}] llzk-opt {} failed (exit={:?}):\n--- stderr ---\n{}\n--- input ---\n{ir}",
        passes.join(" "),
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8(out.stdout)
        .unwrap_or_else(|e| panic!("[{label}] llzk-opt produced non-UTF8 stdout: {e}"))
}
