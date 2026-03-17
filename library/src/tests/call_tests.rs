use acir::circuit::Opcode;
use acir::native_types::{Expression, Witness};
use acir::{AcirField, FieldElement, circuit::opcodes::AcirFunctionId};
use llzk::prelude::{
    BlockLike, FeltType, FuncDefOpRef, LlzkContext, MemberDefOpLike, OperationLike, OperationRef,
    RegionLike, StructDefOpLike, StructDefOpRef, StructType, SymbolRefAttribute, Type, Value,
    ValueLike,
};

use super::{
    first_struct_def, make_circuit, make_circuit_with_opcodes, make_program, mul_constraint,
    print_and_verify_module,
};
use crate::program::translate_program;

const FIELD_NAME: &str = "bn254";

// ── IR data extraction (collect once) ──────────────────────────────────

/// Pre-collected IR data for all `func.call` operations in a struct.
struct StructCallInfo<'c, 'a> {
    member_count: usize,
    calls: Vec<CallInfo<'c, 'a>>,
    /// Number of `struct.writem` ops in @compute.
    compute_writem_count: usize,
    /// Number of `struct.readm` ops in @constrain.
    constrain_readm_count: usize,
}

/// IR data for a single `func.call` pair (one in @compute, one in @constrain).
struct CallInfo<'c, 'a> {
    compute_operands: Vec<Value<'c, 'a>>,
    constrain_operands: Vec<Value<'c, 'a>>,
    compute_callee: SymbolInfo,
    constrain_callee: SymbolInfo,
    /// The subcircuit member type, if the member exists.
    subcircuit_type: Option<Type<'c>>,
}

/// Parsed callee symbol from a `func.call` operation.
struct SymbolInfo {
    struct_name: String,
    func_name: String,
}

/// Collects all call-related IR data from a struct in a single traversal.
fn collect_call_info<'c, 'a>(
    struct_def: &'a llzk::prelude::StructDefOp<'c>,
) -> StructCallInfo<'c, 'a> {
    let compute = struct_def.get_compute_func().expect("should have @compute");
    let constrain = struct_def
        .get_constrain_func()
        .expect("should have @constrain");

    let compute_ops = func_call_ops(compute);
    let constrain_ops = func_call_ops(constrain);
    assert_eq!(
        compute_ops.len(),
        constrain_ops.len(),
        "@compute and @constrain should have the same number of func.call operations"
    );

    let calls: Vec<CallInfo> = compute_ops
        .iter()
        .zip(constrain_ops.iter())
        .enumerate()
        .map(|(i, (c_op, s_op))| {
            let member_name = format!("subcircuit_{i}");
            let subcircuit_type = struct_def
                .get_member_def(&member_name)
                .map(|m| m.member_type());

            CallInfo {
                compute_operands: c_op.operands().collect(),
                constrain_operands: s_op.operands().collect(),
                compute_callee: extract_callee_symbol(c_op),
                constrain_callee: extract_callee_symbol(s_op),
                subcircuit_type,
            }
        })
        .collect();

    let compute_block = compute.region(0).unwrap().first_block().unwrap();
    let constrain_block = constrain.region(0).unwrap().first_block().unwrap();

    StructCallInfo {
        member_count: struct_def.get_member_defs().len(),
        compute_writem_count: super::iter_block_ops(compute_block)
            .filter(llzk::prelude::dialect::r#struct::is_struct_writem)
            .count(),
        constrain_readm_count: super::iter_block_ops(constrain_block)
            .filter(llzk::prelude::dialect::r#struct::is_struct_readm)
            .count(),
        calls,
    }
}

/// Returns `func.call` operations from a function.
fn func_call_ops<'c, 'a>(func: FuncDefOpRef<'c, 'a>) -> Vec<OperationRef<'c, 'a>> {
    let block = func.region(0).unwrap().first_block().unwrap();
    super::iter_block_ops(block)
        .filter(llzk::prelude::dialect::function::is_func_call)
        .collect()
}

/// Extracts the callee symbol from a `func.call` operation.
fn extract_callee_symbol(op: &OperationRef) -> SymbolInfo {
    let callee_attr = op
        .attribute("callee")
        .expect("func.call should have a callee attribute");
    let sym = SymbolRefAttribute::try_from(callee_attr)
        .expect("callee attribute should be a SymbolRefAttribute");
    SymbolInfo {
        struct_name: sym
            .root()
            .as_str()
            .expect("root should be UTF-8")
            .to_string(),
        func_name: sym
            .leaf()
            .as_str()
            .expect("leaf should be UTF-8")
            .to_string(),
    }
}

// ── Assertions (no IR traversal) ───────────────────────────────────────

fn felt_type<'c>(context: &'c LlzkContext) -> Type<'c> {
    FeltType::with_field(context, FIELD_NAME).into()
}

impl StructCallInfo<'_, '_> {
    fn assert_counts(
        &self,
        members: usize,
        calls: usize,
        writem: usize,
        readm: usize,
        label: &str,
    ) {
        assert_eq!(self.member_count, members, "{label} member count");
        assert_eq!(self.calls.len(), calls, "{label} func.call count");
        assert_eq!(
            self.compute_writem_count, writem,
            "{label} @compute writem count"
        );
        assert_eq!(
            self.constrain_readm_count, readm,
            "{label} @constrain readm count"
        );
    }
}

impl CallInfo<'_, '_> {
    /// Asserts all structural properties of a single call.
    fn assert_shape(&self, context: &LlzkContext, call_idx: usize, callee_name: &str, label: &str) {
        self.assert_subcircuit_type(context, call_idx, callee_name, label);
        self.assert_arities(call_idx, label);
        self.assert_operand_types(context, call_idx, callee_name, label);
        self.assert_callee_symbols(call_idx, callee_name, label);
    }

    fn assert_subcircuit_type(
        &self,
        context: &LlzkContext,
        call_idx: usize,
        callee_name: &str,
        label: &str,
    ) {
        let actual = self
            .subcircuit_type
            .unwrap_or_else(|| panic!("{label} should have a subcircuit_{call_idx} member"));
        let expected: Type = StructType::from_str(context, callee_name).into();
        assert_eq!(
            actual, expected,
            "{label} subcircuit_{call_idx} should have type !struct.type<@{callee_name}>"
        );
    }

    fn assert_arities(&self, call_idx: usize, label: &str) {
        assert_eq!(
            self.compute_operands.len() + 1,
            self.constrain_operands.len(),
            "{label} call {call_idx}: @constrain should have one extra arg (callee struct) vs @compute"
        );
    }

    /// Checks all operand types: @compute args are all felt, @constrain arg 0 is
    /// the callee struct (SSA result, not block arg), remaining @constrain args are felt.
    fn assert_operand_types(
        &self,
        context: &LlzkContext,
        call_idx: usize,
        callee_name: &str,
        label: &str,
    ) {
        let felt = felt_type(context);
        let struct_ty: Type = StructType::from_str(context, callee_name).into();

        // All @compute operands should be felt.
        for (i, op) in self.compute_operands.iter().enumerate() {
            assert_eq!(
                op.r#type(),
                felt,
                "{label} @compute call {call_idx} operand {i} should be felt"
            );
        }

        // @constrain operand 0: callee struct (SSA result from readm).
        let first = self.constrain_operands[0];
        assert!(
            first.is_operation_result(),
            "{label} @constrain call {call_idx} arg 0 should be an SSA result \
             (struct.readm of subcircuit_{call_idx})"
        );
        assert_eq!(
            first.r#type(),
            struct_ty,
            "{label} @constrain call {call_idx} arg 0 should be !struct.type<@{callee_name}>"
        );

        // @constrain operands 1.. should be felt.
        for (i, op) in self.constrain_operands.iter().enumerate().skip(1) {
            assert_eq!(
                op.r#type(),
                felt,
                "{label} @constrain call {call_idx} operand {i} should be felt"
            );
        }
    }

    fn assert_callee_symbols(&self, call_idx: usize, callee_name: &str, label: &str) {
        assert_eq!(
            self.compute_callee.struct_name, callee_name,
            "{label} @compute call {call_idx} callee struct should be @{callee_name}"
        );
        assert_eq!(
            self.compute_callee.func_name, "compute",
            "{label} @compute call {call_idx} callee func should be @compute"
        );
        assert_eq!(
            self.constrain_callee.struct_name, callee_name,
            "{label} @constrain call {call_idx} callee struct should be @{callee_name}"
        );
        assert_eq!(
            self.constrain_callee.func_name, "constrain",
            "{label} @constrain call {call_idx} callee func should be @constrain"
        );
    }

    /// Asserts that a specific operand (by index into @compute args) is an operation result.
    fn assert_operand_is_ssa(&self, compute_idx: usize, label: &str) {
        assert!(
            self.compute_operands[compute_idx].is_operation_result(),
            "{label} @compute operand {compute_idx} should be SSA result, not block arg"
        );
        // constrain operands are shifted by 1 (callee struct at position 0).
        let constrain_idx = compute_idx + 1;
        assert!(
            self.constrain_operands[constrain_idx].is_operation_result(),
            "{label} @constrain operand {constrain_idx} should be SSA result, not block arg"
        );
    }

    fn assert_operand_is_block_arg(&self, compute_idx: usize, label: &str) {
        assert!(
            self.compute_operands[compute_idx].is_block_argument(),
            "{label} @compute operand {compute_idx} should be a block arg"
        );
        let constrain_idx = compute_idx + 1;
        assert!(
            self.constrain_operands[constrain_idx].is_block_argument(),
            "{label} @constrain operand {constrain_idx} should be a block arg"
        );
    }
}

// ── Test helpers ───────────────────────────────────────────────────────

/// Builds a Call opcode with a trivially-true predicate (always execute).
fn call_opcode(id: u32, inputs: Vec<u32>, outputs: Vec<u32>) -> Opcode<FieldElement> {
    Opcode::Call {
        id: AcirFunctionId(id),
        inputs: inputs.into_iter().map(Witness).collect(),
        outputs: outputs.into_iter().map(Witness).collect(),
        predicate: Expression::one(),
    }
}

/// Translates a program and runs count and per-call shape assertions on the outer circuit.
fn translate_and_assert(
    context: &LlzkContext,
    program: &acir::circuit::Program<FieldElement>,
    label: &str,
    expected_members: usize,
    expected_writem: usize,
    expected_constrain_readm: usize,
    calls: &[&str],
) {
    let module = translate_program(context, program).unwrap();
    let struct0 = first_struct_def(&module);
    let info = collect_call_info(&struct0);

    info.assert_counts(
        expected_members,
        calls.len(),
        expected_writem,
        expected_constrain_readm,
        label,
    );

    for (i, callee) in calls.iter().enumerate() {
        info.calls[i].assert_shape(context, i, callee, label);
    }

    print_and_verify_module(&module, label);
}

// ── Tests ──────────────────────────────────────────────────────────────

/// Call outputs become known witnesses that can be used in subsequent AssertZero solves.
///
///   Circuit1: w0*w1 = w2
///   Circuit0: call Circuit1(w0, w1) → w2; then assert w2 + w0 - w3 = 0 to solve w3
#[test]
fn call_output_used_in_subsequent_solve() {
    let context = LlzkContext::new();

    let circuit1 = make_circuit_with_opcodes(2, &[0, 1], &[], &[2], vec![mul_constraint(0, 1, 2)]);

    // assert: w2 + w0 - w3 = 0  →  w3 = w2 + w0
    let assert_expr = Expression {
        mul_terms: vec![],
        linear_combinations: vec![
            (FieldElement::one(), Witness(2)),
            (FieldElement::one(), Witness(0)),
            (-FieldElement::one(), Witness(3)),
        ],
        q_c: FieldElement::zero(),
    };
    let circuit0 = make_circuit_with_opcodes(
        3,
        &[0, 1],
        &[],
        &[],
        vec![
            call_opcode(1, vec![0, 1], vec![2]),
            Opcode::AssertZero(assert_expr),
        ],
    );

    // 2 internal witnesses (w2, w3) + 1 subcircuit = 3 members
    // writem: subcircuit + w2 (call output) + w3 (solve) = 3
    // constrain readm: subcircuit + w2 + w3 (non-input witnesses read from %self) = 3
    let program = make_program(vec![circuit0, circuit1]);
    println!("ACIR: {:?}", program);
    translate_and_assert(&context, &program, "Circuit0", 3, 3, 4, &["Circuit1"]);
}

/// Two Call opcodes to the same callee → two distinct subcircuit members.
#[test]
fn two_calls_same_callee() {
    let context = LlzkContext::new();

    let circuit1 = make_circuit_with_opcodes(2, &[0, 1], &[], &[2], vec![mul_constraint(0, 1, 2)]);

    let circuit0 = make_circuit_with_opcodes(
        4,
        &[0, 1],
        &[],
        &[],
        vec![
            call_opcode(1, vec![0, 1], vec![2]),
            call_opcode(1, vec![0, 1], vec![3]),
            mul_constraint(2, 3, 4),
        ],
    );

    // 3 internal witnesses (w2, w3, w4) + 2 subcircuits = 5 members
    // writem: 2 subcircuits + 3 outputs (w2, w3, w4) = 5
    // constrain readm: 2 subcircuits + 3 witnesses (w2, w3, w4) + 2 return values = 7
    let program = make_program(vec![circuit0, circuit1]);
    translate_and_assert(
        &context,
        &program,
        "Circuit0",
        5,
        5,
        7,
        &["Circuit1", "Circuit1"],
    );
}

/// Transitive calls: Circuit0 → Circuit1 → Circuit2, plus a direct Circuit0 → Circuit2 call
/// where one argument is the output of the Circuit1 call (not a block arg of Circuit0).
#[test]
fn transitive_calls() {
    let context = LlzkContext::new();

    let circuit2 = make_circuit_with_opcodes(2, &[0, 1], &[], &[2], vec![mul_constraint(0, 1, 2)]);
    let circuit1 = make_circuit_with_opcodes(
        2,
        &[0, 1],
        &[],
        &[2],
        vec![call_opcode(2, vec![0, 1], vec![2])],
    );
    let circuit0 = make_circuit_with_opcodes(
        3,
        &[0, 1],
        &[],
        &[],
        vec![
            call_opcode(1, vec![0, 1], vec![2]),
            call_opcode(2, vec![1, 2], vec![3]),
        ],
    );

    let program = make_program(vec![circuit0, circuit1, circuit2]);
    let module = translate_program(&context, &program).expect("translation should succeed");

    let body = module.body();
    let op0 = body
        .first_operation()
        .expect("module should have a first op");
    let op1 = op0.next_in_block().expect("module should have a second op");
    let struct0 = StructDefOpRef::try_from(op0).expect("op0 should be a struct def");
    let struct1 = StructDefOpRef::try_from(op1).expect("op1 should be a struct def");

    let c0_info = collect_call_info(&struct0);
    let c1_info = collect_call_info(&struct1);

    // Circuit0: 2 internal witnesses (w2, w3) + 2 subcircuits = 4 members; 2 calls
    c0_info.assert_counts(4, 2, 4, 6, "Circuit0");
    // Circuit1: 1 internal witness (w2) + 1 subcircuit = 2 members; 1 call
    c1_info.assert_counts(2, 1, 2, 3, "Circuit1");

    c0_info.calls[0].assert_shape(&context, 0, "Circuit1", "Circuit0");
    c0_info.calls[1].assert_shape(&context, 1, "Circuit2", "Circuit0");

    // w0, w1 are block args for the first call.
    c0_info.calls[0].assert_operand_is_block_arg(0, "Circuit0 call 0 w0");
    c0_info.calls[0].assert_operand_is_block_arg(1, "Circuit0 call 0 w1");

    // In the second call, w1 is a block arg, w2 is SSA (came from first call's output).
    c0_info.calls[1].assert_operand_is_block_arg(0, "Circuit0 call 1 w1");
    c0_info.calls[1].assert_operand_is_ssa(1, "Circuit0 call 1 w2");

    c1_info.calls[0].assert_shape(&context, 0, "Circuit2", "Circuit1");

    print_and_verify_module(&module, "transitive_calls");
}

/// A circuit with no opcodes other than a call still produces a valid module.
#[test]
fn call_only_circuit_verifies() {
    let context = LlzkContext::new();

    let callee = make_circuit(0, &[0], &[], &[]);
    let caller =
        make_circuit_with_opcodes(0, &[0], &[], &[], vec![call_opcode(1, vec![0], vec![])]);

    // 0 internal witnesses + 1 subcircuit = 1 member; writem: 1 (subcircuit); readm: 1 (subcircuit)
    let program = make_program(vec![caller, callee]);
    translate_and_assert(&context, &program, "Circuit0", 1, 1, 1, &["Circuit1"]);
}

/// The `predicate` field of a Call opcode is not used during translation.
#[test]
fn call_with_nontrivial_predicate_is_ignored() {
    let context = LlzkContext::new();

    let circuit1 = make_circuit_with_opcodes(2, &[0, 1], &[], &[2], vec![mul_constraint(0, 1, 2)]);

    let nontrivial_predicate = Expression {
        mul_terms: vec![],
        linear_combinations: vec![(FieldElement::one(), Witness(0))],
        q_c: FieldElement::zero(),
    };
    let circuit0 = make_circuit_with_opcodes(
        2,
        &[0, 1],
        &[],
        &[],
        vec![Opcode::Call {
            id: AcirFunctionId(1),
            inputs: vec![Witness(0), Witness(1)],
            outputs: vec![Witness(2)],
            predicate: nontrivial_predicate,
        }],
    );

    // 1 internal witness (w2) + 1 subcircuit = 2 members
    // writem: subcircuit + w2 = 2; readm: subcircuit only (w0,w1 are block args)
    let program = make_program(vec![circuit0, circuit1]);
    translate_and_assert(&context, &program, "Circuit0", 2, 2, 3, &["Circuit1"]);
}

/// A Call opcode referencing a circuit index that does not exist in the program
/// returns an `OutOfRangeCallTarget` error rather than panicking.
#[test]
fn call_with_out_of_range_id_returns_error() {
    let context = LlzkContext::new();

    let circuit0 =
        make_circuit_with_opcodes(0, &[0], &[], &[], vec![call_opcode(99, vec![0], vec![])]);

    let program = make_program(vec![circuit0]);
    let result = translate_program(&context, &program);
    assert!(
        matches!(
            result,
            Err(crate::Error::OutOfRangeCallTarget { id: 99, .. })
        ),
        "expected OutOfRangeCallTarget error for circuit id 99, got: {:?}",
        result
    );
}

/// A call with zero inputs exercises the edge case where @compute and @constrain
/// calls have no witness operands.
#[test]
fn call_with_zero_inputs() {
    let context = LlzkContext::new();

    // Circuit1: no inputs, no opcodes, no returns.
    let circuit1 = make_circuit(0, &[], &[], &[]);
    // Circuit0: calls Circuit1 with no inputs and no outputs.
    let circuit0 =
        make_circuit_with_opcodes(0, &[], &[], &[], vec![call_opcode(1, vec![], vec![])]);

    // 0 witnesses + 1 subcircuit = 1 member
    let program = make_program(vec![circuit0, circuit1]);
    translate_and_assert(&context, &program, "Circuit0", 1, 1, 1, &["Circuit1"]);
}

/// A call that produces multiple outputs wires all return values correctly.
///
///   Circuit1: w0*w1 = w2, w0*w2 = w3, returns w2 and w3.
///   Circuit0: call Circuit1(w0, w1) → (w2, w3)
#[test]
fn call_with_multiple_outputs() {
    let context = LlzkContext::new();

    let circuit1 = make_circuit_with_opcodes(
        3,
        &[0, 1],
        &[],
        &[2, 3],
        vec![mul_constraint(0, 1, 2), mul_constraint(0, 2, 3)],
    );

    let circuit0 = make_circuit_with_opcodes(
        3,
        &[0, 1],
        &[],
        &[],
        vec![call_opcode(1, vec![0, 1], vec![2, 3])],
    );

    // 2 internal witnesses (w2, w3) + 1 subcircuit = 3 members
    // writem: subcircuit + w2 + w3 = 3; readm: subcircuit only
    let program = make_program(vec![circuit0, circuit1]);
    translate_and_assert(&context, &program, "Circuit0", 3, 3, 5, &["Circuit1"]);
}

/// Calls two different callees at the same level (no transitivity).
///
///   Circuit1: w0*w1 = w2
///   Circuit2: w0*w1 = w2
///   Circuit0: call Circuit1(w0, w1) → w2, call Circuit2(w0, w1) → w3,
///   assert(w2 * w3 == w4)
#[test]
fn two_calls_different_callees() {
    let context = LlzkContext::new();

    let circuit1 = make_circuit_with_opcodes(2, &[0, 1], &[], &[2], vec![mul_constraint(0, 1, 2)]);
    let circuit2 = make_circuit_with_opcodes(2, &[0, 1], &[], &[2], vec![mul_constraint(0, 1, 2)]);

    let circuit0 = make_circuit_with_opcodes(
        4,
        &[0, 1],
        &[],
        &[],
        vec![
            call_opcode(1, vec![0, 1], vec![2]),
            call_opcode(2, vec![0, 1], vec![3]),
            mul_constraint(2, 3, 4),
        ],
    );

    // 3 internal witnesses (w2, w3, w4) + 2 subcircuits = 5 members
    // writem: 2 subcircuits + 3 outputs (w2, w3, w4) = 5; readm: 2 subcircuits + 3 witnesses = 5
    let program = make_program(vec![circuit0, circuit1, circuit2]);
    translate_and_assert(
        &context,
        &program,
        "Circuit0",
        5,
        5,
        7,
        &["Circuit1", "Circuit2"],
    );
}

/// A callee with public parameters is called correctly.
///
///   Circuit1: w0 (private), w1 (public), w0*w1 = w2
///   Circuit0: call Circuit1(w0, w1) → w2
#[test]
fn call_with_public_params() {
    let context = LlzkContext::new();

    let circuit1 = make_circuit_with_opcodes(2, &[0], &[1], &[2], vec![mul_constraint(0, 1, 2)]);

    let circuit0 = make_circuit_with_opcodes(
        2,
        &[0, 1],
        &[],
        &[],
        vec![call_opcode(1, vec![0, 1], vec![2])],
    );

    // 1 internal witness (w2) + 1 subcircuit = 2 members
    // writem: subcircuit + w2 = 2; readm: subcircuit only
    let program = make_program(vec![circuit0, circuit1]);
    translate_and_assert(&context, &program, "Circuit0", 2, 2, 3, &["Circuit1"]);
}

/// A caller that returns a value produced by a subcircuit call exercises
/// the return-value wiring path.
///
///   Circuit1: w0*w1 = w2, returns w2
///   Circuit0: call Circuit1(w0, w1) → w2, returns w2
#[test]
fn call_return_propagated_to_caller() {
    let context = LlzkContext::new();

    let circuit1 = make_circuit_with_opcodes(2, &[0, 1], &[], &[2], vec![mul_constraint(0, 1, 2)]);

    let circuit0 = make_circuit_with_opcodes(
        2,
        &[0, 1],
        &[],
        &[2],
        vec![call_opcode(1, vec![0, 1], vec![2])],
    );

    // 1 internal witness (w2) + 1 subcircuit = 2 members
    // writem: subcircuit + w2 = 2; readm: subcircuit only
    let program = make_program(vec![circuit0, circuit1]);
    translate_and_assert(&context, &program, "Circuit0", 2, 2, 3, &["Circuit1"]);
}
