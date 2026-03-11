// acir2llzk library crate

#[cfg(test)]
mod tests {
    use acir::circuit::{Circuit, Program, PublicInputs};
    use acir::native_types::Witness;
    use acir::FieldElement;
    use llzk::prelude::*;
    use std::collections::BTreeSet;

    /// Smoke test: create an MLIR context, register LLZK dialects,
    /// create an empty module, verify it, and print it to string.
    #[test]
    fn llzk_empty_module_smoke_test() {
        // Create context (auto-registers all LLZK dialects)
        let context = LlzkContext::new();

        // Create an empty LLZK module
        let location = Location::unknown(&context);
        let module = llzk_module(location);

        // Verify the module
        assert!(
            module.as_operation().verify(),
            "Empty LLZK module should verify successfully"
        );

        // Print module to string
        let ir_string = format!("{}", module.as_operation());
        assert!(
            !ir_string.is_empty(),
            "Module IR string should not be empty"
        );
        println!("Empty LLZK module IR:\n{ir_string}");
    }

    /// Smoke test: construct an acir::circuit::Program in memory
    /// (one circuit, zero opcodes, one witness) and assert on its structure.
    #[test]
    fn acir_program_smoke_test() {
        // Build a circuit with one private witness (w0), zero opcodes
        let mut private = BTreeSet::new();
        private.insert(Witness(0));

        let circuit = Circuit::<FieldElement> {
            function_name: "main".to_string(),
            current_witness_index: 0,
            opcodes: vec![],
            private_parameters: private,
            public_parameters: PublicInputs(BTreeSet::new()),
            return_values: PublicInputs(BTreeSet::new()),
            assert_messages: vec![],
        };

        // Wrap in a Program
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: vec![],
        };

        // Assert on the structure
        assert_eq!(program.functions.len(), 1, "Should have exactly one circuit");

        let c = &program.functions[0];
        assert_eq!(c.function_name, "main");
        assert_eq!(c.current_witness_index, 0, "One witness at index 0");
        assert!(c.opcodes.is_empty(), "Should have zero opcodes");
        assert_eq!(c.private_parameters.len(), 1, "One private parameter");
        assert!(
            c.private_parameters.contains(&Witness(0)),
            "Private parameter should be witness 0"
        );
        assert!(
            c.public_parameters.0.is_empty(),
            "No public parameters"
        );
        assert!(c.return_values.0.is_empty(), "No return values");

        println!("ACIR Program: {} circuit(s), first circuit has {} opcode(s) and witness index up to {}",
            program.functions.len(),
            c.opcodes.len(),
            c.current_witness_index,
        );
    }
}
