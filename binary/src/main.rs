use std::{fs, path::Path, process};

use acir::{FieldElement, circuit::Program};
use acir_llzk::program::translate_program;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use llzk::prelude::LlzkContext;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <acir-file>", args[0]);
        process::exit(1);
    }

    let path = Path::new(&args[1]);
    let json_str = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("Error reading {}: {e}", path.display());
        process::exit(1);
    });

    let acir_program = load_program(&json_str).unwrap_or_else(|e| {
        eprintln!("Error loading ACIR program: {e}");
        process::exit(1);
    });

    let context = LlzkContext::new();
    let module = translate_program(&context, &acir_program).unwrap_or_else(|e| {
        eprintln!("Translation error: {e:?}");
        process::exit(1);
    });

    println!("ACIR program:\n{:?}", acir_program);

    print!("{}", module.as_operation());
}

/// Deserializes an ACIR `Program` from a JSON artifact file.
fn load_program(json_str: &str) -> Result<Program<FieldElement>, String> {
    let json: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("JSON parse error: {e}"))?;

    let bytecode_b64 = json
        .get("bytecode")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "JSON artifact missing 'bytecode' string field".to_string())?;

    let bytecode = STANDARD
        .decode(bytecode_b64)
        .map_err(|e| format!("base64 decode error: {e}"))?;

    Program::deserialize_program(&bytecode).map_err(|e| format!("ACIR deserialization error: {e}"))
}
