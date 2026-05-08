use std::{fs, path::Path, process};

use acir_llzk::{load_program, translate_program};
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

    print!("{}", module.as_operation());
}
