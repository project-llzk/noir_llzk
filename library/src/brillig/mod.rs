//! Translation of Brillig bytecode into LLZK functions.
//!
//! ACIR programs invoke Brillig (unconstrained) bytecode via the
//! `BrilligCall` opcode. The call-site itself is emitted by
//! [`crate::opcodes::brillig_call::BrilligCall`] inside the caller's
//! `@compute`. The brillig function bodies live at module scope and are
//! emitted once per `(BrilligFunctionId, input_count, output_count)` after
//! all circuits have been translated — see [`registry::emit_brillig_functions`].

mod cfg;
mod flow;
mod memory;
mod opcodes;
mod registry;
mod structured_translator;
mod structurer;
#[cfg(test)]
mod test_helpers;
mod translator;

pub(crate) use registry::{BrilligRegistry, BrilligRegistryKey, emit_brillig_functions};
