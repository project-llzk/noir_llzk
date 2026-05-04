//! Unit tests for the Brillig structurer.
//! Contrived bytecode tests cover the canonical region shapes; the
//! integration tests' first four fixtures are the minimum cover of every reachable
//! catch in [`super::walker`] and[`super::loop_shape`];
//!  the rest assert structure on distinct shapes.

use acir::FieldElement;
use acir::brillig::{HeapVector, Label, MemoryAddress, Opcode as BrilligOpcode};

use crate::opcodes::brillig::cfg::{BlockId, Cfg};
use crate::opcodes::brillig::structurer::{
    CondPolarity, EscapeFlagSlot, LoopCondition, RegionNode, StructuredFunction, structure_function,
};
use crate::tests::noir_helpers::{
    circuits_dir, load_program_from_file, nargo_available, nargo_compile,
};

use super::{brillig_stop, mov};

// ── Fixture constructors ────────────────────────────────────────────────

fn jump(location: Label) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Jump { location }
}

fn jump_if(condition: u32, location: Label) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::JumpIf {
        condition: MemoryAddress::Direct(condition),
        location,
    }
}

fn call(location: Label) -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Call { location }
}

fn ret() -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Return
}

fn trap() -> BrilligOpcode<FieldElement> {
    BrilligOpcode::Trap {
        revert_data: HeapVector {
            pointer: MemoryAddress::Direct(0),
            size: MemoryAddress::Direct(0),
        },
    }
}

/// Placeholder non-terminator body opcode.
fn body() -> BrilligOpcode<FieldElement> {
    mov(0, 0)
}

fn structure(bytecode: &[BrilligOpcode<FieldElement>]) -> StructuredFunction {
    let cfg = Cfg::build(bytecode).expect("Cfg::build should succeed");
    structure_function(&cfg).expect("structure_function should succeed")
}

// Pattern-matching helpers — destructure a node, panic with a clear
// message if it doesn't match.

fn as_if(node: &RegionNode) -> (BlockId, MemoryAddress, &[RegionNode], &[RegionNode]) {
    match node {
        RegionNode::IfThenElse {
            cond_block,
            condition,
            then_branch,
            else_branch,
        } => (*cond_block, *condition, then_branch, else_branch),
        other => panic!("expected IfThenElse, got {other:?}"),
    }
}

fn as_loop(node: &RegionNode) -> (BlockId, Option<EscapeFlagSlot>, &[RegionNode]) {
    match node {
        RegionNode::Loop {
            header,
            escape_flag,
            body,
            ..
        } => (*header, *escape_flag, body),
        other => panic!("expected Loop, got {other:?}"),
    }
}

fn as_call(node: &RegionNode) -> BlockId {
    match node {
        RegionNode::Call { target } => *target,
        other => panic!("expected Call, got {other:?}"),
    }
}

// ── Contrived bytecode tests ────────────────────────────────────────────

#[test]
fn structure_diamond_emits_if_then_else_with_post_dom_join() {
    // Idiomatic Noir diamond:
    //   0: JumpIf cond=7, then=4
    //   1: Jump 2                (paired-Jump; else)
    //   2: body                  (else body)
    //   3: Jump 6
    //   4: body                  (then body)
    //   5: Jump 6
    //   6: Stop                  (join)
    let f = structure(&[
        jump_if(7, 4),
        jump(2),
        body(),
        jump(6),
        body(),
        jump(6),
        brillig_stop(),
    ]);
    let (cond_block, condition, then_branch, else_branch) = as_if(&f.main[1]);
    assert_eq!(cond_block, BlockId(0));
    assert_eq!(condition, MemoryAddress::Direct(7));
    assert!(!then_branch.is_empty(), "then-branch should be non-empty");
    assert!(!else_branch.is_empty(), "else-branch should be non-empty");
    assert!(matches!(f.main.last(), Some(RegionNode::Stop { .. })));
}

#[test]
fn trap_peephole_collapses_assert_pattern() {
    // Canonical assertion shape — `assert(cond)`:
    //   0: JumpIf cond=5, end=3      (cond true → skip to end)
    //   1: body                       (trap arm: error setup)
    //   2: Trap
    //   3: Stop                       (end label)
    let f = structure(&[jump_if(5, 3), body(), trap(), brillig_stop()]);

    assert!(
        !f.main
            .iter()
            .any(|n| matches!(n, RegionNode::IfThenElse { .. })),
        "trap peephole should suppress IfThenElse: {:#?}",
        f.main,
    );
    let condition = f
        .main
        .iter()
        .find_map(|n| match n {
            RegionNode::BoolAssert { condition, .. } => Some(*condition),
            _ => None,
        })
        .expect("expected BoolAssert");
    assert_eq!(condition, MemoryAddress::Direct(5));
}

#[test]
fn structure_simple_while_loop_emits_loop_with_continue_on_true() {
    // Single-exit while loop:
    //   0: JumpIf cond=11, then=2     (continue if true)
    //   1: Jump 4                      (exit arm)
    //   2: body                        (loop body)
    //   3: Jump 0                      (back-edge)
    //   4: Stop
    let f = structure(&[jump_if(11, 2), jump(4), body(), jump(0), brillig_stop()]);
    assert_eq!(f.main_escape_flag_count, 0);

    let loop_node = f
        .main
        .iter()
        .find(|n| matches!(n, RegionNode::Loop { .. }))
        .expect("expected a Loop region");
    let (header, flag, body) = as_loop(loop_node);
    assert_eq!(header, BlockId(0));
    assert!(flag.is_none());
    assert!(!body.is_empty());

    let cond = match loop_node {
        RegionNode::Loop {
            condition: Some(c), ..
        } => *c,
        _ => panic!("expected JumpIf-shaped condition"),
    };
    assert_eq!(cond.polarity, CondPolarity::ContinueOnTrue);
    assert_eq!(cond.register, MemoryAddress::Direct(11));
}

#[test]
fn structure_multi_break_loop_unifies_via_escape_flag() {
    // Two break paths sharing one exit destination — forces escape-flag
    // rewrite. Also exercises the Jump-terminated loop header
    // classification path in `loop_shape::get_loop_shape`.
    //   0: Jump 1                            (header, no condition)
    //   1: JumpIf cond=2, then=6             (first break: jump straight to exit)
    //   2: Jump 3                             (else: continue to next check)
    //   3: JumpIf cond=4, then=6             (second break: same exit)
    //   4: Jump 5                             (else: continue to back-edge)
    //   5: Jump 0                             (back-edge)
    //   6: Stop                               (single exit destination)
    let f = structure(&[
        jump(1),
        jump_if(2, 6),
        jump(3),
        jump_if(4, 6),
        jump(5),
        jump(0),
        brillig_stop(),
    ]);
    assert_eq!(
        f.main_escape_flag_count, 1,
        "expected exactly one escape flag for the multi-exit loop",
    );

    let loop_node = f
        .main
        .iter()
        .find(|n| matches!(n, RegionNode::Loop { .. }))
        .expect("expected a Loop region");
    let (_, flag, body) = as_loop(loop_node);
    let slot = flag.expect("multi-exit loop should have an escape flag");
    let count = count_set_escape_flag(body, slot);
    assert!(
        count >= 2,
        "expected ≥2 SetEscapeFlag(slot {}) nodes, got {count}",
        slot.0,
    );
}

#[test]
fn structure_call_emits_call_node_and_separate_procedure_body() {
    //   0: Call 2          (main: call site)
    //   1: Stop            (main: continuation / exit)
    //   2: body            (procedure body)
    //   3: Return
    let f = structure(&[call(2), brillig_stop(), body(), ret()]);
    let call_node = f
        .main
        .iter()
        .find(|n| matches!(n, RegionNode::Call { .. }))
        .expect("expected a Call region in main");
    assert_eq!(as_call(call_node), BlockId(2));
    let body = f
        .body_of(BlockId(2))
        .expect("procedure body should be available via body_of");
    assert!(
        body.iter().any(|n| matches!(n, RegionNode::Return { .. })),
        "procedure body must end with a Return marker: {body:#?}",
    );
}

// ── Integration helper ──────────────────────────────────────────────────

/// Compiles a `noir_examples` project, runs `Cfg::build` and
/// `structure_function` on every unconstrained function. Panics with a
/// useful message on any failure. Returns the structured form of every
/// function, in input order.
fn structure_noir(project: &str) -> Vec<StructuredFunction> {
    assert!(nargo_available(), "nargo not found on PATH");
    let project_dir = circuits_dir().join(project);
    assert!(
        project_dir.exists(),
        "test circuit directory not found: {}",
        project_dir.display(),
    );
    let artifact = nargo_compile(&project_dir);
    let program = load_program_from_file(&artifact);
    program
        .unconstrained_functions
        .iter()
        .enumerate()
        .map(|(i, func)| {
            let cfg = Cfg::build(&func.bytecode)
                .unwrap_or_else(|e| panic!("Cfg::build failed for fn {i}: {e}"));
            println!(
                "CFG for brillig function {} of project {}, \n{:?}",
                i, project, cfg
            );
            let structure = structure_function(&cfg)
                .unwrap_or_else(|e| panic!("structure_function failed for fn {i}: {e}"));
            println!(
                "Structure of brillig function {} of project {}, \n{:?}",
                i, project, structure
            );
            structure
        })
        .collect()
}

fn total_escape_flag_count(s: &StructuredFunction) -> usize {
    s.main_escape_flag_count
        + s.procedures
            .iter()
            .map(|p| p.escape_flag_count)
            .sum::<usize>()
}

// ── Integration tests ───────────────────────────────────────────────────
// The first four are the minimum-cover fixtures — passing-or-panicking
// is the regression signal.

/// `for i in 0..=u8::MAX { if … { break; } … }`. Noir lowers the
/// inclusive bound as an exclusive loop followed by a final-iteration
/// `JumpIf` diamond; both the break and the natural exit must converge
/// at the diamond's *head*.
///
/// Expected shape per `walker::structure_loop` and `loop_shape`:
/// - single body-internal exit (the break) ⇒ exactly one escape flag
/// - JumpIf-headed `for i < N` ⇒ `condition = Some(_)`, `ContinueOnTrue`
/// - the diamond head is multi-succ ⇒ `walk_to_canonical` stops there ⇒
///   an `IfThenElse` follows the `Loop` (rather than being absorbed)
#[test]
fn noir_inclusive_break_structures() {
    let funcs = structure_noir("inclusive_break");

    // Find the body hosting the for-break Loop. Noir may emit extra
    // Loop-bearing bodies (caller wrappers etc.) — filter to the one with
    // a single escape flag (the break path).
    let bodies: Vec<(&[RegionNode], usize)> = funcs
        .iter()
        .flat_map(|f| {
            std::iter::once((f.main.as_slice(), f.main_escape_flag_count)).chain(
                f.procedures
                    .iter()
                    .map(|p| (p.body.as_slice(), p.escape_flag_count)),
            )
        })
        .collect();
    let (host, _) = *bodies
        .iter()
        .find(|(seq, n)| {
            *n == 1
                && seq
                    .iter()
                    .any(|node| matches!(node, RegionNode::Loop { .. }))
        })
        .expect("expected one body with a Loop and exactly one escape flag");

    let loop_pos = host
        .iter()
        .position(|n| matches!(n, RegionNode::Loop { .. }))
        .expect("host body should contain a Loop");
    assert!(
        host[loop_pos + 1..]
            .iter()
            .all(|n| !matches!(n, RegionNode::Loop { .. })),
        "expected exactly one top-level Loop in the host body: {host:#?}",
    );

    let loop_node = &host[loop_pos];
    let (_, escape_flag, body) = as_loop(loop_node);
    let slot = escape_flag.expect("break path must allocate an escape flag");

    let condition = match loop_node {
        RegionNode::Loop {
            condition: Some(c), ..
        } => *c,
        _ => panic!("for-loop should be JumpIf-headed: {loop_node:?}"),
    };
    assert_eq!(
        condition.polarity,
        CondPolarity::ContinueOnTrue,
        "`for i in 0..N` lowers as `i < N` continuation test",
    );

    assert_eq!(
        count_set_escape_flag(body, slot),
        1,
        "single `break` should emit exactly one SetEscapeFlag(slot {})",
        slot.0,
    );

    assert!(
        host[loop_pos + 1..]
            .iter()
            .any(|n| matches!(n, RegionNode::IfThenElse { .. })),
        "expected a post-loop IfThenElse for the inclusive-range \
         final-iteration diamond: {host:#?}",
    );
}

/// Smoke tests — each fixture exercises a distinct catch in
/// [`super::walker`] / [`super::loop_shape`] that other tests don't reach.
/// Pass-or-panic is the regression signal; per-fixture rationale is
/// inline.
#[test]
fn noir_passes_structurer_smoke_tests() {
    let fixtures = [
        // `find_effective_header` advances past a header JumpIf with both
        // arms in the body; also the header-level trap-peephole
        // (skip-divergent-arm).
        "walk_assert_then_joining",
        // `assert(_, "msg")` in a loop body lowers to a divergent
        // `Call <RevertWithString>` whose continuation byte coincides
        // with another procedure's entry — diverging-JumpIf with both
        // arms divergent and the divergent-Call terminator.
        "panic_in_loop",
        // User-defined divergent helper inside a loop — exercises the
        // procedure-entry fence in `procedure_body` and the Call→target
        // drop in `collect_exit_edges`.
        "divergent_helper_in_loop",
        // Mutually recursive helpers (`is_even` ↔ `is_odd`) — procedure
        // detection on a co-recursive call graph; recursive Call edges
        // emit as leaf Call nodes (no inlining).
        "mutual_recursion",
    ];
    for fixture in fixtures {
        structure_noir(fixture);
    }
}

/// Cascaded `if/else if/else` where each `if` panics on a sentinel.
/// Noir routes the panic sites through a shared dispatcher with its own
/// nested `JumpIf` chain — so each top-level check's divergent branch
/// nests further `IfThenElse` regions (multi-level half-joining).
#[test]
fn noir_cascaded_match_has_deep_half_joining_nesting() {
    let funcs = structure_noir("cascaded_match");

    let mut max_depth_seen = 0;
    let mut top_level_half_joiners = 0;
    for f in &funcs {
        for body in
            std::iter::once(f.main.as_slice()).chain(f.procedures.iter().map(|p| p.body.as_slice()))
        {
            max_depth_seen = max_depth_seen.max(if_then_else_depth(body));
            top_level_half_joiners += count_half_joining_if(body);
        }
    }
    assert!(
        top_level_half_joiners >= 3,
        "expected ≥3 half-joining IfThenElses (got {top_level_half_joiners}) — \
         each cascade level should produce one with an empty branch",
    );
    assert!(
        max_depth_seen >= 3,
        "expected nested IfThenElse depth ≥3 (got {max_depth_seen})",
    );
}

/// `for i in 0..n { if cond { break; } do_more(); }`. `SetEscapeFlag`
/// lands at the tail of the break arm; `do_more()` lives in the else-arm.
/// Also exercises the trap-destination filter in `collect_exit_edges` —
/// the overflow check on `count + 1` jumps to a divergent-Call block that
/// would otherwise look like a non-converging loop exit.
#[test]
fn noir_break_with_trailing_body_allocates_escape_flag() {
    let funcs = structure_noir("break_with_trailing");
    let total: usize = funcs.iter().map(total_escape_flag_count).sum();
    assert!(
        total > 0,
        "expected at least one escape flag for the break path (got {total})",
    );
}

/// `for i in 0..N { if cond { continue; } body; }`. `continue` uses the
/// natural back-edge — no escape flag. Counterpart to `break_with_trailing`.
#[test]
fn noir_continue_with_trailing_body_uses_back_edge() {
    let funcs = structure_noir("continue_with_trailing");
    let total: usize = funcs.iter().map(total_escape_flag_count).sum();
    assert_eq!(
        total, 0,
        "continue should use the back-edge, not an escape flag",
    );
    assert!(
        funcs.iter().any(|f| {
            std::iter::once(f.main.as_slice())
                .chain(f.procedures.iter().map(|p| p.body.as_slice()))
                .any(contains_loop)
        }),
        "expected a runtime Loop to survive (Noir's unroller refuses loops with continue)",
    );
}

/// Nested `for` loops where the inner has a `break`. The inner loop's
/// `LoopCtx` (with its own escape flag) must shadow the outer's during
/// inner-body structuring without colliding on `exit_dest`.
#[test]
fn noir_nested_loops_with_inner_break_emits_nested_loops() {
    let funcs = structure_noir("nested_loops");
    let nested = funcs
        .iter()
        .map(|f| {
            count_nested_loops(&f.main)
                + f.procedures
                    .iter()
                    .map(|p| count_nested_loops(&p.body))
                    .sum::<usize>()
        })
        .sum::<usize>();
    assert!(
        nested == 1,
        "expected at least one Loop nested inside another Loop (got {nested})",
    );
}

/// `while cond { ... }` keyword. The structurer recovers a `Loop` with
/// `CondPolarity::ContinueOnTrue` and no escape flag.
#[test]
fn noir_while_loop_recovers_continue_on_true_polarity() {
    let funcs = structure_noir("while_loop");
    let total: usize = funcs.iter().map(total_escape_flag_count).sum();
    assert_eq!(
        total, 0,
        "a `while` with no break needs no escape flag (got {total})",
    );

    let cond = funcs
        .iter()
        .find_map(|f| {
            std::iter::once(f.main.as_slice())
                .chain(f.procedures.iter().map(|p| p.body.as_slice()))
                .find_map(find_loop_condition)
        })
        .expect("expected a JumpIf-headed Loop with a continuation condition");
    assert_eq!(
        cond.polarity,
        CondPolarity::ContinueOnTrue,
        "`while cond` should produce a ContinueOnTrue header",
    );
}

// ── Tree-walking helpers ────────────────────────────────────────────────

fn count_set_escape_flag(seq: &[RegionNode], slot: EscapeFlagSlot) -> usize {
    let mut total = 0;
    for n in seq {
        match n {
            RegionNode::SetEscapeFlag { slot: s } if *s == slot => total += 1,
            RegionNode::IfThenElse {
                then_branch,
                else_branch,
                ..
            } => {
                total += count_set_escape_flag(then_branch, slot);
                total += count_set_escape_flag(else_branch, slot);
            }
            RegionNode::Loop {
                test_prefix, body, ..
            } => {
                total += count_set_escape_flag(test_prefix, slot);
                total += count_set_escape_flag(body, slot);
            }
            _ => {}
        }
    }
    total
}

/// Counts `Loop` regions that are nested inside another `Loop` region's
/// body (at any depth).
fn count_nested_loops(seq: &[RegionNode]) -> usize {
    fn count_loops_in(seq: &[RegionNode]) -> usize {
        let mut n = 0;
        for node in seq {
            match node {
                RegionNode::Loop {
                    test_prefix, body, ..
                } => {
                    n += 1;
                    n += count_loops_in(test_prefix);
                    n += count_loops_in(body);
                }
                RegionNode::IfThenElse {
                    then_branch,
                    else_branch,
                    ..
                } => {
                    n += count_loops_in(then_branch);
                    n += count_loops_in(else_branch);
                }
                _ => {}
            }
        }
        n
    }
    let mut nested = 0;
    for node in seq {
        match node {
            RegionNode::Loop {
                test_prefix, body, ..
            } => nested += count_loops_in(test_prefix) + count_loops_in(body),
            RegionNode::IfThenElse {
                then_branch,
                else_branch,
                ..
            } => nested += count_nested_loops(then_branch) + count_nested_loops(else_branch),
            _ => {}
        }
    }
    nested
}

/// Maximum nesting depth of `IfThenElse` regions in `seq`. A standalone
/// `IfThenElse` is depth 1; one whose branches contain another is depth 2.
fn if_then_else_depth(seq: &[RegionNode]) -> usize {
    let mut max = 0;
    for node in seq {
        let depth = match node {
            RegionNode::IfThenElse {
                then_branch,
                else_branch,
                ..
            } => 1 + if_then_else_depth(then_branch).max(if_then_else_depth(else_branch)),
            RegionNode::Loop {
                test_prefix, body, ..
            } => if_then_else_depth(test_prefix).max(if_then_else_depth(body)),
            _ => 0,
        };
        max = max.max(depth);
    }
    max
}

/// Counts top-level `IfThenElse` nodes in `seq` whose `then_branch` or
/// `else_branch` is empty — the half-joining shape produced when one arm
/// of a `JumpIf` is always-divergent.
fn count_half_joining_if(seq: &[RegionNode]) -> usize {
    seq.iter()
        .filter(|n| {
            matches!(
                n,
                RegionNode::IfThenElse { then_branch, else_branch, .. }
                if then_branch.is_empty() || else_branch.is_empty()
            )
        })
        .count()
}

/// First `LoopCondition` found in any `Loop` region, recursing through
/// `IfThenElse` arms. Returns `None` for Jump-headed `loop {}` bodies.
fn find_loop_condition(seq: &[RegionNode]) -> Option<LoopCondition> {
    for node in seq {
        match node {
            RegionNode::Loop {
                condition: Some(cond),
                ..
            } => return Some(*cond),
            RegionNode::Loop {
                test_prefix, body, ..
            } => {
                if let Some(c) = find_loop_condition(test_prefix) {
                    return Some(c);
                }
                if let Some(c) = find_loop_condition(body) {
                    return Some(c);
                }
            }
            RegionNode::IfThenElse {
                then_branch,
                else_branch,
                ..
            } => {
                if let Some(c) = find_loop_condition(then_branch) {
                    return Some(c);
                }
                if let Some(c) = find_loop_condition(else_branch) {
                    return Some(c);
                }
            }
            _ => {}
        }
    }
    None
}

/// True iff `seq` contains a `Loop` region at any depth.
fn contains_loop(seq: &[RegionNode]) -> bool {
    seq.iter().any(|n| match n {
        RegionNode::Loop { .. } => true,
        RegionNode::IfThenElse {
            then_branch,
            else_branch,
            ..
        } => contains_loop(then_branch) || contains_loop(else_branch),
        _ => false,
    })
}
