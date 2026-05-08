//! [`Debug`] rendering for [`StructuredFunction`] and [`RegionNode`] —
//! a tree-style dump that mirrors the structurer's recursive shape.

use std::fmt;

use acir::brillig::MemoryAddress;

use super::{CondPolarity, EscapeFlagSlot, LoopCondition, RegionNode, StructuredFunction};

impl fmt::Debug for StructuredFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "StructuredFunction: {} main region{} ({} escape flag{}), {} procedure{}",
            self.main.len(),
            s(self.main.len()),
            self.main_escape_flag_count,
            s(self.main_escape_flag_count),
            self.procedures.len(),
            s(self.procedures.len()),
        )?;
        writeln!(f, "main:")?;
        write_seq(f, &self.main, "")?;
        for proc in &self.procedures {
            writeln!(
                f,
                "procedure b{} ({} region{}, {} escape flag{}):",
                proc.entry.0,
                proc.body.len(),
                s(proc.body.len()),
                proc.escape_flag_count,
                s(proc.escape_flag_count),
            )?;
            write_seq(f, &proc.body, "")?;
        }
        Ok(())
    }
}

impl fmt::Debug for RegionNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_node(f, self, "", "")
    }
}

// ── Tree walker ────────────────────────────────────────────────────────

fn write_seq(f: &mut fmt::Formatter<'_>, seq: &[RegionNode], prefix: &str) -> fmt::Result {
    let last = seq.len().saturating_sub(1);
    for (i, node) in seq.iter().enumerate() {
        let connector = if i == last {
            "└── "
        } else {
            "├── "
        };
        write_node(f, node, prefix, connector)?;
    }
    Ok(())
}

fn write_node(
    f: &mut fmt::Formatter<'_>,
    node: &RegionNode,
    prefix: &str,
    connector: &str,
) -> fmt::Result {
    let child_prefix = format!("{prefix}{}", cont(connector));
    match node {
        RegionNode::Linear { block } => {
            writeln!(f, "{prefix}{connector}Linear(b{})", block.0)
        }
        RegionNode::IfThenElse {
            cond_block,
            condition,
            then_branch,
            else_branch,
        } => {
            writeln!(
                f,
                "{prefix}{connector}IfThenElse(cond={}, at b{})",
                fmt_addr(condition),
                cond_block.0,
            )?;
            write_arm(f, "then", then_branch, &child_prefix, false)?;
            write_arm(f, "else", else_branch, &child_prefix, true)
        }
        RegionNode::Loop {
            header,
            test_prefix,
            condition,
            escape_flag,
            body,
        } => {
            writeln!(
                f,
                "{prefix}{connector}Loop(header=b{}, cond={}, flag={})",
                header.0,
                fmt_loop_cond(condition),
                fmt_flag(escape_flag),
            )?;
            write_arm(f, "test_prefix", test_prefix, &child_prefix, false)?;
            write_arm(f, "body", body, &child_prefix, true)
        }
        RegionNode::SetEscapeFlag { slot } => {
            writeln!(f, "{prefix}{connector}SetEscapeFlag({})", fmt_slot(slot))
        }
        RegionNode::Call { target } => {
            writeln!(f, "{prefix}{connector}Call(target=b{})", target.0)
        }
        RegionNode::BoolAssert {
            cond_block,
            condition,
        } => {
            writeln!(
                f,
                "{prefix}{connector}BoolAssert(cond={}, at b{})",
                fmt_addr(condition),
                cond_block.0
            )
        }
        RegionNode::Trap { block } => {
            writeln!(f, "{prefix}{connector}Trap(b{})", block.0)
        }
        RegionNode::Stop { block } => {
            writeln!(f, "{prefix}{connector}Stop(b{})", block.0)
        }
        RegionNode::Return { block } => {
            writeln!(f, "{prefix}{connector}Return(b{})", block.0)
        }
    }
}

fn write_arm(
    f: &mut fmt::Formatter<'_>,
    label: &str,
    seq: &[RegionNode],
    prefix: &str,
    is_last: bool,
) -> fmt::Result {
    let connector = if is_last { "└── " } else { "├── " };
    if seq.is_empty() {
        writeln!(f, "{prefix}{connector}{label}: (empty)")
    } else {
        writeln!(f, "{prefix}{connector}{label}:")?;
        let inner_prefix = format!("{prefix}{}", cont(connector));
        write_seq(f, seq, &inner_prefix)
    }
}

// ── Formatting helpers ─────────────────────────────────────────────────

fn cont(connector: &str) -> &'static str {
    match connector {
        "├── " => "│   ",
        "└── " => "    ",
        _ => "",
    }
}

fn s(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

fn fmt_addr(addr: &MemoryAddress) -> String {
    match addr {
        MemoryAddress::Direct(i) => format!("d{i}"),
        MemoryAddress::Relative(i) => format!("r{i}"),
    }
}

fn fmt_loop_cond(cond: &Option<LoopCondition>) -> String {
    match cond {
        Some(LoopCondition { register, polarity }) => {
            let polarity = match polarity {
                CondPolarity::ContinueOnTrue => "continue-on-true",
                CondPolarity::ExitOnTrue => "exit-on-true",
            };
            format!("{} {polarity}", fmt_addr(register))
        }
        None => "always".into(),
    }
}

fn fmt_flag(flag: &Option<EscapeFlagSlot>) -> String {
    flag.map(|EscapeFlagSlot(i)| format!("slot{i}"))
        .unwrap_or_else(|| "none".into())
}

fn fmt_slot(slot: &EscapeFlagSlot) -> String {
    format!("slot{}", slot.0)
}
