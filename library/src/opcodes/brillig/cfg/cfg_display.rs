//! [`Debug`] rendering for [`Cfg`] — block ranges, successor/dominator/
//! post-dominator trees, natural loops, and per-procedure subtrees.

use std::collections::BTreeSet;
use std::fmt;

use super::{BlockId, Cfg, DomTree, Terminator};

impl fmt::Debug for Cfg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.blocks.len();
        writeln!(
            f,
            "Cfg: {} block{}, {} loop{}, {} procedure{}",
            n,
            s(n),
            self.loops.len(),
            s(self.loops.len()),
            self.procedures.len(),
            s(self.procedures.len()),
        )?;

        writeln!(f, "\nBlocks (bytecode ranges):")?;
        for (i, b) in self.blocks.iter().enumerate() {
            writeln!(
                f,
                "  b{i}: [{}, {}) {}",
                b.start,
                b.end_exclusive,
                kind(&b.terminator),
            )?;
        }

        writeln!(f, "\nSuccessor tree (DFS from b0):")?;
        let mut seen = vec![false; n];
        dfs(f, BlockId(0), &self.successors, None, &mut seen, "", "")?;
        let u: Vec<_> = (0..n).map(BlockId).filter(|b| !seen[b.0]).collect();
        if !u.is_empty() {
            writeln!(f, "  (unreached from b0: {})", ids(&u, '[', ']'))?;
        }

        writeln!(f, "\nDominator tree:")?;
        let dk = dom_kids(&self.dominators, n);
        // The forward dom tree is a forest: `BlockId(0)` plus every
        // procedure entry is a root (idom is None). Render each root as
        // its own subtree.
        let is_live = |b: BlockId| !matches!(self.blocks[b.0].terminator, Terminator::Unreachable);
        for r in (0..n)
            .map(BlockId)
            .filter(|&b| self.dominators.idom(b).is_none() && is_live(b))
        {
            walk(f, r, &dk, "", "")?;
        }

        writeln!(f, "\nPost-dominator tree:")?;
        let pk = dom_kids(&self.post_dominators, n);
        for r in (0..n)
            .map(BlockId)
            .filter(|&b| self.post_dominators.idom(b).is_none() && is_live(b))
        {
            walk(f, r, &pk, "", "")?;
        }

        writeln!(
            f,
            "\nNatural loops:{}",
            if self.loops.is_empty() { " none" } else { "" },
        )?;
        for l in &self.loops {
            writeln!(
                f,
                "  header=b{}  body={}",
                l.header.0,
                ids(&l.body, '{', '}'),
            )?;
        }

        writeln!(
            f,
            "\nProcedures:{}",
            if self.procedures.is_empty() {
                " none"
            } else {
                ""
            },
        )?;
        for (i, p) in self.procedures.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            match p.return_block {
                Some(b) => writeln!(f, "  entry=b{}  return=b{}", p.entry.0, b.0)?,
                None => writeln!(f, "  entry=b{}  diverging (no return)", p.entry.0)?,
            }
            let mut v = vec![false; n];
            dfs(f, p.entry, &self.successors, Some(&p.body), &mut v, "", "")?;
        }
        Ok(())
    }
}

fn s(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

fn kind(t: &Terminator) -> &'static str {
    match t {
        Terminator::Jump(_) => "jump",
        Terminator::Fallthrough(_) => "fall-through",
        Terminator::JumpIf { .. } => "if/else",
        Terminator::Call { .. } => "call",
        Terminator::Return => "return",
        Terminator::Stop => "stop",
        Terminator::Trap => "trap",
        Terminator::TrapReturn => "trap-return",
        Terminator::Unreachable => "unreachable",
    }
}

fn dom_kids(d: &DomTree, n: usize) -> Vec<Vec<BlockId>> {
    let mut k = vec![Vec::new(); n];
    for i in 0..n {
        if let Some(p) = d.idom(BlockId(i)) {
            k[p.0].push(BlockId(i));
        }
    }
    k
}

fn cont(c: &str) -> &'static str {
    match c {
        "├── " => "│   ",
        "└── " => "    ",
        _ => "",
    }
}

fn walk(
    f: &mut fmt::Formatter<'_>,
    b: BlockId,
    k: &[Vec<BlockId>],
    p: &str,
    c: &str,
) -> fmt::Result {
    writeln!(f, "  {p}{c}b{}", b.0)?;
    let pp = format!("{p}{}", cont(c));
    let ks = &k[b.0];
    for (i, &x) in ks.iter().enumerate() {
        walk(
            f,
            x,
            k,
            &pp,
            if i + 1 == ks.len() {
                "└── "
            } else {
                "├── "
            },
        )?;
    }
    Ok(())
}

fn dfs(
    f: &mut fmt::Formatter<'_>,
    b: BlockId,
    succ: &[Vec<BlockId>],
    body: Option<&BTreeSet<BlockId>>,
    seen: &mut [bool],
    p: &str,
    c: &str,
) -> fmt::Result {
    if seen[b.0] {
        return writeln!(f, "  {p}{c}b{} (seen)", b.0);
    }
    seen[b.0] = true;
    writeln!(f, "  {p}{c}b{}", b.0)?;
    let pp = format!("{p}{}", cont(c));
    let ks: Vec<_> = succ[b.0]
        .iter()
        .copied()
        .filter(|x| body.map_or(true, |t| t.contains(x)))
        .collect();
    for (i, &x) in ks.iter().enumerate() {
        dfs(
            f,
            x,
            succ,
            body,
            seen,
            &pp,
            if i + 1 == ks.len() {
                "└── "
            } else {
                "├── "
            },
        )?;
    }
    Ok(())
}

fn ids<'a, I: IntoIterator<Item = &'a BlockId>>(iter: I, open: char, close: char) -> String {
    let v: Vec<_> = iter.into_iter().map(|b| format!("b{}", b.0)).collect();
    format!("{open}{}{close}", v.join(", "))
}
