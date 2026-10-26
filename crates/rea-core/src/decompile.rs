//! Pseudo-C from Capstone for the architectures already disassembled.
//!
//! This is a structured listing: assignments, calls, gotos, and returns, that
//! follows unconditional `jmp` / `b` / `br` with a direct target inside the
//! enclosing function — bounds come from rea-core's function discovery, or
//! from the forward-jump walk from the address itself when no discovered
//! function covers it. One forward conditional (`jcc` on x86_64, `b.cond` on
//! arm64) whose target is inside the same function and ahead of the branch is
//! also followed: the fall-through block is listed up to the target, where
//! both paths join, and the walk continues from there. The listing keeps the
//! 64-instruction cap and follows at most 8 hops; a repeated target, an
//! out-of-function branch, an indirect jump, or a `ret` ends it. A backward
//! conditional, or one whose target is outside the function, stays a `goto`
//! line and its taken path is not explored. On x86_64 and arm64, registers
//! that receive a value of known width are rendered as synthetic typed locals
//! (`int v1; void* v2;`): loads are typed by the signedness and width of the
//! load mnemonic, and `lea` / `adrp`+`add` targets become `void*`. A type
//! flows through a followed join while the register state is trivially
//! carried (same physical register, no writes in the skipped gap); across a
//! conditional join, a type carries only when every incoming path agrees on
//! it — an unsound join drops the type instead of guessing. A store of a
//! typed register to a stack slot (`[rbp±N]` / `[rsp±N]` on x86_64,
//! `[sp, #N]` on arm64; N decimal or Capstone's hex) and a later load from that same slot reuse the type:
//! the slot itself never becomes a synthetic local, so reloading into the
//! register that typed the slot stays one local, and a slot written with two
//! different types — or with unknown data — becomes untyped. Heap addresses,
//! struct fields, and cross-function stack layouts keep no types. It is
//! still not a type-recovering decompiler: struct recovery and
//! cross-function dataflow stay out of scope. A short or unmapped body
//! returns an error from disassembly and does not invent instructions.

use crate::{analysis, disasm, Arch, Error, Result, Target};
use std::collections::{HashMap, HashSet};

/// A stack slot: `(base, displacement)` — base `0` is `rbp`, `1` is `rsp`
/// (x86_64), `2` is `sp` (arm64); displacement in bytes, signed.
type SlotKey = (u8, i64);

/// A slot's recorded type and the window index of the store that set it.
#[derive(Clone, Copy)]
struct SlotSnap {
    ty: Option<&'static str>,
    at: usize,
    /// A slot that saw two different types is poisoned: it stays untyped
    /// even when a later typed store arrives.
    poisoned: bool,
}

/// Unconditional-jump hops the window follows within one function.
const MAX_HOPS: u32 = 8;

/// Gap instructions decoded per hop to check for register writes. A longer
/// or undecodable gap is unknown, and carried types are dropped at the join.
const MAX_GAP: usize = 16;

/// A skipped gap behind a followed jump. `after` is the window index of the
/// first instruction at the join; `insns` are the skipped instructions when
/// they decoded fully, `None` otherwise.
struct Gap {
    after: usize,
    insns: Option<Vec<disasm::Instruction>>,
}

/// A followed conditional branch's join. `branch` is the window index of the
/// branch itself, `after` the window index of the first instruction at its
/// target, and `insns` the listed fall-through block between the two.
struct CondJoin {
    branch: usize,
    after: usize,
    insns: Vec<disasm::Instruction>,
}

/// Pseudo-C for at most `limit` instructions from `addr`, following
/// unconditional jumps and one forward conditional inside the enclosing
/// function. `limit` is capped at 64.
pub fn decompile(target: &Target, addr: u64, limit: usize) -> Result<String> {
    let limit = limit.clamp(1, 64);
    let (insns, skipped, gaps, joins) = walk(target, addr, limit)?;
    if insns.is_empty() {
        return Err(Error::Parse("decompile: no instructions".into()));
    }
    let typed = plan_types(&insns, target.arch, &gaps, &joins);
    let (declared, kills) = carry_types(&typed, &gaps, &joins, target.arch);
    let mut names = Names::new(target.arch);
    let mut next = 0usize;
    let mut dead = 0usize;
    let mut body = String::new();
    for (i, insn) in insns.iter().enumerate() {
        // A register carries its type from the instruction that typed it on,
        // until a join where its state is not trivially carried.
        while next < declared.len() && declared[next].0.first <= i {
            let (reg, n) = declared[next];
            names.activate(reg, n);
            next += 1;
        }
        while dead < kills.len() && kills[dead].0 <= i {
            names.deactivate(&kills[dead].1);
            dead += 1;
        }
        // A followed jump renders nothing: the target block carries a label.
        if skipped.contains(&i) {
            continue;
        }
        body.push_str(&format!("loc_{:x}:\n  {};\n", insn.addr, statement(insn, &names)));
    }
    let header: String = declared
        .iter()
        .map(|(r, n)| format!("  {} v{};\n", r.ty, n))
        .collect();
    Ok(format!("void sub_{addr:x}() {{\n{header}{body}}}\n"))
}

/// Walk the window from `addr`, following unconditional jumps whose direct
/// target stays inside `[fstart, fend)`. One forward conditional (`jcc` /
/// `b.cond`) whose target is inside the function and ahead of the branch is
/// also followed: its fall-through block is listed up to the target, where
/// both paths join, and the walk continues from there; a fall-through that
/// stops short of the target leaves the branch an ordinary `goto` line.
/// Returns the flow-ordered instructions, the indices of followed jumps (not
/// rendered), the gaps behind them, and the conditional joins. Stops at
/// `ret`, an indirect or out-of-bounds branch (rendered as `goto`), a
/// repeated target, the instruction cap, or undecodable bytes.
fn walk(
    target: &Target,
    addr: u64,
    limit: usize,
) -> Result<(
    Vec<disasm::Instruction>,
    HashSet<usize>,
    Vec<Gap>,
    Vec<CondJoin>,
)> {
    let (fstart, fend) = function_bounds(target, addr);
    let mut out: Vec<disasm::Instruction> = Vec::new();
    let mut gaps: Vec<Gap> = Vec::new();
    let mut joins: Vec<CondJoin> = Vec::new();
    let mut skipped: HashSet<usize> = HashSet::new();
    let mut visited: HashSet<u64> = HashSet::new();
    let mut cur = addr;
    let mut remaining = limit;
    let mut hops = 0u32;
    let mut cond_done = false;
    loop {
        let chunk = match disasm::disassemble(target, cur, remaining) {
            Ok(c) => c,
            Err(e) => {
                if out.is_empty() {
                    return Err(Error::Parse(e.to_string()));
                }
                break;
            }
        };
        if chunk.is_empty() {
            break;
        }
        // Capstone stops at invalid bytes: a short chunk has no continuation.
        let complete = chunk.len() == remaining;
        let mut stop = false;
        let mut jumped = false;
        for insn in &chunk {
            visited.insert(insn.addr);
            out.push(insn.clone());
            remaining -= 1;
            let m = insn.mnemonic.as_str();
            if m == "jmp" || m == "b" || m == "br" {
                let t = analysis::direct_target(&insn.operands);
                // Any direct target inside the function follows, forward or
                // backward; the visited set ends a path that re-enters code
                // already listed, which is what bounds a loop.
                let followable = matches!(t, Some(t) if t >= fstart
                    && t < fend
                    && !visited.contains(&t)
                    && hops < MAX_HOPS
                    && remaining > 0);
                match t {
                    Some(t) if followable => {
                        let gap_end = insn.addr.saturating_add(insn.size as u64);
                        let gap = if t > gap_end {
                            scan_gap(target, gap_end, t)
                        } else {
                            Some(Vec::new())
                        };
                        gaps.push(Gap { after: out.len(), insns: gap });
                        skipped.insert(out.len() - 1);
                        hops += 1;
                        cur = t;
                        jumped = true;
                    }
                    _ => stop = true,
                }
                break;
            }
            // One forward conditional per window: list the fall-through block
            // and continue at the target, where both paths join. A backward
            // or out-of-function target stays a `goto` line.
            if !cond_done && followable_cond(m, target.arch) {
                if let Some(t) = analysis::direct_target(&insn.operands) {
                    let branch_end = insn.addr.saturating_add(insn.size as u64);
                    let followable = t > insn.addr
                        && t >= fstart
                        && t < fend
                        && !visited.contains(&t)
                        && hops < MAX_HOPS;
                    if followable {
                        if let Some(fall) = walk_fallthrough(target, branch_end, t, remaining) {
                            let branch_at = out.len() - 1;
                            for fi in &fall {
                                visited.insert(fi.addr);
                                out.push(fi.clone());
                            }
                            remaining -= fall.len();
                            joins.push(CondJoin {
                                branch: branch_at,
                                after: out.len(),
                                insns: fall,
                            });
                            hops += 1;
                            cond_done = true;
                            cur = t;
                            jumped = true;
                            break;
                        }
                    }
                }
            }
            if m == "ret" || m == "retf" {
                stop = true;
                break;
            }
            if remaining == 0 {
                stop = true;
                break;
            }
        }
        if stop {
            break;
        }
        if jumped {
            continue;
        }
        if !complete {
            break;
        }
        let last = chunk.last().unwrap();
        cur = last.addr.saturating_add(last.size as u64);
    }
    Ok((out, skipped, gaps, joins))
}

/// Instructions in the skipped gap `(from, to)`, decoded to check for
/// register writes. `None` when the gap does not decode fully: the carried
/// state is then unknown and dropped at the join.
fn scan_gap(target: &Target, from: u64, to: u64) -> Option<Vec<disasm::Instruction>> {
    let insns = disasm::disassemble(target, from, MAX_GAP).ok()?;
    let last = insns.last()?;
    if last.addr.saturating_add(last.size as u64) < to {
        return None;
    }
    Some(insns.into_iter().take_while(|i| i.addr < to).collect())
}

/// The fall-through block of a followed conditional: the instructions from
/// `from` up to (not including) the join target `to`, decoded linearly within
/// `budget`. `None` when the block does not decode cleanly to `to` — a
/// `ret`, a branch, undecodable bytes, an instruction straddling `to`, or
/// the budget spent — because the path then stops short of the join and the
/// branch stays an ordinary `goto` line.
fn walk_fallthrough(
    target: &Target,
    from: u64,
    to: u64,
    budget: usize,
) -> Option<Vec<disasm::Instruction>> {
    let mut out = Vec::new();
    let mut cur = from;
    while cur < to {
        if out.len() >= budget {
            return None;
        }
        let insns = disasm::disassemble(target, cur, 1).ok()?;
        let insn = insns.into_iter().next()?;
        let end = insn.addr.checked_add(insn.size as u64)?;
        if end > to {
            return None;
        }
        let m = insn.mnemonic.as_str();
        if m == "ret"
            || m == "retf"
            || m == "jmp"
            || m == "b"
            || m == "br"
            || m.starts_with("invalid")
            || is_cond(m)
        {
            return None;
        }
        out.push(insn);
        cur = end;
    }
    Some(out)
}

/// Bounds of the function containing `addr`, from rea-core's function
/// discovery. When no discovered function covers `addr`, the forward-jump
/// walk from `addr` itself gives conservative bounds.
fn function_bounds(target: &Target, addr: u64) -> (u64, u64) {
    let covered = analysis::discover_functions(target)
        .iter()
        .find(|f| f.addr <= addr && addr - f.addr < f.size)
        .map(|f| {
            let size = f.size;
            (f.addr, f.addr.saturating_add(size))
        });
    covered.unwrap_or_else(|| {
        let (size, _) = analysis::function_body(target, addr, 0x20000);
        (addr, addr.saturating_add(size))
    })
}

/// The canonical register an instruction writes through its first operand,
/// if it names one.
fn written_reg(insn: &disasm::Instruction, arch: Arch) -> Option<String> {
    let (dst, _) = split_first(&insn.operands)?;
    canonical_of(arch, dst)
}

/// Where each typed register's type dies: the index after which the renderer
/// drops it. A skipped gap that writes the register (or that does not decode)
/// kills it at the join; a followed conditional kills it when the incoming
/// paths disagree.
fn register_deaths(
    typed: &[TypedReg],
    gaps: &[Gap],
    joins: &[CondJoin],
    arch: Arch,
) -> HashMap<String, usize> {
    let mut kill: HashMap<String, usize> = HashMap::new();
    for gap in gaps {
        let dead: Vec<String> = match &gap.insns {
            Some(insns) => insns.iter().filter_map(|i| written_reg(i, arch)).collect(),
            None => typed.iter().map(|r| r.aliases[0].clone()).collect(),
        };
        for reg in dead {
            let first = typed.iter().find(|r| r.aliases[0] == reg).map(|r| r.first);
            if first.map_or(false, |f| f < gap.after) {
                kill.entry(reg)
                    .and_modify(|k| *k = (*k).min(gap.after))
                    .or_insert(gap.after);
            }
        }
    }
    for join in joins {
        // Types established before the branch, as the direct path carries
        // them into the join.
        let pre: HashMap<String, &'static str> = typed
            .iter()
            .filter(|r| r.first < join.branch)
            .map(|r| (r.aliases[0].clone(), r.ty))
            .collect();
        for r in typed {
            if r.first >= join.after {
                continue;
            }
            let reg = &r.aliases[0];
            let disagreed = if r.first >= join.branch {
                // First typed inside the fall-through block: the direct path
                // arrives with the register untyped.
                true
            } else {
                // Replay the block's writes: the carried type survives only
                // when the block leaves the same type the direct path has.
                let mut state = Some(r.ty);
                for insn in &join.insns {
                    if written_reg(insn, arch).as_deref() == Some(reg.as_str()) {
                        state = infer_insn(insn, arch, &pre)
                            .filter(|(c, _)| c == reg)
                            .map(|(_, ty)| ty);
                    }
                }
                state != Some(r.ty)
            };
            if disagreed {
                kill.entry(reg.clone())
                    .and_modify(|k| *k = (*k).min(join.after))
                    .or_insert(join.after);
            }
        }
    }
    kill
}

/// Resolve which typed registers survive the followed joins. A register keeps
/// its type across an unconditional hop when the skipped gap holds no write
/// to it (same physical register, no intervening writes); an undecodable gap
/// drops every type carried into the join. Across a followed conditional's
/// join, the incoming paths are the fall-through block and the direct entry
/// at the target: a type carries only when every incoming path agrees on it —
/// a register first typed inside the fall-through block is untyped on the
/// direct path, and a block write that leaves a different type (or no
/// inferable type) kills the carried type. Returns the declared registers
/// with their synthetic-local numbers, and the window index after which each
/// type dies.
fn carry_types<'a>(
    typed: &'a [TypedReg],
    gaps: &[Gap],
    joins: &[CondJoin],
    arch: Arch,
) -> (Vec<(&'a TypedReg, usize)>, Vec<(usize, String)>) {
    let kill = register_deaths(typed, gaps, joins, arch);
    let declared: Vec<(&TypedReg, usize)> =
        typed.iter().enumerate().map(|(n, r)| (r, n + 1)).collect();
    let mut kills: Vec<(usize, String)> = typed
        .iter()
        .filter_map(|r| {
            kill.get(&r.aliases[0])
                .copied()
                .filter(|k| *k > r.first)
                .map(|k| (k, r.aliases[0].clone()))
        })
        .collect();
    kills.sort_by_key(|k| k.0);
    (declared, kills)
}

fn statement(insn: &disasm::Instruction, names: &Names) -> String {
    let m = insn.mnemonic.as_str();
    let ops = insn.operands.as_str();
    if m == "ret" || m == "retf" {
        return names.return_stmt();
    }
    if m == "call" || m == "bl" || m == "blx" {
        let target = ops.split(',').next().unwrap_or(ops).trim();
        let args = names.call_args();
        if args.is_empty() {
            return format!("{target}()");
        }
        return format!("{target}({})", args.join(", "));
    }
    if m == "jmp" || m == "b" || m == "br" {
        return format!("goto {ops}");
    }
    if is_cond(m) {
        let target = branch_target(ops);
        return format!("if ({m}) goto {target}");
    }
    if m == "mov" || m == "ldr" {
        if let Some((dst, src)) = split_two(ops) {
            return names.rename(&format!("{dst} = {src}"));
        }
    }
    if let Some(text) = names.typed_assignment(insn) {
        return text;
    }
    let raw = if ops.is_empty() {
        m.to_string()
    } else {
        format!("{m} {ops}")
    };
    names.rename(&raw)
}

/// Whether the window may follow `m` as a conditional branch: `jcc` on
/// x86_64, `b.cond` on arm64. Other architectures stay linear.
fn followable_cond(m: &str, arch: Arch) -> bool {
    match arch {
        Arch::X86_64 => m.starts_with('j') && m != "jmp",
        Arch::Arm64 => m.starts_with("b."),
        _ => false,
    }
}

fn is_cond(m: &str) -> bool {
    matches!(
        m,
        "je" | "jne"
            | "jz"
            | "jnz"
            | "jl"
            | "jle"
            | "jg"
            | "jge"
            | "jb"
            | "jbe"
            | "ja"
            | "jae"
            | "js"
            | "jns"
            | "jo"
            | "jno"
            | "beq"
            | "bne"
            | "blt"
            | "ble"
            | "bgt"
            | "bge"
            | "bcc"
            | "bcs"
            | "b.eq"
            | "b.ne"
            | "b.lt"
            | "b.le"
            | "b.gt"
            | "b.ge"
            | "b.lo"
            | "b.hs"
            | "cbz"
            | "cbnz"
            | "tbz"
            | "tbnz"
    ) || m.starts_with("b.")
}

fn branch_target(ops: &str) -> &str {
    ops.rsplit(',').next().unwrap_or(ops).trim()
}

fn split_two(ops: &str) -> Option<(&str, &str)> {
    let (dst, src) = ops.split_once(',')?;
    let dst = dst.trim();
    let src = src.trim();
    if dst.is_empty() || src.is_empty() || src.contains(',') {
        return None;
    }
    Some((dst, src))
}

/// First comma split; the source side may itself contain commas (arm64
/// load/store addressing), which [`split_two`] rejects.
fn split_first(ops: &str) -> Option<(&str, &str)> {
    let (dst, src) = ops.split_once(',')?;
    let dst = dst.trim();
    let src = src.trim();
    if dst.is_empty() || src.is_empty() {
        return None;
    }
    Some((dst, src))
}

/// A register that received a value of known width in the window, keyed by its
/// canonical 64-bit name with every alias it is spelled as. `first` is the
/// window index of the instruction that typed it.
struct TypedReg {
    aliases: Vec<String>,
    ty: &'static str,
    first: usize,
}

/// Synthetic typed locals in first appearance order, plus casts at call
/// arguments and returns. Types activate at their typing instruction and flow
/// forward through the window.
struct Names {
    arch: Arch,
    /// alias spelling -> synthetic local name
    alias: HashMap<String, String>,
    /// canonical register -> C type
    types: HashMap<String, &'static str>,
}

impl Names {
    fn new(arch: Arch) -> Names {
        Names {
            arch,
            alias: HashMap::new(),
            types: HashMap::new(),
        }
    }

    fn activate(&mut self, reg: &TypedReg, n: usize) {
        let v = format!("v{n}");
        for a in &reg.aliases {
            self.alias.insert(a.clone(), v.clone());
        }
        self.types.insert(reg.aliases[0].clone(), reg.ty);
    }

    /// Drop a register's type at a join where its state is not trivially
    /// carried: statements from there on use the raw register name again.
    fn deactivate(&mut self, canon: &str) {
        for a in aliases_of(canon) {
            self.alias.remove(&a);
        }
        self.types.remove(canon);
    }

    fn name<'a>(&'a self, canon: &'a str) -> &'a str {
        self.alias.get(canon).map(String::as_str).unwrap_or(canon)
    }

    /// Replace every register spelling in `text` with its synthetic local name.
    fn rename(&self, text: &str) -> String {
        if self.alias.is_empty() {
            return text.to_string();
        }
        let mut out = String::with_capacity(text.len());
        let mut tok = String::new();
        for ch in text.chars() {
            if ch.is_ascii_alphanumeric() {
                tok.push(ch);
                continue;
            }
            if !tok.is_empty() {
                out.push_str(self.alias.get(&tok).unwrap_or(&tok));
                tok.clear();
            }
            out.push(ch);
        }
        if !tok.is_empty() {
            out.push_str(self.alias.get(&tok).unwrap_or(&tok));
        }
        out
    }

    /// Assignment rendering for a typed load or address formation, if the
    /// destination carries an inferred type.
    fn typed_assignment(&self, insn: &disasm::Instruction) -> Option<String> {
        let m = insn.mnemonic.as_str();
        let ops = insn.operands.as_str();
        let is_addr = matches!(m, "lea" | "adrp" | "adr");
        let is_load = matches!(m, "movzx" | "movsx" | "movsxd")
            || m.starts_with("ldr")
            || m.starts_with("ldur")
            || is_addr;
        if !is_load || (!is_addr && !ops.contains('[')) {
            return None;
        }
        let (dst, src) = split_first(ops)?;
        let canon = canonical_of(self.arch, dst)?;
        if !self.types.contains_key(&canon) {
            return None;
        }
        let src = if is_addr {
            format!("&{}", src.trim_start_matches('#').trim())
        } else {
            src.to_string()
        };
        Some(format!("{} = {src}", self.name(&canon)))
    }

    /// Casted arguments for the calling convention's registers that carry
    /// inferred types, in ABI order.
    fn call_args(&self) -> Vec<String> {
        let regs: &[&str] = match self.arch {
            Arch::X86_64 => &["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            Arch::Arm64 => &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
            _ => &[],
        };
        regs.iter()
            .filter_map(|r| {
                let ty = self.types.get(*r)?;
                Some(format!("({ty}){}", self.name(r)))
            })
            .collect()
    }

    fn return_stmt(&self) -> String {
        let reg = match self.arch {
            Arch::X86_64 => "rax",
            Arch::Arm64 => "x0",
            _ => return "return".to_string(),
        };
        match self.types.get(reg) {
            Some(ty) => format!("return ({ty}){}", self.name(reg)),
            None => "return".to_string(),
        }
    }
}

/// Width inference over the flow-ordered window: one entry per register the
/// first time a typing instruction names it, in window order. A store of a
/// typed register to a stack slot — `[rbp±N]` / `[rsp±N]` on x86_64,
/// `[sp, #N]` on arm64 — records the slot's type at the store's window
/// index; a later load from that slot reuses it (and re-activates or first
/// types the destination register at the load), so the synthetic local stays
/// one local. A slot stored a second, different type — or written with
/// unknown data — becomes untyped from then on, and a store inside a
/// followed conditional's fall-through block reaches only loads inside that
/// same block: the other path never executed it.
fn plan_types(
    insns: &[disasm::Instruction],
    arch: Arch,
    gaps: &[Gap],
    joins: &[CondJoin],
) -> Vec<TypedReg> {
    // Pass 1: register-only inference, so slot stores know which source
    // registers are typed without circular reasoning.
    let reg_typed = plan_register_types(insns, arch);
    let deaths = register_deaths(&reg_typed, gaps, joins, arch);

    let mut typed = reg_typed;
    let mut types: HashMap<String, &'static str> =
        typed.iter().map(|r| (r.aliases[0].clone(), r.ty)).collect();
    let mut slots: HashMap<SlotKey, SlotSnap> = HashMap::new();

    // Skipped gaps the walk decoded may overwrite slots behind a jump; a gap
    // that did not decode makes every recorded slot suspect.
    let mut gap_invalidations: Vec<(usize, Vec<Option<SlotKey>>)> = gaps
        .iter()
        .map(|gap| {
            let keys = match &gap.insns {
                Some(insns) => insns
                    .iter()
                    .filter_map(|i| slot_store_key(i, arch))
                    .map(Some)
                    .collect(),
                None => vec![None],
            };
            (gap.after, keys)
        })
        .collect();
    gap_invalidations.sort_by_key(|(after, _)| *after);
    let mut next_gap = 0usize;

    for (i, insn) in insns.iter().enumerate() {
        while next_gap < gap_invalidations.len() && gap_invalidations[next_gap].0 <= i {
            let (after, keys) = &gap_invalidations[next_gap];
            if keys.iter().any(Option::is_none) {
                for snap in slots.values_mut() {
                    snap.poisoned = true;
                    snap.ty = None;
                }
            } else {
                for k in keys.iter().flatten() {
                    // The gap's store is unknown data landing in this slot:
                    // record a poisoned snap even when the walked path has
                    // not stored here yet, so no later typed store re-types
                    // the slot.
                    let snap = slots.entry(*k).or_insert(SlotSnap {
                        ty: None,
                        at: *after,
                        poisoned: false,
                    });
                    snap.poisoned = true;
                    snap.ty = None;
                    snap.at = *after;
                }
            }
            next_gap += 1;
        }

        // A store of a typed register to a slot records the slot's type; a
        // second, different type — or a store of an untyped value — makes
        // the slot untyped.
        if let Some(key) = slot_store_key(insn, arch) {
            let src = slot_store_source(insn, arch);
            // A register whose type died at a join holds path-dependent
            // data; a store of it writes unknown data.
            let ty = src
                .filter(|c| deaths.get(c).map_or(true, |k| *k > i))
                .and_then(|c| types.get(&c).copied());
            let snap = slots
                .entry(key)
                .or_insert(SlotSnap { ty: None, at: i, poisoned: false });
            // A store poisons the slot when it conflicts with the recorded
            // type (or carries no type at all); a poisoned slot never
            // recovers — mixed data landed there for the whole window.
            let poisoned = snap.poisoned
                || match (snap.ty, ty) {
                    (Some(old), Some(new)) => old != new,
                    (Some(_), None) | (None, None) => true,
                    (None, Some(_)) => false,
                };
            if poisoned {
                snap.poisoned = true;
                snap.ty = None;
                snap.at = i;
            } else {
                snap.ty = ty;
                snap.at = i;
            }
        }

        // A load from a typed, unpoisoned slot types (or re-types) its
        // destination register at this index.
        if let Some(key) = slot_load_key(insn, arch) {
            if let Some(snap) = slots.get(&key) {
                if let Some(ty) = snap.ty {
                    if !snap.poisoned && slot_reaches(i, snap.at, joins) {
                        let dst = slot_load_dest(insn, arch);
                        if let Some(canon) = dst {
                            if types.get(&canon) != Some(&ty) {
                                types.insert(canon.clone(), ty);
                                if let Some(entry) =
                                    typed.iter_mut().find(|r| r.aliases[0] == canon)
                                {
                                    entry.ty = ty;
                                    entry.first = i;
                                } else {
                                    typed.push(TypedReg {
                                        aliases: aliases_of(&canon),
                                        ty,
                                        first: i,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Some((canon, ty)) = infer_insn(insn, arch, &types) {
            if types.contains_key(&canon) {
                continue;
            }
            types.insert(canon.clone(), ty);
            typed.push(TypedReg {
                aliases: aliases_of(&canon),
                ty,
                first: i,
            });
        }
    }
    typed
}

/// Whether a slot type recorded at `store_at` may reach a load at `load_at`:
/// a store strictly inside a followed conditional's fall-through block
/// (`branch < store < after`) executed only on that path, so it reaches only
/// loads inside the same block.
fn slot_reaches(load_at: usize, store_at: usize, joins: &[CondJoin]) -> bool {
    joins.iter().all(|j| {
        !(j.branch < store_at && store_at < j.after && load_at >= j.after)
    })
}

/// Register-only width inference: the original pass, without slots.
fn plan_register_types(insns: &[disasm::Instruction], arch: Arch) -> Vec<TypedReg> {
    let mut typed: Vec<TypedReg> = Vec::new();
    let mut types: HashMap<String, &'static str> = HashMap::new();
    for (i, insn) in insns.iter().enumerate() {
        if let Some((canon, ty)) = infer_insn(insn, arch, &types) {
            if types.contains_key(&canon) {
                continue;
            }
            types.insert(canon.clone(), ty);
            typed.push(TypedReg {
                aliases: aliases_of(&canon),
                ty,
                first: i,
            });
        }
    }
    typed
}

/// A stack slot a memory operand names: `(base, disp)` with base `rbp` (0)
/// or `rsp` (1) on x86_64, or `sp` (2) with a `#N` displacement on arm64.
/// Anything else — another base, an index register, a scale, a
/// post-index — is not a plain slot and returns `None`.
fn slot_key_of(mem: &str, arch: Arch) -> Option<SlotKey> {
    // x86_64 memory operands may carry a size keyword ("dword ptr [rbp - 8]").
    let open = mem.find('[')?;
    let close = mem.rfind(']')?;
    let inner = mem[open + 1..close].trim();
    // Capstone prints displacements in decimal up to |9| and in hex beyond
    // (0xc, 0x10, ...), so accept either radix.
    let parse_disp = |s: &str| -> Option<i64> {
        let s = s.trim();
        let (neg, digits) = match s.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, s),
        };
        let n = if let Some(hex) = digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
            i64::from_str_radix(hex, 16).ok()?
        } else {
            digits.parse::<i64>().ok()?
        };
        Some(if neg { -n } else { n })
    };
    match arch {
        Arch::X86_64 => {
            let flat: String = inner.chars().filter(|c| !c.is_whitespace()).collect();
            let (base, disp) = match flat.find(['+', '-']) {
                Some(p) => {
                    let n = parse_disp(&flat[p + 1..])?;
                    let disp = if flat[p..].starts_with('-') { -n } else { n };
                    (&flat[..p], disp)
                }
                None => (flat.as_str(), 0),
            };
            match base {
                "rbp" => Some((0, disp)),
                "rsp" => Some((1, disp)),
                _ => None,
            }
        }
        Arch::Arm64 => {
            let mut parts = inner.splitn(2, ',');
            if parts.next()?.trim() != "sp" {
                return None;
            }
            match parts.next() {
                None => Some((2, 0)),
                Some(off) => {
                    let off = off.trim().strip_prefix('#')?.trim();
                    Some((2, parse_disp(off)?))
                }
            }
        }
        _ => None,
    }
}

/// The slot a store instruction writes, when it stores to a plain stack
/// slot: `mov [slot], reg` on x86_64, `str reg, [slot]` on arm64.
fn slot_store_key(insn: &disasm::Instruction, arch: Arch) -> Option<SlotKey> {
    let m = insn.mnemonic.as_str();
    let ops = insn.operands.as_str();
    match arch {
        Arch::X86_64 if m == "mov" => {
            let (dst, _) = split_first(ops)?;
            slot_key_of(dst, arch)
        }
        Arch::Arm64 if m == "str" => {
            let (_, src) = split_first(ops)?;
            slot_key_of(src, arch)
        }
        _ => None,
    }
}

/// The canonical source register of a slot store, if it stores a register.
fn slot_store_source(insn: &disasm::Instruction, arch: Arch) -> Option<String> {
    let m = insn.mnemonic.as_str();
    let ops = insn.operands.as_str();
    match arch {
        Arch::X86_64 if m == "mov" => {
            let (_, src) = split_first(ops)?;
            canonical_of(arch, src)
        }
        Arch::Arm64 if m == "str" => {
            let (dst, _) = split_first(ops)?;
            canonical_of(arch, dst)
        }
        _ => None,
    }
}

/// The slot a load instruction reads, when it loads from a plain stack slot:
/// `mov reg, [slot]` on x86_64, `ldr reg, [slot]` on arm64.
fn slot_load_key(insn: &disasm::Instruction, arch: Arch) -> Option<SlotKey> {
    let m = insn.mnemonic.as_str();
    let ops = insn.operands.as_str();
    match arch {
        Arch::X86_64 if m == "mov" => {
            let (dst, src) = split_first(ops)?;
            if dst.starts_with('[') {
                return None;
            }
            slot_key_of(src, arch)
        }
        Arch::Arm64 if m == "ldr" || m == "ldur" => {
            let (_, src) = split_first(ops)?;
            slot_key_of(src, arch)
        }
        _ => None,
    }
}

/// The canonical destination register of a slot load.
fn slot_load_dest(insn: &disasm::Instruction, arch: Arch) -> Option<String> {
    let ops = insn.operands.as_str();
    let (dst, _) = split_first(ops)?;
    canonical_of(arch, dst)
}

/// Width inference for one instruction: `(canonical register, C type)`.
fn infer_insn(
    insn: &disasm::Instruction,
    arch: Arch,
    types: &HashMap<String, &'static str>,
) -> Option<(String, &'static str)> {
    let m = insn.mnemonic.as_str();
    let ops = insn.operands.as_str();
    match arch {
        Arch::X86_64 => {
            if m == "lea" {
                let dst = ops.split(',').next()?.trim();
                let (canon, _) = x86_reg(dst)?;
                return Some((canon.to_string(), "void*"));
            }
            if matches!(m, "mov" | "movzx" | "movsx" | "movsxd") {
                let (dst, src) = split_first(ops)?;
                if !src.contains('[') {
                    return None;
                }
                let width = size_keyword(src).or_else(|| x86_reg(dst).map(|(_, w)| w))?;
                let signed = matches!(m, "movsx" | "movsxd");
                let (canon, _) = x86_reg(dst)?;
                return Some((canon.to_string(), c_type(width, signed)?));
            }
            None
        }
        Arch::Arm64 => {
            if m == "adrp" || m == "adr" {
                let dst = ops.split(',').next()?.trim();
                return Some((arm64_reg(dst)?, "void*"));
            }
            if m == "add" {
                // adrp+add: a known pointer propagates through dst == src1.
                let parts: Vec<&str> = ops.split(',').collect();
                if parts.len() >= 2 {
                    let dst = arm64_reg(parts[0].trim())?;
                    let src1 = arm64_reg(parts[1].trim())?;
                    if dst == src1 {
                        let ty = *types.get(&dst)?;
                        return Some((dst, ty));
                    }
                }
                return None;
            }
            if (m.starts_with("ldr") || m.starts_with("ldur")) && ops.contains('[') {
                let (dst, _) = split_first(ops)?;
                let (width, signed) = if m.ends_with("sw") {
                    (32, true)
                } else if m.ends_with("sb") {
                    (8, true)
                } else if m.ends_with("sh") {
                    (16, true)
                } else if m.ends_with('b') {
                    (8, false)
                } else if m.ends_with('h') {
                    (16, false)
                } else if dst.starts_with('w') {
                    (32, false)
                } else {
                    return None;
                };
                return Some((arm64_reg(dst)?, c_type(width, signed)?));
            }
            None
        }
        _ => None,
    }
}

/// Capstone's x86_64 operand spellings per canonical 64-bit register, widest
/// first: index 0 is 64-bit, 1 is 32-bit, 2 is 16-bit, the rest are 8-bit.
const X86_64_REGS: &[(&str, &[&str])] = &[
    ("rax", &["rax", "eax", "ax", "al", "ah"]),
    ("rbx", &["rbx", "ebx", "bx", "bl", "bh"]),
    ("rcx", &["rcx", "ecx", "cx", "cl", "ch"]),
    ("rdx", &["rdx", "edx", "dx", "dl", "dh"]),
    ("rsi", &["rsi", "esi", "si", "sil"]),
    ("rdi", &["rdi", "edi", "di", "dil"]),
    ("rbp", &["rbp", "ebp", "bp", "bpl"]),
    ("rsp", &["rsp", "esp", "sp", "spl"]),
    ("r8", &["r8", "r8d", "r8w", "r8b"]),
    ("r9", &["r9", "r9d", "r9w", "r9b"]),
    ("r10", &["r10", "r10d", "r10w", "r10b"]),
    ("r11", &["r11", "r11d", "r11w", "r11b"]),
    ("r12", &["r12", "r12d", "r12w", "r12b"]),
    ("r13", &["r13", "r13d", "r13w", "r13b"]),
    ("r14", &["r14", "r14d", "r14w", "r14b"]),
    ("r15", &["r15", "r15d", "r15w", "r15b"]),
];

fn x86_reg(reg: &str) -> Option<(&'static str, u8)> {
    for (canon, aliases) in X86_64_REGS {
        for (i, a) in aliases.iter().enumerate() {
            if *a == reg {
                let width = match i {
                    0 => 64,
                    1 => 32,
                    2 => 16,
                    _ => 8,
                };
                return Some((canon, width));
            }
        }
    }
    None
}

/// arm64 W registers are the low 32 bits of the X register: canonical is `xN`.
fn arm64_reg(reg: &str) -> Option<String> {
    let n: u32 = reg
        .strip_prefix('x')
        .or_else(|| reg.strip_prefix('w'))?
        .parse()
        .ok()?;
    (n <= 30).then(|| format!("x{n}"))
}

fn aliases_of(canon: &str) -> Vec<String> {
    if let Some((_, aliases)) = X86_64_REGS.iter().find(|(c, _)| *c == canon) {
        return aliases.iter().map(|a| a.to_string()).collect();
    }
    if let Some(n) = canon.strip_prefix('x') {
        return vec![canon.to_string(), format!("w{n}")];
    }
    vec![canon.to_string()]
}

/// Operand size keyword in a Capstone memory operand, in bits. Wide keywords
/// are checked first because "dword ptr" contains "word ptr".
fn size_keyword(src: &str) -> Option<u8> {
    if src.contains("qword ptr") {
        Some(64)
    } else if src.contains("dword ptr") {
        Some(32)
    } else if src.contains("word ptr") {
        Some(16)
    } else if src.contains("byte ptr") {
        Some(8)
    } else {
        None
    }
}

fn c_type(width: u8, signed: bool) -> Option<&'static str> {
    Some(match (width, signed) {
        (32, false) => "unsigned int",
        (32, true) => "int",
        (16, false) => "uint16_t",
        (16, true) => "int16_t",
        (8, false) => "uint8_t",
        (8, true) => "int8_t",
        _ => return None,
    })
}

fn canonical_of(arch: Arch, reg: &str) -> Option<String> {
    match arch {
        Arch::X86_64 => x86_reg(reg).map(|(c, _)| c.to_string()),
        Arch::Arm64 => arm64_reg(reg),
        _ => None,
    }
}

#[cfg(all(test, feature = "disasm"))]
mod tests {
    use super::decompile;
    use crate::{Arch, Format, Section, Target};

    fn target(arch: Arch, bits: u8, code: &[u8]) -> Target {
        let mut bytes = vec![0u8; 4096];
        bytes[..code.len()].copy_from_slice(code);
        Target {
            path: "fixture".into(),
            format: Format::Elf,
            arch,
            bits,
            little_endian: true,
            entry: 0x1000,
            sections: vec![Section {
                name: ".text".into(),
                addr: 0x1000,
                size: bytes.len() as u64,
                file_offset: 0,
                perms: "r-x".into(),
                sh_type: None,
                sh_flags: None,
            }],
            symbols: Vec::new(),
            bytes,
            page_map: None,
        }
    }

    #[test]
    fn x86_64_mov_and_ret_become_an_assignment_and_a_return() {
        let code = [0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 8).unwrap();
        assert!(text.contains("void sub_1000()"), "{text}");
        assert!(text.contains("eax = 1"), "{text}");
        assert!(text.contains("return"), "{text}");
        assert!(!text.contains(" v1;"), "{text}");
    }

    #[test]
    fn arm64_ret_is_a_return() {
        let code = [0xc0, 0x03, 0x5f, 0xd6];
        let text = decompile(&target(Arch::Arm64, 64, &code), 0x1000, 4).unwrap();
        assert!(text.contains("return"), "{text}");
    }

    #[test]
    fn x86_64_lea_pointer_becomes_a_typed_local_and_a_cast_argument() {
        // lea rdi, [rip + 0]; call 0x100c; ret
        let code = [
            0x48, 0x8d, 0x3d, 0x00, 0x00, 0x00, 0x00, 0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3,
        ];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 8).unwrap();
        assert!(text.contains("void* v1;"), "{text}");
        assert!(text.contains("v1 = &[rip"), "{text}");
        assert!(text.contains("(void*)v1"), "{text}");
    }

    #[test]
    fn x86_64_signed_word_load_is_int_and_casts_the_return() {
        // movsxd rax, dword ptr [rip + 0]; ret
        let code = [0x48, 0x63, 0x05, 0x00, 0x00, 0x00, 0x00, 0xc3];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 8).unwrap();
        assert!(text.contains("int v1;"), "{text}");
        assert!(text.contains("v1 = dword ptr [rip"), "{text}");
        assert!(text.contains("return (int)v1"), "{text}");
    }

    #[test]
    fn x86_64_byte_load_is_uint8_t() {
        // movzx eax, byte ptr [rip + 0]; ret
        let code = [0x0f, 0xb6, 0x05, 0x00, 0x00, 0x00, 0x00, 0xc3];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 8).unwrap();
        assert!(text.contains("uint8_t v1;"), "{text}");
        assert!(text.contains("v1 = byte ptr [rip"), "{text}");
        assert!(text.contains("return (uint8_t)v1"), "{text}");
    }

    #[test]
    fn arm64_adrp_plus_add_pointer_flows_into_a_call_argument() {
        // adrp x0, #0; add x0, x0, #0; bl 0x1008; ret
        let code = [
            0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x91, 0x00, 0x00, 0x00, 0x94, 0xc0, 0x03,
            0x5f, 0xd6,
        ];
        let text = decompile(&target(Arch::Arm64, 64, &code), 0x1000, 8).unwrap();
        assert!(text.contains("void* v1;"), "{text}");
        assert!(text.contains("0x1008((void*)v1)"), "{text}");
    }

    #[test]
    fn arm64_signed_word_and_byte_loads_get_their_c_types() {
        // ldrsw x8, [x9]; ldrb w9, [x10]; ret
        let code = [
            0x28, 0x01, 0x80, 0xb9, 0x49, 0x01, 0x40, 0x39, 0xc0, 0x03, 0x5f, 0xd6,
        ];
        let text = decompile(&target(Arch::Arm64, 64, &code), 0x1000, 8).unwrap();
        assert!(text.contains("int v1;"), "{text}");
        assert!(text.contains("v1 = [x9]"), "{text}");
        assert!(text.contains("uint8_t v2;"), "{text}");
        assert!(text.contains("v2 = [x10]"), "{text}");
    }

    #[test]
    fn x86_64_jmp_chain_continues_at_the_target() {
        // mov eax, 1; jmp 0x1007; mov ebx, 2; ret
        let code = [
            0xb8, 0x01, 0x00, 0x00, 0x00, 0xeb, 0x00, 0xbb, 0x02, 0x00, 0x00, 0x00, 0xc3,
        ];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 16).unwrap();
        assert!(text.contains("loc_1007:"), "{text}");
        assert!(text.contains("ebx = 2"), "{text}");
        assert!(text.contains("return"), "{text}");
        assert!(!text.contains("goto"), "{text}");
    }

    #[test]
    fn arm64_b_chain_continues_at_the_target() {
        // movz x8, #1; b 0x1008; movz x9, #2; ret
        let code = [
            0x28, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0x14, 0x49, 0x00, 0x80, 0xd2, 0xc0, 0x03,
            0x5f, 0xd6,
        ];
        let text = decompile(&target(Arch::Arm64, 64, &code), 0x1000, 16).unwrap();
        assert!(text.contains("loc_1008:"), "{text}");
        assert!(text.contains("x9 = #2"), "{text}");
        assert!(text.contains("return"), "{text}");
        assert!(!text.contains("goto"), "{text}");
    }

    #[test]
    fn x86_64_loop_back_to_a_visited_target_ends_with_a_goto() {
        // 0x1000: jmp 0x1004; nop; 0x1004: jmp 0x1000
        let code = [0xeb, 0x02, 0x90, 0x90, 0xeb, 0xfa];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 16).unwrap();
        assert!(text.contains("goto 0x1000;\n}"), "{text}");
    }

    #[test]
    fn arm64_loop_back_to_a_visited_target_ends_with_a_goto() {
        // 0x1000: b 0x1008; nop; 0x1008: b 0x1000
        let code = [
            0x02, 0x00, 0x00, 0x14, 0x1f, 0x20, 0x03, 0xd5, 0xfe, 0xff, 0xff, 0x17,
        ];
        let text = decompile(&target(Arch::Arm64, 64, &code), 0x1000, 16).unwrap();
        assert!(text.contains("goto #0x1000;\n}"), "{text}");
    }

    #[test]
    fn x86_64_backward_jump_to_unvisited_code_walks_it_then_ends_at_the_visited_loop_head() {
        // 0x1000: jmp 0x1005; nop; nop; nop; 0x1005: jmp 0x1002.
        // The backward jump at 0x1005 reaches unvisited 0x1002, which is
        // walked; re-reaching the visited jmp at 0x1005 then ends the
        // listing — the visited guard, not a forward-only rule, stops it.
        let code = [0xeb, 0x03, 0x90, 0x90, 0x90, 0xeb, 0xfb];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 16).unwrap();
        assert!(text.contains("loc_1002:"), "{text}");
        assert!(text.contains("nop"), "{text}");
        assert!(text.contains("goto 0x1002;\n}"), "{text}");
    }

    #[test]
    fn x86_64_jmp_out_of_the_function_ends_with_a_goto() {
        // mov eax, 1; jmp 0x9000
        let code = [0xb8, 0x01, 0x00, 0x00, 0x00, 0xe9, 0xf6, 0x7f, 0x00, 0x00];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 16).unwrap();
        assert!(text.contains("goto 0x9000;\n}"), "{text}");
    }

    #[test]
    fn arm64_b_out_of_the_function_ends_with_a_goto() {
        // b 0x9000
        let code = [0x00, 0x20, 0x00, 0x14];
        let text = decompile(&target(Arch::Arm64, 64, &code), 0x1000, 16).unwrap();
        assert!(text.contains("goto #0x9000;\n}"), "{text}");
    }

    #[test]
    fn x86_64_typed_register_flows_through_a_followed_join() {
        // movsxd rax, dword ptr [rip + 0]; jmp 0x1009; ret
        let code = [
            0x48, 0x63, 0x05, 0x00, 0x00, 0x00, 0x00, 0xeb, 0x00, 0xc3,
        ];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 16).unwrap();
        assert!(text.contains("int v1;"), "{text}");
        assert!(text.contains("return (int)v1"), "{text}");
    }

    #[test]
    fn x86_64_type_writes_in_the_skipped_gap_drop_the_type_at_the_join() {
        // movsxd rax, dword ptr [rip + 0]; jmp 0x100e; mov rax, rbx; nop; nop; ret
        let code = [
            0x48, 0x63, 0x05, 0x00, 0x00, 0x00, 0x00, 0xeb, 0x05, 0x48, 0x89, 0xd8, 0x90, 0x90,
            0xc3,
        ];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 16).unwrap();
        assert!(text.contains("int v1;"), "{text}");
        assert!(text.contains("v1 = dword ptr [rip"), "{text}");
        assert!(text.contains("  return;\n"), "{text}");
        assert!(!text.contains("return (int)"), "{text}");
    }

    #[test]
    fn x86_64_type_flows_through_a_followed_conditional_join() {
        // movsxd rax, dword ptr [rip + 0]; je 0x100a; nop; ret
        let code = [
            0x48, 0x63, 0x05, 0x00, 0x00, 0x00, 0x00, 0x74, 0x01, 0x90, 0xc3,
        ];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 16).unwrap();
        assert!(text.contains("int v1;"), "{text}");
        assert!(text.contains("if (je) goto 0x100a;"), "{text}");
        assert!(text.contains("return (int)v1"), "{text}");
    }

    #[test]
    fn x86_64_fallthrough_write_of_a_different_type_drops_the_type_at_the_join() {
        // movzx eax, byte ptr [rip + 0]; je 0x1010; movsxd rax, dword ptr
        // [rip + 0]; ret. The fall-through rewrites rax as int, so the direct
        // path's uint8_t disagrees and the register is untyped at the join.
        let code = [
            0x0f, 0xb6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x74, 0x07, 0x48, 0x63, 0x05, 0x00, 0x00,
            0x00, 0x00, 0xc3,
        ];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 16).unwrap();
        assert!(text.contains("uint8_t v1;"), "{text}");
        assert!(text.contains("v1 = dword ptr [rip"), "{text}");
        assert!(text.contains("  return;\n"), "{text}");
        assert!(!text.contains("return (uint8_t)"), "{text}");
    }

    #[test]
    fn x86_64_backward_conditional_stays_a_goto_and_the_fallthrough_continues() {
        // mov eax, 1; je 0x1000; ret
        let code = [0xb8, 0x01, 0x00, 0x00, 0x00, 0x74, 0xf9, 0xc3];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 16).unwrap();
        assert!(text.contains("if (je) goto 0x1000;"), "{text}");
        assert!(text.contains("return"), "{text}");
        // The taken path is not re-listed: exactly one `eax = 1`.
        assert_eq!(text.matches("eax = 1").count(), 1);
    }

    #[test]
    fn x86_64_conditional_to_an_out_of_function_target_stays_a_goto() {
        // mov eax, 1; je 0x9000; ret
        let code = [
            0xb8, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x84, 0xf5, 0x7f, 0x00, 0x00, 0xc3,
        ];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 16).unwrap();
        assert!(text.contains("if (je) goto 0x9000;"), "{text}");
        assert!(text.contains("return"), "{text}");
    }

    #[test]
    fn x86_64_conditional_whose_fallthrough_stops_short_is_not_followed() {
        // mov eax, 1; je 0x100b; ret; nop; nop; nop; mov ebx, 2; ret.
        // The fall-through path hits the ret, so the branch stays a goto and
        // the taken path at 0x100b is never listed.
        let code = [
            0xb8, 0x01, 0x00, 0x00, 0x00, 0x74, 0x04, 0xc3, 0x90, 0x90, 0x90, 0xbb, 0x02, 0x00,
            0x00, 0x00, 0xc3,
        ];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 16).unwrap();
        assert!(text.contains("if (je) goto 0x100b;"), "{text}");
        assert!(text.contains("return"), "{text}");
        assert!(!text.contains("ebx = 2"), "{text}");
    }

    #[test]
    fn arm64_b_cond_follows_to_the_join_and_carries_the_type() {
        // ldr w0, [x9]; b.eq #0x100c; nop; ret — the type survives the join,
        // so the return casts the synthetic local.
        let code = [
            0x20, 0x01, 0x40, 0xb9, 0x40, 0x00, 0x00, 0x54, 0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03,
            0x5f, 0xd6,
        ];
        let text = decompile(&target(Arch::Arm64, 64, &code), 0x1000, 16).unwrap();
        assert!(text.contains("unsigned int v1;"), "{text}");
        assert!(text.contains("v1 = [x9]"), "{text}");
        assert!(text.contains("if (b.eq) goto #0x100c;"), "{text}");
        assert!(text.contains("return (unsigned int)v1"), "{text}");
    }

    #[test]
    fn arm64_fallthrough_write_of_an_untypeable_load_drops_the_type_at_the_join() {
        // ldr w0, [x9] @0x1000; b.eq #0x1010 @0x1004; ldr x0, [x10] @0x1008
        // (no inferable type); nop @0x100c; ret @0x1010. The fall block is
        // listed only because following walks it to the join, and its x0
        // write kills the carried `unsigned int`, so the return has no cast.
        // With the Arm64 arm of followable_cond dropped, the linear walk
        // keeps the cast and both of the last two asserts fail.
        let code = [
            0x20, 0x01, 0x40, 0xb9, // ldr w0, [x9]
            0x60, 0x00, 0x00, 0x54, // b.eq #0x1010
            0x40, 0x01, 0x40, 0xf9, // ldr x0, [x10]
            0x1f, 0x20, 0x03, 0xd5, // nop
            0xc0, 0x03, 0x5f, 0xd6, // ret
        ];
        let text = decompile(&target(Arch::Arm64, 64, &code), 0x1000, 20).unwrap();
        assert!(text.contains("unsigned int v1;"), "{text}");
        assert!(text.contains("v1 = [x9]"), "{text}");
        assert!(text.contains("if (b.eq) goto #0x1010;"), "{text}");
        assert!(text.contains("v1 = [x10]"), "{text}");
        assert!(text.contains("\n  return;\n"), "{text}");
        assert!(!text.contains("return (unsigned int)"), "{text}");
    }

    #[test]
    fn decompiling_a_body_whose_section_reaches_u64_max_does_not_panic() {
        // Regression: `ins.addr + ins.size` overflowed for an instruction at
        // u64::MAX - 1, and `s.addr + s.size` overflowed in vaddr_to_offset.
        // A 2-byte insn at 0xffff_ffff_ffff_fffe reaches both.
        let mut bytes = vec![0u8; 16];
        bytes[..2].copy_from_slice(&[0x66, 0x90]); // xchg ax, ax: 2 bytes
        let high = 0xffff_ffff_ffff_fffeu64;
        let t = Target {
            path: "fixture".into(),
            format: Format::Elf,
            arch: Arch::X86_64,
            bits: 64,
            little_endian: true,
            entry: high,
            sections: vec![Section {
                name: ".text".into(),
                addr: high,
                size: 8,
                file_offset: 0,
                perms: "r-x".into(),
                sh_type: None,
                sh_flags: None,
            }],
            symbols: Vec::new(),
            page_map: None,
            bytes,
        };
        let _ = decompile(&t, high, 4); // must simply not panic
    }

    #[test]
    fn decompiling_a_section_with_a_hostile_file_offset_does_not_panic() {
        // Regression: prologue_starts computed `file_offset + size` before
        // the length check, overflowing for file_offset near usize::MAX.
        let t = Target {
            path: "fixture".into(),
            format: Format::Elf,
            arch: Arch::X86_64,
            bits: 64,
            little_endian: true,
            entry: 0x1000,
            sections: vec![Section {
                name: ".text".into(),
                addr: 0x1000,
                size: 8,
                file_offset: 0xffff_ffff_ffff_fff0,
                perms: "r-x".into(),
                sh_type: None,
                sh_flags: None,
            }],
            symbols: Vec::new(),
            page_map: None,
            bytes: vec![0x90; 16],
        };
        let _ = decompile(&t, 0x1000, 4); // must simply not panic
    }

    #[test]
    fn decompiling_a_body_at_a_huge_mapped_address_does_not_panic() {
        // Regression: function_body computed `start + max`, which overflowed
        // for a section mapped near u64::MAX. A forward jmp evaluates the
        // second comparison, so this reaches the former panic site.
        let mut bytes = vec![0u8; 4096];
        // jmp +2 (0xeb 0x02): a forward direct target past the jmp itself.
        bytes[..2].copy_from_slice(&[0xeb, 0x02]);
        let high = 0xffff_ffff_ffff_0000u64;
        let t = Target {
            path: "fixture".into(),
            format: Format::Elf,
            arch: Arch::X86_64,
            bits: 64,
            little_endian: true,
            entry: high,
            sections: vec![Section {
                name: ".text".into(),
                addr: high,
                size: bytes.len() as u64,
                file_offset: 0,
                perms: "r-x".into(),
                sh_type: None,
                sh_flags: None,
            }],
            symbols: Vec::new(),
            page_map: None,
            bytes,
        };
        let out = decompile(&t, high, 4);
        assert!(out.is_ok(), "expected Ok, got {out:?}");
    }

    #[test]
    fn decompiling_an_address_beyond_every_section_is_an_error_not_a_panic() {
        // Regression: function_body used `start + max`, which overflowed for
        // addresses near u64::MAX.
        let t = target(Arch::X86_64, 64, &[0xc3]);
        let out = decompile(&t, 0xffff_ffff_fffe_0000, 4);
        assert!(out.is_err(), "expected Err, got {out:?}");
    }

    #[test]
    fn x86_64_store_then_load_shares_one_typed_local() {
        // lea rdi, [rip + 0]; mov [rbp - 8], rdi; mov rdx, qword ptr [rbp - 8]; ret
        let code = [
            0x48, 0x8d, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x7d, 0xf8, 0x48, 0x8b, 0x55,
            0xf8, 0xc3,
        ];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 8).unwrap();
        assert!(text.contains("void* v1;"), "{text}");
        assert!(text.contains("void* v2;"), "{text}");
        assert!(text.contains("v2 = qword ptr [rbp - 8]"), "{text}");
    }

    #[test]
    fn x86_64_slot_reload_into_the_same_register_stays_one_local() {
        // lea rdi, [rip + 0]; mov [rbp - 8], rdi; mov rdi, qword ptr [rbp - 8]; ret
        let code = [
            0x48, 0x8d, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x7d, 0xf8, 0x48, 0x8b, 0x7d,
            0xf8, 0xc3,
        ];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 8).unwrap();
        assert!(text.contains("void* v1;"), "{text}");
        assert!(!text.contains("v2"), "{text}");
        assert!(text.contains("v1 = qword ptr [rbp - 8]"), "{text}");
    }

    #[test]
    fn x86_64_two_slot_types_poison_the_slot() {
        // movsxd rax (int); mov [rbp - 8], rax; movzx edx (uint8_t);
        // mov [rbp - 8], rdx; mov rbx, qword ptr [rbp - 8]; ret
        let code = [
            0x48, 0x63, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0xf8, 0x0f, 0xb6, 0x15,
            0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x55, 0xf8, 0x48, 0x8b, 0x5d, 0xf8, 0xc3,
        ];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 16).unwrap();
        assert!(text.contains("int v1;"), "{text}");
        assert!(text.contains("uint8_t v2;"), "{text}");
        // The slot is untyped: rbx gets no synthetic local.
        assert!(!text.contains("v3"), "{text}");
        assert!(text.contains("rbx = qword ptr [rbp - 8]"), "{text}");
    }

    #[test]
    fn x86_64_an_untyped_store_poisons_the_slot() {
        // mov [rbp - 8], rdx (untyped); movsxd rax (int);
        // mov [rbp - 8], rax; mov rbx, qword ptr [rbp - 8]; ret.
        // The untyped store poisons the slot, so the later int store must
        // not re-type it and the load stays untyped.
        let code = [
            0x48, 0x89, 0x55, 0xf8, 0x48, 0x63, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45,
            0xf8, 0x48, 0x8b, 0x5d, 0xf8, 0xc3,
        ];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 20).unwrap();
        assert!(text.contains("int v1;"), "{text}");
        assert!(!text.contains("v2;"), "{text}");
        assert!(!text.contains("v2 "), "{text}");
        assert!(text.contains("rbx = qword ptr [rbp - 8]"), "{text}");
    }

    #[test]
    fn x86_64_a_gap_store_to_a_fresh_slot_poisons_it() {
        // movsxd rax; jmp over the gap store mov [rbp - 8], rax (the first
        // write the walked path sees is inside the gap); then movzx edx
        // (uint8_t); mov [rbp - 8], rdx; mov rbx, [rbp - 8]; ret. The gap's
        // store poisons the slot even though the walked path never stored to
        // it before the jump, so the uint8_t store cannot type the load.
        let code = [
            0x48, 0x63, 0x05, 0x00, 0x00, 0x00, 0x00, 0xeb, 0x04, 0x48, 0x89, 0x45, 0xf8, 0x0f,
            0xb6, 0x15, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x55, 0xf8, 0x48, 0x8b, 0x5d, 0xf8,
            0xc3,
        ];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 29).unwrap();
        assert!(text.contains("int v1;"), "{text}");
        assert!(text.contains("uint8_t v2;"), "{text}");
        assert!(!text.contains("v3"), "{text}");
        assert!(text.contains("rbx = qword ptr [rbp - 8]"), "{text}");
    }

    #[test]
    fn x86_64_a_typed_store_after_poison_keeps_the_slot_untyped() {
        // movsxd rax (int); mov [rbp - 8], rax; movzx edx (uint8_t);
        // mov [rbp - 8], rdx; movsxd rsi (int); mov [rbp - 8], rsi;
        // mov rbx, qword ptr [rbp - 8]; ret
        // The slot saw int then uint8_t; the later int store does not
        // resurrect it — the slot holds mixed data for the whole window.
        let code = [
            0x48, 0x63, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0xf8, 0x0f, 0xb6, 0x15,
            0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x55, 0xf8, 0x48, 0x63, 0x35, 0x00, 0x00, 0x00,
            0x00, 0x48, 0x89, 0x75, 0xf8, 0x48, 0x8b, 0x5d, 0xf8, 0xc3,
        ];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 32).unwrap();
        assert!(text.contains("int v1;"), "{text}");
        assert!(text.contains("uint8_t v2;"), "{text}");
        // rsi is typed int by its own movsxd (v3), but rbx must stay untyped:
        // the poisoned slot does not re-type it even though the last store
        // carried an int.
        assert!(!text.contains("v4"), "{text}");
        assert!(text.contains("rbx = qword ptr [rbp - 8]"), "{text}");
    }

    #[test]
    fn x86_64_slot_store_before_the_branch_reaches_the_join() {
        // movsxd rax; mov [rbp - 8], rax; je 0x1012; nop; mov rbx, [rbp - 8]; ret
        let code = [
            0x48, 0x63, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0xf8, 0x74, 0x05, 0x90,
            0x48, 0x8b, 0x5d, 0xf8, 0xc3,
        ];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 16).unwrap();
        assert!(text.contains("int v1;"), "{text}");
        assert!(text.contains("int v2;"), "{text}");
        assert!(text.contains("v2 = qword ptr [rbp - 8]"), "{text}");
    }

    #[test]
    fn x86_64_slot_store_inside_the_fallthrough_block_stops_at_the_join() {
        // movsxd rax; je 0x100d; mov [rbp - 8], rax (inside the block);
        // mov rbx, [rbp - 8]; ret
        let code = [
            0x48, 0x63, 0x05, 0x00, 0x00, 0x00, 0x00, 0x74, 0x04, 0x48, 0x89, 0x45, 0xf8, 0x48,
            0x8b, 0x5d, 0xf8, 0xc3,
        ];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 16).unwrap();
        assert!(text.contains("int v1;"), "{text}");
        // The other path never executed the store: rbx stays untyped.
        assert!(!text.contains("v2;"), "{text}");
        assert!(!text.contains("v2 "), "{text}");
        assert!(text.contains("rbx = qword ptr [rbp - 8]"), "{text}");
    }

    #[test]
    fn x86_64_slot_store_in_a_skipped_gap_poisons_the_slot() {
        // movsxd rax; mov [rbp - 8], rax; jmp 0x1011;
        // gap: mov [rbp - 8], rdx (untyped); mov rbx, [rbp - 8]; ret
        let code = [
            0x48, 0x63, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0xf8, 0xeb, 0x04, 0x48,
            0x89, 0x55, 0xf8, 0x48, 0x8b, 0x5d, 0xf8, 0xc3,
        ];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 16).unwrap();
        assert!(text.contains("int v1;"), "{text}");
        assert!(!text.contains("v2;"), "{text}");
        assert!(text.contains("rbx = qword ptr [rbp - 8]"), "{text}");
    }

    #[test]
    fn x86_64_a_typed_store_after_the_gap_keeps_the_slot_poisoned() {
        // movsxd rax; mov [rbp - 8], rax (int); jmp over the gap store
        // mov [rbp - 8], rdx (untyped); then movsxd rsi (int);
        // mov [rbp - 8], rsi; mov rbx, [rbp - 8]; ret. The gap store wrote
        // unknown data to the slot, so the later int store must not re-type
        // it and the load stays untyped.
        let code = [
            0x48, 0x63, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0xf8, 0xeb, 0x04, 0x48,
            0x89, 0x55, 0xf8, 0x48, 0x63, 0x35, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x75, 0xf8,
            0x48, 0x8b, 0x5d, 0xf8, 0xc3,
        ];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 33).unwrap();
        assert!(text.contains("int v1;"), "{text}");
        // movsxd rsi still types its own register local (int v2), but the
        // poisoned slot must not re-type the load's destination.
        assert!(!text.contains("v2 = qword ptr [rbp - 8]"), "{text}");
        assert!(text.contains("rbx = qword ptr [rbp - 8]"), "{text}");
    }

    #[test]
    fn x86_64_a_hex_displacement_is_a_slot() {
        // movsxd rax (int); mov [rbp - 0x10], rax (Capstone prints this
        // displacement in hex); mov rbx, qword ptr [rbp - 0x10]; ret.
        // The slot must type through in hex exactly as it does in decimal.
        let code = [
            0x48, 0x63, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0xf0, 0x48, 0x8b, 0x5d,
            0xf0, 0xc3,
        ];
        let text = decompile(&target(Arch::X86_64, 64, &code), 0x1000, 16).unwrap();
        assert!(text.contains("int v1;"), "{text}");
        // rbx reuses the slot's int local instead of staying raw; the
        // load line is spelled with Capstone's hex displacement.
        assert!(text.contains("v2 = qword ptr [rbp - 0x10]"), "{text}");
    }

    #[test]
    fn arm64_store_then_load_shares_one_typed_local() {
        // adrp x0; add x0, x0, #0; str x0, [sp, #8]; ldr x2, [sp, #8]; ret
        let code = [
            0x00, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x91, 0xe0, 0x07, 0x00, 0xf9, 0xe2, 0x07,
            0x40, 0xf9, 0xc0, 0x03, 0x5f, 0xd6,
        ];
        let text = decompile(&target(Arch::Arm64, 64, &code), 0x1000, 8).unwrap();
        assert!(text.contains("void* v1;"), "{text}");
        assert!(text.contains("void* v2;"), "{text}");
        assert!(text.contains("v2 = [sp, #8]"), "{text}");
        assert!(text.contains("str v1, [sp, #8]"), "{text}");
    }
}
