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
//! it — an unsound join drops the type instead of guessing. It is still not a
//! type-recovering decompiler: memory objects keep no types, and struct
//! recovery and cross-function dataflow stay out of scope. A short or
//! unmapped body returns an error from disassembly and does not invent
//! instructions.

use crate::{analysis, disasm, Arch, Error, Result, Target};
use std::collections::{HashMap, HashSet};

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
    let typed = plan_types(&insns, target.arch);
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

/// Width inference over the straight-line window: one entry per register the
/// first time a typing instruction names it, in window order.
fn plan_types(insns: &[disasm::Instruction], arch: Arch) -> Vec<TypedReg> {
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
}
