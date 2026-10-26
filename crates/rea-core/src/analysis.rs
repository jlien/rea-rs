//! Static analysis: function discovery, call graph, and cross-references.
//!
//! Approach is deliberately simple and format-agnostic:
//! - Function starts come from the entry point, local/export symbols in text
//!   sections, every direct `call`/`bl` target reachable from already-known
//!   functions, and frame prologues scanned in code sections (x86 `push ebp;
//!   mov ebp, esp`, x86_64 `push rbp; mov rbp, rsp`, arm64 `stp x29, x30,
//!   [sp, #imm]`).
//! - Function bodies follow forward unconditional jumps (`jmp`, `b`) and
//!   stop at `ret`, indirect or backward jumps, and invalid bytes.
//! - Data cross-references come from searching code bytes for the
//!   little-endian address: 4 bytes when `bits < 64`, 8 bytes otherwise
//!   (covers `mov reg, [addr]`, `push [addr]`, and immediate loads).
//!   Text also records PC-relative addresses in `__text` / `.text`: arm64
//!   `adrp` plus `add` or a load, x86_64 RIP-relative memory operands, 32-bit
//!   x86 `call`/`pop`/`mov` sequences, and ARM or Thumb literal loads.

use crate::{disasm, strings, Arch, SymbolKind, Target};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, serde::Serialize)]
pub struct Function {
    pub addr: u64,
    /// Approximate body length in bytes (linear run to first ret/jmp).
    pub size: u64,
    /// Direct call targets found in the body.
    pub calls: Vec<u64>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct XRef {
    /// Address of the referencing instruction (approximate: byte hit minus
    /// the 4-byte operand length gives the instruction start guess).
    pub from: u64,
    /// Referenced address.
    pub to: u64,
}

fn code_sections(target: &Target) -> impl Iterator<Item = &crate::Section> {
    target.sections.iter().filter(|s| s.size > 0)
}

/// Linear-sweep a code section, returning every direct `call`/`bl`/`blx`
/// target. Recovers from invalid bytes by advancing one byte, so the whole
/// section gets covered (mixed code/data in flat 32-bit images). `blr` is
/// indirect and is not recorded. `bl` is exact, so it does not match `blr`
/// or `b.ne`. Unknown arches have no sweep.
fn sweep_call_targets(target: &Target, sec: &crate::Section) -> Vec<u64> {
    if !matches!(
        target.arch,
        Arch::X86 | Arch::X86_64 | Arch::Arm64 | Arch::Arm
    ) {
        return Vec::new();
    }
    let Ok(mut cs) = disasm::build_capstone(target.arch) else {
        return Vec::new();
    };
    let _ = cs.set_skipdata(true); // treat unknown bytes as data, keep going

    let start = sec.file_offset as usize;
    let end = start.saturating_add(sec.size as usize).min(target.bytes.len());
    if start >= end {
        return Vec::new();
    }
    let code = &target.bytes[start..end];
    let base = sec.addr;

    let mut targets = Vec::new();
    let mut pos = 0usize;
    while pos < code.len() {
        match cs.disasm_count(&code[pos..], base.saturating_add(pos as u64), 64) {
            Ok(insns) if !insns.is_empty() => {
                let mut consumed = 0usize;
                for ins in insns.iter() {
                    consumed += ins.bytes().len();
                    if matches!(ins.mnemonic().unwrap_or(""), "call" | "bl" | "blx") {
                        if let Some(t) = direct_target(ins.op_str().unwrap_or("")) {
                            targets.push(t);
                        }
                    }
                }
                pos += consumed;
            }
            _ => pos += 1,
        }
    }
    targets
}

/// Frame-pointer prologues in a code section.
/// x86: `push ebp; mov ebp, esp`. x86_64: `push rbp; mov rbp, rsp`.
/// arm64: `stp x29, x30, [sp, #imm]!` or `stp x29, x30, [sp, #imm]`,
/// at 4-byte-aligned virtual addresses. Arm Thumb: `push {r7, lr}`
/// (`80 b5`) at even virtual addresses. Unknown yields nothing.
fn prologue_starts(target: &Target, sec: &crate::Section) -> Vec<u64> {
    let start = sec.file_offset as usize;
    let end = start.saturating_add(sec.size as usize);
    if end > target.bytes.len() {
        return Vec::new();
    }
    match target.arch {
        Arch::X86 => scan_prologue_bytes(target, sec, start, end, &[0x55, 0x8b, 0xec]),
        Arch::X86_64 => scan_prologue_bytes(target, sec, start, end, &[0x55, 0x48, 0x89, 0xe5]),
        Arch::Arm64 => scan_arm64_stp_prologues(target, sec, start, end),
        Arch::Arm => scan_thumb_push_prologues(target, sec, start, end),
        Arch::Unknown => Vec::new(),
    }
}

fn scan_prologue_bytes(
    target: &Target,
    sec: &crate::Section,
    start: usize,
    end: usize,
    needle: &[u8],
) -> Vec<u64> {
    let mut out = Vec::new();
    let mut i = start;
    while i + needle.len() <= end {
        if &target.bytes[i..i + needle.len()] == needle {
            out.push(sec.addr.saturating_add((i - start) as u64));
        }
        i += 1;
    }
    out
}

fn scan_arm64_stp_prologues(
    target: &Target,
    sec: &crate::Section,
    start: usize,
    end: usize,
) -> Vec<u64> {
    let mut out = Vec::new();
    // Instructions are 4-byte aligned. Skip a leading unaligned byte or two
    // so the first word sits on an aligned virtual address.
    let misalign = (sec.addr as usize) % 4;
    let mut i = start + if misalign == 0 { 0 } else { 4 - misalign };
    while i + 4 <= end {
        let word = u32::from_le_bytes([
            target.bytes[i],
            target.bytes[i + 1],
            target.bytes[i + 2],
            target.bytes[i + 3],
        ]);
        let masked = word & 0xFFC0_7FFF;
        // pre-index `stp x29, x30, [sp, #imm]!` or signed-offset form.
        if masked == 0xA980_7BFD || masked == 0xA900_7BFD {
            out.push(sec.addr.saturating_add((i - start) as u64));
        }
        i += 4;
    }
    out
}

fn scan_thumb_push_prologues(
    target: &Target,
    sec: &crate::Section,
    start: usize,
    end: usize,
) -> Vec<u64> {
    let mut out = Vec::new();
    // Thumb sites are 2-byte aligned. Skip one byte when the section address
    // is odd so the first site is an even virtual address.
    let misalign = (sec.addr as usize) % 2;
    let mut i = start + misalign;
    while i + 2 <= end {
        if target.bytes[i] == 0x80 && target.bytes[i + 1] == 0xb5 {
            out.push(sec.addr.saturating_add((i - start) as u64));
        }
        i += 2;
    }
    out
}

/// Follow control flow from `start`, returning (body extent, call targets).
/// Unlike a plain linear run this handles forward unconditional jumps
/// (`jmp`, `b`), stops at `ret`, indirect jumps (`br` / register `jmp`),
/// and invalid bytes — so functions no longer bleed into padding or the
/// next function. Conditional branches fall through.
pub(crate) fn function_body(target: &Target, start: u64, max: u64) -> (u64, Vec<u64>) {
    let mut visited: BTreeSet<u64> = BTreeSet::new();
    let mut calls: Vec<u64> = Vec::new();
    let mut work = vec![start];
    let mut end = start;
    while let Some(addr) = work.pop() {
        if addr < start || addr >= start.saturating_add(max) || !visited.insert(addr) {
            continue;
        }
        let Ok(insns) = disasm::disassemble(target, addr, 64) else {
            continue;
        };
        if insns.is_empty() {
            continue;
        }
        let mut jumped = false;
        for ins in &insns {
            visited.insert(ins.addr);
            end = end.max(ins.addr.saturating_add(ins.size as u64));
            match ins.mnemonic.as_str() {
                // Exact mnemonics: `b` must not swallow `bl` or `b.ne`,
                // and `bl` must not swallow `blr`. Thumb `blx` is a call.
                "call" | "bl" | "blr" | "blx" => {
                    if let Some(t) = direct_target(&ins.operands) {
                        calls.push(t);
                    }
                }
                "ret" | "retf" => {
                    jumped = false;
                    break;
                }
                // Thumb returns. A bare `bx` or `pop` is not one.
                "bx" if ins.operands.contains("lr") => {
                    jumped = false;
                    break;
                }
                "pop" if ins.operands.contains("pc") => {
                    jumped = false;
                    break;
                }
                "jmp" | "b" | "br" => {
                    jumped = false;
                    if let Some(t) = direct_target(&ins.operands) {
                        if t > ins.addr && t < start.saturating_add(max) {
                            // forward jump inside the body: continue there
                            work.push(t);
                            jumped = true;
                        }
                    }
                    break; // indirect/backward/outside: body ends here
                }
                m if m.starts_with("invalid") => break,
                _ => {}
            }
        }
        if !jumped {
            // chunk ran out without a terminator: keep going linearly
            if let Some(last) = insns.last() {
                let next = last.addr.saturating_add(last.size as u64);
                if next < start.saturating_add(max) {
                    work.push(next);
                }
            }
        }
    }
    calls.sort_unstable();
    calls.dedup();
    (end.saturating_sub(start).min(max), calls)
}

/// First operand when it is a bare hex immediate (`0x…` or Capstone's `#0x…`).
/// Memory operands (`qword ptr [rip + 0x10]`) and anything non-hex are rejected.
pub(crate) fn direct_target(operands: &str) -> Option<u64> {
    let token = operands
        .split(|c: char| c == ',' || c == ' ' || c == '\t')
        .next()
        .unwrap_or("");
    let token = token.strip_prefix('#').unwrap_or(token);
    let hex = token.strip_prefix("0x")?;
    if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}

/// Local and export symbols that lie in a text section (`__text`, `.text`,
/// `CODE`, `.init`, `.fini`). Imports, address 0, and other section names
/// (including LE `code0` / `data0`) are not seeds.
fn symbol_seeds(target: &Target) -> Vec<u64> {
    target
        .symbols
        .iter()
        .filter(|sym| matches!(sym.kind, SymbolKind::Local | SymbolKind::Export) && sym.addr != 0)
        .filter(|sym| {
            target.sections.iter().any(|sec| {
                matches!(sec.name.as_str(), "__text" | ".text" | "CODE" | ".init" | ".fini")
                    && sym.addr >= sec.addr
                    && sym.addr < sec.addr + sec.size
            })
        })
        .map(|sym| sym.addr)
        .collect()
}

/// Discover functions: entry point, symbol seeds in text sections, and
/// prologue scan, expanded through direct call edges. Returns functions
/// sorted by address.
pub fn discover_functions(target: &Target) -> Vec<Function> {
    let mut seeds: BTreeSet<u64> = BTreeSet::new();
    seeds.insert(target.entry);
    for addr in symbol_seeds(target) {
        seeds.insert(addr);
    }
    for sec in code_sections(target) {
        for s in prologue_starts(target, sec) {
            seeds.insert(s);
        }
        for t in sweep_call_targets(target, sec) {
            seeds.insert(t);
        }
    }

    let mut funcs: BTreeMap<u64, Function> = BTreeMap::new();
    let mut queue: Vec<u64> = seeds.into_iter().collect();
    while let Some(addr) = queue.pop() {
        if funcs.contains_key(&addr) {
            continue;
        }
        let (size, calls) = function_body(target, addr, 0x20000);
        if size == 0 {
            continue;
        }
        for c in &calls {
            if !funcs.contains_key(c) && *c != addr {
                queue.push(*c);
            }
        }
        funcs.insert(
            addr,
            Function {
                addr,
                size,
                calls: calls.clone(),
            },
        );
    }
    funcs.into_values().collect()
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CallEdge {
    pub from: u64,
    pub to: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CallGraph {
    pub edges: Vec<CallEdge>,
    /// callee address -> caller addresses, both sorted
    pub callers: BTreeMap<u64, Vec<u64>>,
}

/// Direct calls whose target is the address of a function in `functions`.
/// Calls outside that set are dropped. Edges are sorted by `(from, to)` and
/// deduplicated; `callers` lists the sorted unique callers of each callee.
pub fn call_graph(functions: &[Function]) -> CallGraph {
    let known: BTreeSet<u64> = functions.iter().map(|f| f.addr).collect();
    let mut edges: Vec<CallEdge> = Vec::new();
    for f in functions {
        for &to in &f.calls {
            if known.contains(&to) {
                edges.push(CallEdge { from: f.addr, to });
            }
        }
    }
    edges.sort_by(|a, b| a.from.cmp(&b.from).then(a.to.cmp(&b.to)));
    edges.dedup_by(|a, b| a.from == b.from && a.to == b.to);

    let mut callers: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for edge in &edges {
        let callers_of = callers.entry(edge.to).or_default();
        if callers_of.last() != Some(&edge.from) {
            callers_of.push(edge.from);
        }
    }
    CallGraph { edges, callers }
}

/// PC-relative data addresses in `__text` and `.text` only.
///
/// Arm64 keeps a map from the destination register to the ADRP page.
/// `add` of that register emits `page + imm` and drops the page, because the
/// register now holds the full address. `ldr` / `ldrb` / `ldrh` / `ldrsw`
/// from a still-live page emit `page + disp`. Any other write of a mapped
/// register drops it. x86_64 emits `insn + len + disp` for each RIP-relative
/// memory operand with no index. 32-bit x86 records a `call` to the next
/// instruction, the following `pop`, and a later load through that register.
/// ARM and Thumb record `ldr` / `ldrb` / `ldrh` from `pc`.
fn pc_relative_index(target: &Target) -> BTreeMap<u64, Vec<u64>> {
    let mut index = BTreeMap::new();
    if matches!(target.arch, Arch::Unknown) {
        return index;
    }
    let Ok(mut cs) = disasm::build_capstone(target.arch) else {
        return index;
    };
    if cs.set_detail(true).is_err() {
        return index;
    }
    for sec in target
        .sections
        .iter()
        .filter(|sec| sec.size > 0 && matches!(sec.name.as_str(), "__text" | ".text"))
    {
        let start = sec.file_offset as usize;
        let end = start.saturating_add(sec.size as usize).min(target.bytes.len());
        if start >= end {
            continue;
        }
        let code = &target.bytes[start..end];
        let Ok(insns) = cs.disasm_all(code, sec.addr) else {
            continue;
        };
        match target.arch {
            Arch::Arm64 => collect_arm64_pc_rel(&cs, insns.as_ref(), &mut index),
            Arch::X86_64 => collect_x86_64_pc_rel(&cs, insns.as_ref(), &mut index),
            Arch::X86 => collect_x86_32_pc_rel(&cs, insns.as_ref(), &mut index),
            Arch::Arm => collect_arm_pc_rel(&cs, insns.as_ref(), true, &mut index),
            Arch::Unknown => {}
        }
        if target.arch == Arch::Arm {
            if let Ok(mut a32) = arm_mode_capstone() {
                if a32.set_detail(true).is_ok() {
                    if let Ok(insns) = a32.disasm_all(code, sec.addr) {
                        collect_arm_pc_rel(&a32, insns.as_ref(), false, &mut index);
                    }
                }
            }
        }
    }
    index
}

fn arm_mode_capstone() -> Result<capstone::Capstone, capstone::Error> {
    use capstone::arch::BuildsCapstone;
    capstone::Capstone::new()
        .arm()
        .mode(capstone::arch::arm::ArchMode::Arm)
        .build()
}

fn collect_arm64_pc_rel(
    cs: &capstone::Capstone,
    insns: &[capstone::Insn<'_>],
    index: &mut BTreeMap<u64, Vec<u64>>,
) {
    use capstone::arch::arm64::Arm64OperandType::{Imm, Mem, Reg};
    use capstone::arch::DetailsArchInsn;
    // Register id -> ADRP page. `add` of that register consumes the page.
    let mut pages: BTreeMap<u16, u64> = BTreeMap::new();
    for ins in insns {
        let Ok(detail) = cs.insn_detail(ins) else {
            continue;
        };
        let arch = detail.arch_detail();
        let Some(arm) = arch.arm64() else {
            continue;
        };
        let ops: Vec<_> = arm.operands().map(|op| op.op_type).collect();
        let mnem = ins.mnemonic().unwrap_or("");
        let from = ins.address();
        let handled = match mnem {
            "adrp" => match ops.as_slice() {
                [Reg(dest), Imm(page)] if *page >= 0 => {
                    pages.insert(dest.0, *page as u64);
                    true
                }
                _ => false,
            },
            "add" => match ops.as_slice() {
                [Reg(dest), Reg(src), Imm(off)] if *off >= 0 => {
                    if let Some(&page) = pages.get(&src.0) {
                        index
                            .entry(page.wrapping_add(*off as u64))
                            .or_default()
                            .push(from);
                        // The destination now holds the full address, not the page.
                        pages.remove(&dest.0);
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            },
            "ldr" | "ldrb" | "ldrh" | "ldrsw" => {
                let mut hit = false;
                for op in &ops {
                    let Mem(mem) = op else {
                        continue;
                    };
                    let Some(&page) = pages.get(&mem.base().0) else {
                        continue;
                    };
                    hit = true;
                    if mem.disp() >= 0 {
                        index
                            .entry(page + mem.disp() as u64)
                            .or_default()
                            .push(from);
                    }
                }
                hit
            }
            _ => false,
        };
        if !handled {
            if let Some(Reg(dest)) = ops.first() {
                pages.remove(&dest.0);
            }
        }
    }
}

fn collect_x86_64_pc_rel(
    cs: &capstone::Capstone,
    insns: &[capstone::Insn<'_>],
    index: &mut BTreeMap<u64, Vec<u64>>,
) {
    use capstone::arch::x86::X86OperandType::Mem;
    use capstone::arch::DetailsArchInsn;
    // Capstone's X86_REG_RIP. The absolute address is not in the immediate.
    const X86_REG_RIP: u16 = 41;
    for ins in insns {
        let Ok(detail) = cs.insn_detail(ins) else {
            continue;
        };
        let arch = detail.arch_detail();
        let Some(x86) = arch.x86() else {
            continue;
        };
        let from = ins.address();
        let next = from.wrapping_add(ins.bytes().len() as u64);
        for op in x86.operands() {
            let Mem(mem) = op.op_type else {
                continue;
            };
            if mem.base().0 == X86_REG_RIP && mem.index().0 == 0 {
                let to = next.wrapping_add(mem.disp() as u64);
                index.entry(to).or_default().push(from);
            }
        }
    }
}

/// `call` of the next instruction, then `pop reg`, then a load `[reg + disp]`.
fn collect_x86_32_pc_rel(
    cs: &capstone::Capstone,
    insns: &[capstone::Insn<'_>],
    index: &mut BTreeMap<u64, Vec<u64>>,
) {
    use capstone::arch::x86::X86OperandType::{Imm, Mem, Reg};
    use capstone::arch::DetailsArchInsn;
    let mut pending: Option<u64> = None;
    let mut held: Option<(u16, u64)> = None;
    for ins in insns {
        let Ok(detail) = cs.insn_detail(ins) else {
            pending = None;
            continue;
        };
        let arch = detail.arch_detail();
        let Some(x86) = arch.x86() else {
            continue;
        };
        let ops: Vec<_> = x86.operands().map(|op| op.op_type).collect();
        let mnem = ins.mnemonic().unwrap_or("");
        let from = ins.address();
        let next = from.wrapping_add(ins.bytes().len() as u64);
        if mnem == "call" {
            pending = match ops.first() {
                Some(Imm(target)) if *target >= 0 && *target as u64 == next => Some(next),
                _ => None,
            };
            continue;
        }
        if mnem == "pop" {
            if let (Some(pc), Some(Reg(dest))) = (pending.take(), ops.first()) {
                held = Some((dest.0, pc));
            } else {
                pending = None;
            }
            continue;
        }
        pending = None;
        if let Some((reg, pc)) = held {
            for op in &ops {
                let Mem(mem) = op else {
                    continue;
                };
                if mem.base().0 == reg && mem.index().0 == 0 {
                    let to = pc.wrapping_add(mem.disp() as u64);
                    index.entry(to).or_default().push(from);
                }
            }
        }
        if matches!(mnem, "mov" | "lea" | "add" | "sub" | "xor") {
            if let Some(Reg(dest)) = ops.first() {
                if held.is_some_and(|(reg, _)| reg == dest.0) {
                    held = None;
                }
            }
        }
    }
}

/// Literal load from `pc`. Thumb aligns `addr + 4`. ARM adds 8.
fn collect_arm_pc_rel(
    cs: &capstone::Capstone,
    insns: &[capstone::Insn<'_>],
    thumb: bool,
    index: &mut BTreeMap<u64, Vec<u64>>,
) {
    use capstone::arch::arm::ArmOperandType::Mem;
    use capstone::arch::DetailsArchInsn;
    const ARM_REG_PC: u16 = 11;
    for ins in insns {
        let Ok(detail) = cs.insn_detail(ins) else {
            continue;
        };
        let arch = detail.arch_detail();
        let Some(arm) = arch.arm() else {
            continue;
        };
        let mnem = ins.mnemonic().unwrap_or("");
        if !matches!(mnem, "ldr" | "ldrb" | "ldrh") {
            continue;
        }
        let from = ins.address();
        for op in arm.operands() {
            let Mem(mem) = op.op_type else {
                continue;
            };
            if mem.base().0 != ARM_REG_PC || mem.index().0 != 0 || mem.disp() < 0 {
                continue;
            }
            let base = if thumb {
                from.wrapping_add(4) & !3
            } else {
                from.wrapping_add(8)
            };
            let to = base.wrapping_add(mem.disp() as u64);
            index.entry(to).or_default().push(from);
        }
    }
}

/// Find locations that reference `addr`. The needle is 8 little-endian bytes
/// when `bits >= 64`, otherwise the 4-byte little-endian value. This
/// over-matches (any byte pattern equal to the address). A 4-byte prefix is
/// not a hit on a 64-bit target. Text also contributes PC-relative hits on
/// arm64, x86_64, 32-bit x86, and ARM/Thumb. Results are sorted by `from` and deduped.
pub fn data_xrefs(target: &Target, addr: u64) -> Vec<XRef> {
    let needle8 = addr.to_le_bytes();
    let needle4 = (addr as u32).to_le_bytes();
    let needle: &[u8] = if target.bits >= 64 {
        &needle8
    } else {
        &needle4
    };
    let width = needle.len();
    let mut out = Vec::new();
    for sec in code_sections(target) {
        let start = sec.file_offset as usize;
        let end = start.saturating_add(sec.size as usize).min(target.bytes.len());
        let mut i = start;
        while i + width <= end {
            if &target.bytes[i..i + width] == needle {
                out.push(XRef {
                    from: sec.addr.saturating_add((i - start) as u64),
                    to: addr,
                });
            }
            i += 1;
        }
    }
    let pcrel = pc_relative_index(target);
    if let Some(froms) = pcrel.get(&addr) {
        for &from in froms {
            out.push(XRef { from, to: addr });
        }
    }
    out.sort_by_key(|xref| xref.from);
    out.dedup_by(|a, b| a.from == b.from);
    out
}

/// Index every pointer-width little-endian value in sections with the address
/// where it occurs. 8 bytes when `bits >= 64`; otherwise 4, zero-extended
/// into the `u64` key. One pass; used for string/reference lookup.
fn code_pointer_index(target: &Target) -> BTreeMap<u64, Vec<u64>> {
    let wide = target.bits >= 64;
    let mut index: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for sec in code_sections(target) {
        let start = sec.file_offset as usize;
        let end = start.saturating_add(sec.size as usize).min(target.bytes.len());
        if start >= end {
            continue;
        }
        let width = if wide { 8 } else { 4 };
        for i in start..end.saturating_sub(width - 1) {
            let key = if wide {
                u64::from_le_bytes([
                    target.bytes[i],
                    target.bytes[i + 1],
                    target.bytes[i + 2],
                    target.bytes[i + 3],
                    target.bytes[i + 4],
                    target.bytes[i + 5],
                    target.bytes[i + 6],
                    target.bytes[i + 7],
                ])
            } else {
                u32::from_le_bytes([
                    target.bytes[i],
                    target.bytes[i + 1],
                    target.bytes[i + 2],
                    target.bytes[i + 3],
                ]) as u64
            };
            index
                .entry(key)
                .or_default()
                .push(sec.addr.saturating_add((i - start) as u64));
        }
    }
    index
}

/// Strings with their virtual addresses and the code locations referencing
/// them. A code pointer counts as a reference when it lands anywhere within
/// the string's bytes (LE string records carry small headers, so pointers
/// often aim a few bytes before the printable text) or up to 16 bytes before
/// the text start.
pub fn strings_with_xrefs(target: &Target, min_len: usize) -> Vec<AnnotatedString> {
    let index = code_pointer_index(target);
    let pcrel = pc_relative_index(target);
    let mut out = Vec::new();
    for hit in strings::extract(&target.bytes, min_len) {
        let Some(sec) = target
            .sections
            .iter()
            .find(|s| hit.offset >= s.file_offset && hit.offset < s.file_offset + s.size)
        else {
            continue;
        };
        let vaddr = sec.addr + (hit.offset - sec.file_offset);
        let len = hit.value.len() as u64;
        let lo = vaddr.saturating_sub(16);
        let hi = vaddr + len;
        let mut refs: Vec<u64> = Vec::new();
        let mut p = lo;
        while p <= hi {
            let key = if target.bits >= 64 {
                p
            } else {
                u64::from(p as u32)
            };
            if let Some(locs) = index.get(&key) {
                refs.extend_from_slice(locs);
            }
            if let Some(locs) = pcrel.get(&p) {
                refs.extend_from_slice(locs);
            }
            p += 1;
        }
        refs.sort_unstable();
        refs.dedup();
        if !refs.is_empty() {
            out.push(AnnotatedString {
                vaddr,
                value: hit.value,
                refs,
            });
        }
    }
    out
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AnnotatedString {
    pub vaddr: u64,
    pub value: String,
    /// Code addresses that reference this string.
    pub refs: Vec<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_data_xref_pattern() {
        // A synthetic flat buffer: code bytes containing an absolute ref.
        let bytes = vec![0x90u8, 0xb8, 0x00, 0x10, 0x00, 0x00, 0x90];
        let target = Target {
            path: "synthetic".into(),
            format: crate::Format::Elf,
            arch: Arch::X86,
            bits: 32,
            little_endian: true,
            entry: 0,
            sections: vec![crate::Section {
                name: "code0".into(),
                addr: 0x1000,
                size: bytes.len() as u64,
                file_offset: 0,
                perms: "---".into(),
                sh_type: None,
                sh_flags: None,
            }],
            symbols: vec![],
            bytes,
            page_map: None,
        };
        let refs = data_xrefs(&target, 0x1000);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].from, 0x1002);
    }

    #[test]
    fn call_graph_drops_unknown_targets() {
        let a = 0x1000;
        let b = 0x2000;
        let functions = [
            Function {
                addr: a,
                size: 16,
                calls: vec![b, 0xdead],
            },
            Function {
                addr: b,
                size: 16,
                calls: vec![a],
            },
        ];
        let graph = call_graph(&functions);
        assert_eq!(graph.edges.len(), 2);
        assert_eq!((graph.edges[0].from, graph.edges[0].to), (a, b));
        assert_eq!((graph.edges[1].from, graph.edges[1].to), (b, a));
        assert_eq!(graph.callers.get(&a).map(Vec::as_slice), Some(&[b][..]));
        assert_eq!(graph.callers.get(&b).map(Vec::as_slice), Some(&[a][..]));
        assert!(!graph.callers.contains_key(&0xdead));
    }

    /// `disassemble` reads 4096 bytes at the start address. Pad the file so a
    /// read that begins inside `code` succeeds, but keep the section sized to
    /// the real bytes so the sweep does not walk the pad.
    fn synthetic_code(arch: Arch, bits: u8, code: &[u8]) -> Target {
        let mut bytes = code.to_vec();
        bytes.resize(code.len() + 4096, 0);
        Target {
            path: "synthetic".into(),
            format: crate::Format::Elf,
            arch,
            bits,
            little_endian: true,
            entry: 0x1000,
            sections: vec![crate::Section {
                name: "code0".into(),
                addr: 0x1000,
                size: code.len() as u64,
                file_offset: 0,
                perms: "---".into(),
                sh_type: None,
                sh_flags: None,
            }],
            symbols: vec![],
            bytes,
            page_map: None,
        }
    }

    #[test]
    fn direct_target_parses_hex_immediates() {
        assert_eq!(direct_target("0x1000"), Some(0x1000));
        assert_eq!(direct_target("#0xabc"), Some(0xabc));
        assert_eq!(direct_target("qword ptr [rip + 0x10]"), None);
        assert_eq!(direct_target(""), None);
    }

    #[test]
    fn discovers_x86_64_prologue_and_call() {
        // push rbp; mov rbp, rsp; call 0x100f; ret; nops; ret
        let code = [
            0x55, 0x48, 0x89, 0xe5, 0xe8, 0x06, 0x00, 0x00, 0x00, 0xc3, 0x90, 0x90, 0x90, 0x90,
            0x90, 0xc3,
        ];
        let funcs = discover_functions(&synthetic_code(Arch::X86_64, 64, &code));
        let entry = funcs.iter().find(|f| f.addr == 0x1000).expect("entry");
        assert_eq!(entry.calls, vec![0x100f]);
        assert!(funcs.iter().any(|f| f.addr == 0x100f));
    }

    #[test]
    fn thumb_push_pop_is_a_function() {
        // push {r7, lr}; pop {r7, pc}
        let code = [0x80, 0xb5, 0x80, 0xbd];
        let funcs = discover_functions(&synthetic_code(Arch::Arm, 32, &code));
        let entry = funcs
            .iter()
            .find(|f| f.addr == 0x1000)
            .expect("thumb entry");
        assert!(
            entry.size <= 8,
            "size {} (pop should stop the body)",
            entry.size
        );
    }

    #[test]
    fn discovers_arm64_prologue_and_bl() {
        // stp x29, x30, [sp, #-16]!; bl 0x1010; ret; nop; ret
        let code = [
            0xfd, 0x7b, 0xbf, 0xa9, 0x03, 0x00, 0x00, 0x94, 0xc0, 0x03, 0x5f, 0xd6, 0x1f, 0x20,
            0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6,
        ];
        let funcs = discover_functions(&synthetic_code(Arch::Arm64, 64, &code));
        let entry = funcs.iter().find(|f| f.addr == 0x1000).expect("entry");
        assert_eq!(entry.calls, vec![0x1010]);
        assert!(funcs.iter().any(|f| f.addr == 0x1010));
    }

    #[test]
    fn arm64_forward_branch_extends_body() {
        // b 0x1008; ret; ret — body must follow the branch through the ret.
        let code = [
            0x02, 0x00, 0x00, 0x14, 0xc0, 0x03, 0x5f, 0xd6, 0xc0, 0x03, 0x5f, 0xd6,
        ];
        let funcs = discover_functions(&synthetic_code(Arch::Arm64, 64, &code));
        let entry = funcs.iter().find(|f| f.addr == 0x1000).expect("entry");
        assert!(entry.size >= 12, "size {}", entry.size);
    }

    fn padded_ret_target(section_name: &str, kind: crate::SymbolKind) -> Target {
        let mut bytes = vec![0u8; 4096];
        bytes[0] = 0xc3;
        Target {
            path: "synthetic".into(),
            format: crate::Format::MachO,
            arch: Arch::X86,
            bits: 32,
            little_endian: true,
            entry: 0,
            sections: vec![crate::Section {
                name: section_name.into(),
                addr: 0x1000,
                size: 1,
                file_offset: 0,
                perms: "---".into(),
                sh_type: None,
                sh_flags: None,
            }],
            symbols: vec![crate::Symbol::new(0x1000, 0, "f", kind)],
            bytes,
            page_map: None,
        }
    }

    #[test]
    fn symbol_in_text_is_a_function_seed() {
        let funcs = discover_functions(&padded_ret_target("__text", crate::SymbolKind::Local));
        assert!(funcs.iter().any(|f| f.addr == 0x1000));
    }

    #[test]
    fn import_and_non_text_symbol_are_not_seeds() {
        let funcs = discover_functions(&padded_ret_target("__cstring", crate::SymbolKind::Import));
        assert!(funcs.is_empty());
        // A defined symbol in a non-text section is not a seed either.
        let local = discover_functions(&padded_ret_target("__cstring", crate::SymbolKind::Local));
        assert!(local.is_empty());
    }

    fn pointer_target(arch: Arch, bits: u8, bytes: &[u8]) -> Target {
        Target {
            path: "synthetic".into(),
            format: crate::Format::Elf,
            arch,
            bits,
            little_endian: true,
            entry: 0,
            sections: vec![crate::Section {
                name: ".text".into(),
                addr: 0x1000,
                size: bytes.len() as u64,
                file_offset: 0,
                perms: "---".into(),
                sh_type: None,
                sh_flags: None,
            }],
            symbols: vec![],
            bytes: bytes.to_vec(),
            page_map: None,
        }
    }

    #[test]
    fn data_xref_on_64bit_is_eight_bytes() {
        let bytes = [0x08, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let target = pointer_target(Arch::Arm64, 64, &bytes);
        assert_eq!(data_xrefs(&target, 0x1008).len(), 1);

        let short = pointer_target(Arch::Arm64, 64, &[0x08, 0x10, 0x00, 0x00]);
        assert!(data_xrefs(&short, 0x1008).is_empty());
    }

    #[test]
    fn string_xref_follows_64bit_pointer() {
        let mut bytes = vec![0x08, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        bytes.extend_from_slice(b"hello\0");
        bytes.extend_from_slice(&[0u8; 16]);
        let target = pointer_target(Arch::Arm64, 64, &bytes);
        let hits = strings_with_xrefs(&target, 4);
        let hello = hits.iter().find(|s| s.value == "hello").expect("hello");
        assert!(hello.refs.contains(&0x1000));
    }

    fn flat_target(arch: Arch, bits: u8, sections: Vec<crate::Section>, bytes: Vec<u8>) -> Target {
        Target {
            path: "synthetic".into(),
            format: crate::Format::Elf,
            arch,
            bits,
            little_endian: true,
            entry: 0,
            sections,
            symbols: vec![],
            bytes,
            page_map: None,
        }
    }

    #[test]
    fn arm64_adrp_add_is_an_xref() {
        let bytes = vec![0x00, 0x00, 0x00, 0xb0, 0x00, 0x80, 0x00, 0x91];
        let target = flat_target(
            Arch::Arm64,
            64,
            vec![crate::Section {
                name: "__text".into(),
                addr: 0x1000,
                size: 8,
                file_offset: 0,
                perms: "---".into(),
                sh_type: None,
                sh_flags: None,
            }],
            bytes,
        );
        let refs = data_xrefs(&target, 0x2020);
        assert_eq!(
            refs.iter().filter(|r| r.from == 0x1004).count(),
            1,
            "{refs:?}"
        );
    }

    #[test]
    fn arm64_adrp_ldr_is_an_xref() {
        // adrp x0, #0x2000; ldr x1, [x0, #8] — no add in between.
        let bytes = vec![0x00, 0x00, 0x00, 0xb0, 0x01, 0x04, 0x40, 0xf9];
        let target = flat_target(
            Arch::Arm64,
            64,
            vec![crate::Section {
                name: "__text".into(),
                addr: 0x1000,
                size: 8,
                file_offset: 0,
                perms: "---".into(),
                sh_type: None,
                sh_flags: None,
            }],
            bytes,
        );
        let refs = data_xrefs(&target, 0x2008);
        assert!(refs.iter().any(|r| r.from == 0x1004), "{refs:?}");
    }

    #[test]
    fn arm64_add_consumes_the_adrp_page() {
        // adrp; add x0, x0, #0x20; ldr x1, [x0, #8]
        // The load is not a reference to the stale page.
        let bytes = vec![
            0x00, 0x00, 0x00, 0xb0, 0x00, 0x80, 0x00, 0x91, 0x01, 0x04, 0x40, 0xf9,
        ];
        let target = flat_target(
            Arch::Arm64,
            64,
            vec![crate::Section {
                name: "__text".into(),
                addr: 0x1000,
                size: 12,
                file_offset: 0,
                perms: "---".into(),
                sh_type: None,
                sh_flags: None,
            }],
            bytes,
        );
        assert!(data_xrefs(&target, 0x2020).iter().any(|r| r.from == 0x1004));
        assert!(data_xrefs(&target, 0x2008).is_empty());
    }

    #[test]
    fn x86_64_rip_relative_is_an_xref() {
        let bytes = vec![0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00];
        let target = flat_target(
            Arch::X86_64,
            64,
            vec![crate::Section {
                name: ".text".into(),
                addr: 0x1000,
                size: 7,
                file_offset: 0,
                perms: "---".into(),
                sh_type: None,
                sh_flags: None,
            }],
            bytes,
        );
        let refs = data_xrefs(&target, 0x23bf);
        assert!(refs.iter().any(|r| r.from == 0x1000), "{refs:?}");
        assert!(data_xrefs(&target, 0x13b8).is_empty());
    }

    #[test]
    fn x86_32_call_pop_load_is_an_xref() {
        // call next; pop eax; mov eax, [eax + 0x10]
        let bytes = vec![0xe8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x8b, 0x40, 0x10];
        let target = flat_target(
            Arch::X86,
            32,
            vec![crate::Section {
                name: ".text".into(),
                addr: 0x1000,
                size: bytes.len() as u64,
                file_offset: 0,
                perms: "---".into(),
                sh_type: None,
                sh_flags: None,
            }],
            bytes,
        );
        let refs = data_xrefs(&target, 0x1015);
        assert!(refs.iter().any(|r| r.from == 0x1006), "{refs:?}");
    }

    #[test]
    fn thumb_literal_load_is_an_xref() {
        // ldr r0, [pc, #4] at 0x1000. Thumb base is align(0x1004, 4) + 4.
        let bytes = vec![0x01, 0x48];
        let target = flat_target(
            Arch::Arm,
            32,
            vec![crate::Section {
                name: ".text".into(),
                addr: 0x1000,
                size: 2,
                file_offset: 0,
                perms: "---".into(),
                sh_type: None,
                sh_flags: None,
            }],
            bytes,
        );
        let refs = data_xrefs(&target, 0x1008);
        assert!(refs.iter().any(|r| r.from == 0x1000), "{refs:?}");
    }

    #[test]
    fn arm_literal_load_is_an_xref() {
        // ldr r0, [pc, #8]. ARM base is 0x1000 + 8 + 8.
        let bytes = vec![0x08, 0x00, 0x9f, 0xe5];
        let target = flat_target(
            Arch::Arm,
            32,
            vec![crate::Section {
                name: ".text".into(),
                addr: 0x1000,
                size: 4,
                file_offset: 0,
                perms: "---".into(),
                sh_type: None,
                sh_flags: None,
            }],
            bytes,
        );
        let refs = data_xrefs(&target, 0x1010);
        assert!(refs.iter().any(|r| r.from == 0x1000), "{refs:?}");
    }

    #[test]
    fn string_xref_follows_adrp_add() {
        let mut bytes = vec![0x00, 0x00, 0x00, 0xb0, 0x00, 0x80, 0x00, 0x91];
        bytes.extend_from_slice(b"hello\0");
        let target = flat_target(
            Arch::Arm64,
            64,
            vec![
                crate::Section {
                    name: "__text".into(),
                    addr: 0x1000,
                    size: 8,
                    file_offset: 0,
                    perms: "---".into(),
                    sh_type: None,
                    sh_flags: None,
                },
                crate::Section {
                    name: "__cstring".into(),
                    addr: 0x2020,
                    size: 6,
                    file_offset: 8,
                    perms: "---".into(),
                    sh_type: None,
                    sh_flags: None,
                },
            ],
            bytes,
        );
        let hits = strings_with_xrefs(&target, 4);
        let hello = hits.iter().find(|s| s.value == "hello").expect("hello");
        assert!(hello.refs.contains(&0x1004), "{:?}", hello.refs);
    }
}
