//! Static analysis: function discovery, call graph, and cross-references.
//!
//! Approach is deliberately simple and format-agnostic:
//! - Function starts come from the entry point, every direct `call` target
//!   reachable from already-known functions, and `push ebp; mov ebp, esp`
//!   prologues found by scanning code sections (catches callbacks the call
//!   graph misses).
//! - Function bodies are linear disassembly runs ending at `ret`/`jmp`.
//! - Data cross-references come from searching code bytes for the 4-byte
//!   little-endian address (covers `mov reg, [addr]`, `push [addr]`, and
//!   immediate loads — the dominant patterns in 32-bit flat code).

use crate::{disasm, strings, Arch, Target};
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

/// Linear-sweep a code section, returning every direct `call` target found.
/// Recovers from invalid bytes by advancing one byte, so the whole section
/// gets covered (mixed code/data in flat 32-bit images).
fn sweep_call_targets(target: &Target, sec: &crate::Section) -> Vec<u64> {
    if target.arch != Arch::X86 {
        return Vec::new();
    }
    let Ok(mut cs) = disasm::build_capstone(target.arch) else {
        return Vec::new();
    };
    let _ = cs.set_skipdata(true); // treat unknown bytes as data, keep going

    let start = sec.file_offset as usize;
    let end = (start + sec.size as usize).min(target.bytes.len());
    if start >= end {
        return Vec::new();
    }
    let code = &target.bytes[start..end];
    let base = sec.addr;

    let mut targets = Vec::new();
    let mut pos = 0usize;
    while pos < code.len() {
        match cs.disasm_count(&code[pos..], base + pos as u64, 64) {
            Ok(insns) if !insns.is_empty() => {
                let mut consumed = 0usize;
                for ins in insns.iter() {
                    consumed += ins.bytes().len();
                    if ins.mnemonic().unwrap_or("") == "call" {
                        if let Some(op) = ins.op_str().unwrap_or("").strip_prefix("0x") {
                            if let Ok(t) = u64::from_str_radix(op, 16) {
                                targets.push(t);
                            }
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

/// Find `push ebp; mov ebp, esp` prologues in a code section.
fn prologue_starts(target: &Target, sec: &crate::Section) -> Vec<u64> {
    if target.arch != Arch::X86 {
        return Vec::new();
    }
    let start = sec.file_offset as usize;
    let end = start + sec.size as usize;
    let mut out = Vec::new();
    if end > target.bytes.len() {
        return out;
    }
    let needle = [0x55u8, 0x8b, 0xec];
    let mut i = start;
    while i + 3 <= end {
        if &target.bytes[i..i + 3] == needle {
            out.push(sec.addr + (i - start) as u64);
            i += 1;
        } else {
            i += 1;
        }
    }
    out
}

/// Disassemble one linear run from `start`, returning (length, call targets).
fn linear_run(target: &Target, start: u64, max: u64) -> (u64, Vec<u64>) {
    let Ok(insns) = disasm::disassemble(target, start, 4096) else {
        return (0, Vec::new());
    };
    let mut calls = Vec::new();
    let mut end = start;
    for ins in insns {
        if ins.addr - start >= max {
            break;
        }
        end = ins.addr + ins.size as u64;
        if ins.mnemonic == "call" {
            if let Some(t) = ins.operands.strip_prefix("0x") {
                if let Ok(t) = u64::from_str_radix(t, 16) {
                    calls.push(t);
                }
            }
        }
        if ins.mnemonic == "ret" || ins.mnemonic == "retf" {
            break;
        }
        if ins.mnemonic == "jmp" && ins.operands.starts_with("0x") {
            break; // tail call / jump table: stop the linear run here
        }
        if ins.mnemonic.starts_with("invalid") {
            break;
        }
    }
    let size = end.saturating_sub(start);
    (size.min(max), calls)
}

/// Discover functions: entry point + prologue scan, expanded through direct
/// call edges. Returns functions sorted by address.
pub fn discover_functions(target: &Target) -> Vec<Function> {
    let mut seeds: BTreeSet<u64> = BTreeSet::new();
    seeds.insert(target.entry);
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
        let (size, calls) = linear_run(target, addr, 0x20000);
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

/// Find code locations that reference `addr` as a 32-bit immediate or
/// displacement. This over-matches (any byte pattern equal to the address),
/// which is acceptable for flat 32-bit code where such patterns are rare
/// unless intentional.
pub fn data_xrefs(target: &Target, addr: u64) -> Vec<XRef> {
    let needle = (addr as u32).to_le_bytes();
    let mut out = Vec::new();
    for sec in code_sections(target) {
        let start = sec.file_offset as usize;
        let end = (start + sec.size as usize).min(target.bytes.len());
        let mut i = start;
        while i + 4 <= end {
            if &target.bytes[i..i + 4] == needle {
                out.push(XRef {
                    from: sec.addr + (i - start) as u64,
                    to: addr,
                });
            }
            i += 1;
        }
    }
    out
}

/// Index every 4-byte little-endian value in code sections with the code
/// address where it occurs. One pass; used for string/reference lookup.
fn code_pointer_index(target: &Target) -> BTreeMap<u32, Vec<u64>> {
    let mut index: BTreeMap<u32, Vec<u64>> = BTreeMap::new();
    for sec in code_sections(target) {
        let start = sec.file_offset as usize;
        let end = (start + sec.size as usize).min(target.bytes.len());
        if start >= end {
            continue;
        }
        for i in start..end.saturating_sub(3) {
            let v = u32::from_le_bytes([
                target.bytes[i],
                target.bytes[i + 1],
                target.bytes[i + 2],
                target.bytes[i + 3],
            ]);
            index.entry(v).or_default().push(sec.addr + (i - start) as u64);
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
    let mut out = Vec::new();
    for hit in strings::extract(&target.bytes, min_len) {
        let Some(sec) = target.sections.iter().find(|s| {
            hit.offset >= s.file_offset && hit.offset < s.file_offset + s.size
        }) else {
            continue;
        };
        let vaddr = sec.addr + (hit.offset - sec.file_offset);
        let len = hit.value.len() as u64;
        let lo = vaddr.saturating_sub(16);
        let hi = vaddr + len;
        let mut refs: Vec<u64> = Vec::new();
        let mut p = lo;
        while p <= hi {
            if let Some(locs) = index.get(&(p as u32)) {
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
            }],
            symbols: vec![],
            bytes,
            page_map: None,
        };
        let refs = data_xrefs(&target, 0x1000);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].from, 0x1002);
    }
}
