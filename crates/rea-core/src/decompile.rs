//! Straight-line pseudo-C from Capstone for the architectures already disassembled.
//!
//! This is a structured listing: assignments, calls, gotos, and returns. On x86_64
//! and arm64, registers that receive a value of known width inside the window are
//! rendered as synthetic typed locals (`int v1; void* v2;`): loads are typed by
//! the signedness and width of the load mnemonic, and `lea` / `adrp`+`add`
//! targets become `void*`. Where a typed value flows into a call argument or a
//! return, the statement carries a cast. It is still not a type-recovering
//! decompiler: inference stays inside the straight-line window, there is no
//! dataflow across basic blocks, and memory objects keep no types. A short or
//! unmapped body returns an error from disassembly and does not invent
//! instructions.

use crate::{disasm, Arch, Error, Result, Target};
use std::collections::HashMap;

/// Pseudo-C for at most `limit` instructions at `addr`. `limit` is capped at 64.
pub fn decompile(target: &Target, addr: u64, limit: usize) -> Result<String> {
    let limit = limit.clamp(1, 64);
    let insns = disasm::disassemble(target, addr, limit).map_err(|e| Error::Parse(e.to_string()))?;
    if insns.is_empty() {
        return Err(Error::Parse("decompile: no instructions".into()));
    }
    let typed = plan_types(&insns, target.arch);
    let mut names = Names::new(target.arch);
    let mut next = 0usize;
    let mut body = String::new();
    for (i, insn) in insns.iter().enumerate() {
        // A register carries its type from the instruction that typed it on;
        // earlier statements keep raw register names.
        while next < typed.len() && typed[next].first <= i {
            names.activate(&typed[next], next + 1);
            next += 1;
        }
        body.push_str(&format!("loc_{:x}:\n  {};\n", insn.addr, statement(insn, &names)));
    }
    let header: String = typed
        .iter()
        .enumerate()
        .map(|(i, r)| format!("  {} v{};\n", r.ty, i + 1))
        .collect();
    Ok(format!("void sub_{addr:x}() {{\n{header}{body}}}\n"))
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
}
