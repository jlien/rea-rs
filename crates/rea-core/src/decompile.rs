//! Straight-line pseudo-C from Capstone for the architectures already disassembled.
//!
//! This is a structured listing: assignments, calls, gotos, and returns. It is
//! not a type-recovering decompiler. A short or unmapped body returns an error
//! from disassembly and does not invent instructions.

use crate::{disasm, Error, Result, Target};

/// Pseudo-C for at most `limit` instructions at `addr`. `limit` is capped at 64.
pub fn decompile(target: &Target, addr: u64, limit: usize) -> Result<String> {
    let limit = limit.clamp(1, 64);
    let insns = disasm::disassemble(target, addr, limit).map_err(|e| Error::Parse(e.to_string()))?;
    if insns.is_empty() {
        return Err(Error::Parse("decompile: no instructions".into()));
    }
    let mut body = String::new();
    for insn in &insns {
        body.push_str(&format!("loc_{:x}:\n  {};\n", insn.addr, statement(insn)));
    }
    Ok(format!("void sub_{addr:x}() {{\n{body}}}\n"))
}

fn statement(insn: &disasm::Instruction) -> String {
    let m = insn.mnemonic.as_str();
    let ops = insn.operands.as_str();
    if m == "ret" || m == "retf" {
        return "return".to_string();
    }
    if m == "call" || m == "bl" || m == "blx" {
        let target = ops.split(',').next().unwrap_or(ops).trim();
        return format!("{target}()");
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
            return format!("{dst} = {src}");
        }
    }
    if ops.is_empty() {
        m.to_string()
    } else {
        format!("{m} {ops}")
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
    }

    #[test]
    fn arm64_ret_is_a_return() {
        let code = [0xc0, 0x03, 0x5f, 0xd6];
        let text = decompile(&target(Arch::Arm64, 64, &code), 0x1000, 4).unwrap();
        assert!(text.contains("return"), "{text}");
    }
}
