//! Disassembly via capstone, mapped through the uniform [`Target`] view.

use crate::{Arch, Target};

#[derive(Debug, Clone, serde::Serialize)]
pub struct Instruction {
    pub addr: u64,
    pub size: u16,
    pub mnemonic: String,
    pub operands: String,
}

#[derive(Debug, thiserror::Error)]
pub enum DisasmError {
    #[error("unsupported architecture {0:?}")]
    Unsupported(Arch),
    #[error("capstone error: {0}")]
    Capstone(String),
}

type Result<T> = std::result::Result<T, DisasmError>;

/// Disassemble up to `count` instructions starting at virtual address `vaddr`.
pub fn disassemble(target: &Target, vaddr: u64, count: usize) -> Result<Vec<Instruction>> {
    let cs = build_capstone(target.arch)?;

    let code = target
        .read_at_vaddr(vaddr, 4096)
        .ok_or(DisasmError::Capstone(format!("vaddr {vaddr:#x} not mapped")))?;

    let insns = cs
        .disasm_count(code, vaddr, count)
        .map_err(|e| DisasmError::Capstone(e.to_string()))?;

    Ok(insns
        .iter()
        .map(|i| Instruction {
            addr: i.address(),
            size: i.bytes().len() as u16,
            mnemonic: i.mnemonic().unwrap_or("").to_string(),
            operands: i.op_str().unwrap_or("").to_string(),
        })
        .collect())
}

pub(crate) fn build_capstone(arch: Arch) -> Result<capstone::Capstone> {
    use capstone::arch::*;
    use capstone::prelude::*;

    match arch {
        Arch::X86 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .build(),
        Arch::X86_64 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .build(),
        Arch::Arm => Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Thumb)
            .build(),
        Arch::Arm64 => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build(),
        Arch::Unknown => return Err(DisasmError::Unsupported(Arch::Unknown)),
    }
    .map_err(|e| DisasmError::Capstone(e.to_string()))
}
