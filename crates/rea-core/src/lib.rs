//! rea-core: load a binary target and expose a uniform analysis surface
//! across Mach-O (incl. fat), ELF, and PE.

pub mod disasm;
pub mod le;
pub mod loader;
pub mod strings;

/// Executable file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    MachO,
    Elf,
    Pe,
    /// Watcom/DOS/4GW linear executable.
    Le,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Format::MachO => "mach-o",
            Format::Elf => "elf",
            Format::Pe => "pe",
            Format::Le => "le",
        }
    }
}

/// CPU architecture of a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86,
    X86_64,
    Arm,
    Arm64,
    Unknown,
}

impl Arch {
    pub fn as_str(self) -> &'static str {
        match self {
            Arch::X86 => "x86",
            Arch::X86_64 => "x86_64",
            Arch::Arm => "arm",
            Arch::Arm64 => "arm64",
            Arch::Unknown => "unknown",
        }
    }
}

/// A named region of the file mapped into memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Section {
    pub name: String,
    /// Virtual address once loaded.
    pub addr: u64,
    pub size: u64,
    /// Offset in the file (for the selected arch slice in fat binaries).
    pub file_offset: u64,
}

/// A symbol defined or referenced by the target.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Symbol {
    pub addr: u64,
    pub size: u64,
    pub name: String,
    pub kind: SymbolKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum SymbolKind {
    /// Defined in this binary.
    Local,
    /// Defined and exported.
    Export,
    /// Referenced from elsewhere (import).
    Import,
}

/// Uniform view over a loaded binary.
#[derive(Debug, Clone)]
pub struct Target {
    pub path: String,
    pub format: Format,
    pub arch: Arch,
    pub bits: u8,
    pub little_endian: bool,
    pub entry: u64,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    /// Raw file bytes (arch slice for fat Mach-O).
    pub bytes: Vec<u8>,
    /// Page-granular translation table (LE format). When present it takes
    /// precedence over the linear section mapping.
    pub page_map: Option<le::LePages>,
}

impl Target {
    /// Map a virtual address to a file offset. LE images translate through
    /// their object/page tables; everything else maps linearly via sections.
    pub fn vaddr_to_offset(&self, vaddr: u64) -> Option<u64> {
        if let Some(pm) = &self.page_map {
            return pm.translate(vaddr);
        }
        self.sections.iter().find_map(|s| {
            (vaddr >= s.addr && vaddr < s.addr + s.size)
                .then(|| s.file_offset + (vaddr - s.addr))
        })
    }

    /// Read `len` bytes at a virtual address.
    pub fn read_at_vaddr(&self, vaddr: u64, len: u64) -> Option<&[u8]> {
        let off = self.vaddr_to_offset(vaddr)? as usize;
        self.bytes.get(off..off + len as usize)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported or unrecognized binary: {0}")]
    Unrecognized(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error: {0}")]
    Parse(String),
}

pub type Result<T> = std::result::Result<T, Error>;
