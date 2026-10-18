//! rea-core: load a binary target and expose a uniform analysis surface
//! across Mach-O (incl. fat), ELF, and PE.

pub mod analysis;
pub mod artifact;
pub mod crash;
pub mod demangle;
pub mod disasm;
pub mod elf_meta;
pub mod goinfo;
pub mod headers;
pub mod le;
pub mod loader;
pub mod macho_meta;
pub mod pe_meta;
pub mod plist;
pub mod sqlite;
pub mod strings;
pub mod wasm;

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
    /// Three characters: `r`, `w`, `x`, or `-` for each missing bit.
    /// Mach-O uses the segment's initial protection. ELF has no read bit, so
    /// `SHF_ALLOC` is reported as readable. PE uses the section memory bits.
    /// LE uses object flags 0x1, 0x2, and 0x4.
    pub perms: String,
}

/// Format read, write, and execute as `rwx`, with `-` for a missing bit.
pub fn section_perms(read: bool, write: bool, exec: bool) -> String {
    format!(
        "{}{}{}",
        if read { 'r' } else { '-' },
        if write { 'w' } else { '-' },
        if exec { 'x' } else { '-' },
    )
}

/// A symbol defined or referenced by the target.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Symbol {
    pub addr: u64,
    pub size: u64,
    /// The name stored in the file. Mach-O Itanium names keep their `_Z` prefix.
    /// A single leading underscore is removed from other Mach-O names.
    pub name: String,
    /// Itanium C++ form, such as `foo(int)`. `None` when `name` is not mangled
    /// or the suffix does not fit that grammar. Listing still succeeds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demangled: Option<String>,
    pub kind: SymbolKind,
}

/// Bytes past the last mapped segment or PE raw section.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Overlay {
    pub offset: u64,
    pub size: u64,
}

/// Trailing bytes strictly after `image_end`. An end of zero, or a file that
/// ends on that boundary, is `None`.
pub fn trailing_overlay(image_end: u64, file_len: u64) -> Option<Overlay> {
    if image_end > 0 && file_len > image_end {
        Some(Overlay {
            offset: image_end,
            size: file_len - image_end,
        })
    } else {
        None
    }
}

impl Symbol {
    pub fn new(addr: u64, size: u64, name: impl Into<String>, kind: SymbolKind) -> Self {
        let name = name.into();
        let demangled = demangle::itanium(&name);
        Self {
            addr,
            size,
            name,
            demangled,
            kind,
        }
    }
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

#[cfg(test)]
mod tests {
    use super::section_perms;

    #[test]
    fn section_perms_uses_rwx_letters() {
        assert_eq!(section_perms(true, false, true), "r-x");
        assert_eq!(section_perms(true, true, false), "rw-");
        assert_eq!(section_perms(false, false, false), "---");
    }
}
