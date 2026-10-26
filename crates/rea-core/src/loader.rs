//! Loaders producing a uniform [`Target`] for each supported format.

use crate::le::{self, LeImage};
use crate::{Arch, Error, Format, Result, Section, Symbol, SymbolKind, Target};
use std::path::Path;

/// Load and parse a binary from disk. Fat Mach-O binaries are resolved to
/// the host-compatible slice (first entry as fallback).
pub fn load(path: impl AsRef<Path>) -> Result<Target> {
    load_arch(path, None)
}

/// Load `path`. `arch` selects a Mach-O slice (`arm64`, `x86_64`, `arm`, `x86`).
/// `None` keeps the host slice. Other formats reject a selection.
pub fn load_arch(path: impl AsRef<Path>, arch: Option<&str>) -> Result<Target> {
    let path = path.as_ref();
    let bytes = std::fs::read(path).map_err(Error::Io)?;
    let path_str = path.display().to_string();

    // LE images must be checked before goblin: it mispeeks them as PE.
    if le::is_le(&bytes) {
        if arch.is_some() {
            return Err(Error::Parse("arch selection is mach-o only".into()));
        }
        return load_le(bytes, path_str);
    }

    // WASM must be checked before goblin too: peek does not know it. The
    // four-byte magic plus a version word is the whole identity check; the
    // deep parse stays on `wasm::inspect`.
    if bytes.len() >= 8 && bytes[..4] == *b"\0asm" {
        if arch.is_some() {
            return Err(Error::Parse("arch selection is mach-o only".into()));
        }
        return load_wasm(bytes, path_str);
    }

    // A database is identified by its 100-byte header: `sqlite::header`
    // accepting the file is the whole identity check. Rows, the WAL, and the
    // caps stay on `rea sqlite`, which reads the file itself.
    if bytes.starts_with(b"SQLite format 3\0") {
        if arch.is_some() {
            return Err(Error::Parse("arch selection is mach-o only".into()));
        }
        crate::sqlite::header(&bytes)?;
        return load_sqlite(bytes, path_str);
    }

    match {
        let mut cursor = std::io::Cursor::new(&*bytes);
        goblin::peek(&mut cursor).map_err(|e| Error::Parse(format!("peek failed: {e}")))?
    } {
        goblin::Hint::Mach(_) | goblin::Hint::MachFat(_) => load_macho_arch(bytes, path_str, arch),
        goblin::Hint::Elf(_) if arch.is_some() => {
            Err(Error::Parse("arch selection is mach-o only".into()))
        }
        goblin::Hint::Elf(_) => load_elf(bytes, path_str),
        goblin::Hint::PE if arch.is_some() => {
            Err(Error::Parse("arch selection is mach-o only".into()))
        }
        goblin::Hint::PE => load_pe(bytes, path_str),
        other => Err(Error::Unrecognized(format!(
            "format hint {other:?} is not supported"
        ))),
    }
}

/// A WASM module loads as an identity target: no sections, no symbols, no
/// entry, and no linear memory mapped in. `wasm::inspect` reads the module
/// for the deep commands, which read the file themselves.
fn load_wasm(bytes: Vec<u8>, path: String) -> Result<Target> {
    Ok(Target {
        path,
        format: Format::Wasm,
        arch: Arch::Unknown,
        bits: 32,
        little_endian: true,
        entry: 0,
        sections: Vec::new(),
        symbols: Vec::new(),
        bytes,
        page_map: None,
    })
}

/// A database loads as an identity target: no sections, no symbols, and no
/// entry. `sqlite::header` and `sqlite::schema` read the loaded bytes for
/// `rea info`; rows, the WAL, and the caps stay on `rea sqlite`.
fn load_sqlite(bytes: Vec<u8>, path: String) -> Result<Target> {
    Ok(Target {
        path,
        format: Format::Sqlite,
        arch: Arch::Unknown,
        bits: 64,
        little_endian: true,
        entry: 0,
        sections: Vec::new(),
        symbols: Vec::new(),
        bytes,
        page_map: None,
    })
}

fn load_le(bytes: Vec<u8>, path: String) -> Result<Target> {
    let img = LeImage::parse(&bytes)?;
    let entry = img.entry;
    let arch = img.arch();
    let sections = img.sections();
    // Apply internal fixups so analysis sees relocated pointers (the file
    // stores unrelocated values; DOS/4GW patches them at load time).
    let mut patched = bytes;
    img.apply_fixups(&mut patched)?;
    let page_map = img.pages;
    Ok(Target {
        path,
        format: Format::Le,
        arch,
        bits: 32,
        little_endian: true,
        entry,
        sections,
        symbols: Vec::new(),
        bytes: patched,
        page_map: Some(page_map),
    })
}

#[cfg(test)]
fn load_macho(bytes: Vec<u8>, path: String) -> Result<Target> {
    load_macho_arch(bytes, path, None)
}

fn load_macho_arch(bytes: Vec<u8>, path: String, arch: Option<&str>) -> Result<Target> {
    match goblin::mach::Mach::parse(&bytes)
        .map_err(|e| Error::Parse(format!("mach-o: {e}")))?
    {
        goblin::mach::Mach::Binary(mo) => {
            if let Some(name) = arch {
                let want = cputype_of(name)?;
                if mo.header.cputype() != want {
                    return Err(Error::Parse(format!("mach-o: no {name} slice")));
                }
            }
            macho_target(mo, bytes.clone(), path)
        }
        goblin::mach::Mach::Fat(fat) => {
            // Prefer a slice matching this host's arch; else the first.
            // An explicit arch replaces that choice and does not change the default.
            let host = if cfg!(target_arch = "aarch64") {
                goblin::mach::constants::cputype::CPU_TYPE_ARM64
            } else if cfg!(target_arch = "x86_64") {
                goblin::mach::constants::cputype::CPU_TYPE_X86_64
            } else {
                0
            };
            let arches: Vec<goblin::mach::fat::FatArch> = fat
                .iter_arches()
                .filter_map(|a| a.ok())
                .collect();
            let idx = if let Some(name) = arch {
                let want = cputype_of(name)?;
                arches
                    .iter()
                    .position(|a| a.cputype() == want)
                    .ok_or_else(|| Error::Parse(format!("mach-o: no {name} slice")))?
            } else {
                arches
                    .iter()
                    .position(|a| a.cputype() == host)
                    .unwrap_or(0)
            };
            let fa = arches
                .get(idx)
                .ok_or_else(|| Error::Parse("empty fat binary".into()))?;
            let (start, len) = (fa.offset as usize, fa.size as usize);
            let slice = bytes
                .get(start..start + len)
                .ok_or_else(|| Error::Parse("fat slice out of bounds".into()))?;
            let mo = goblin::mach::MachO::parse(slice, 0)
                .map_err(|e| Error::Parse(format!("mach-o slice: {e}")))?;
            macho_target(mo, slice.to_vec(), path)
        }
    }
}

fn cputype_of(name: &str) -> Result<u32> {
    match name {
        "arm64" => Ok(goblin::mach::constants::cputype::CPU_TYPE_ARM64),
        "x86_64" => Ok(goblin::mach::constants::cputype::CPU_TYPE_X86_64),
        "arm" => Ok(goblin::mach::constants::cputype::CPU_TYPE_ARM),
        "x86" => Ok(goblin::mach::constants::cputype::CPU_TYPE_X86),
        other => Err(Error::Parse(format!("mach-o: unknown arch {other}"))),
    }
}

fn macho_target(mo: goblin::mach::MachO, bytes: Vec<u8>, path: String) -> Result<Target> {
    let arch = match mo.header.cputype() {
        goblin::mach::constants::cputype::CPU_TYPE_X86 => Arch::X86,
        goblin::mach::constants::cputype::CPU_TYPE_X86_64 => Arch::X86_64,
        goblin::mach::constants::cputype::CPU_TYPE_ARM => Arch::Arm,
        goblin::mach::constants::cputype::CPU_TYPE_ARM64 => Arch::Arm64,
        _ => Arch::Unknown,
    };

    let mut sections = Vec::new();
    for seg in mo.segments.iter() {
        for (sect, _data) in seg
            .sections()
            .map_err(|e| Error::Parse(format!("sections: {e}")))?
        {
            let name = String::from_utf8_lossy(&sect.sectname).trim_end_matches('\0').to_string();
            let prot = seg.initprot;
            sections.push(Section {
                name,
                addr: u64::from(sect.addr),
                size: u64::from(sect.size),
                file_offset: u64::from(sect.offset),
                perms: crate::section_perms(
                    prot & goblin::mach::constants::VM_PROT_READ != 0,
                    prot & goblin::mach::constants::VM_PROT_WRITE != 0,
                    prot & goblin::mach::constants::VM_PROT_EXECUTE != 0,
                ),
                sh_type: None,
                sh_flags: None,
            });
        }
    }

    let mut symbols = Vec::new();
    for (name, nlist) in mo.symbols().flatten() {
        if nlist.is_stab() {
            continue;
        }
        let kind = if nlist.n_type & goblin::mach::symbols::N_TYPE
            == goblin::mach::symbols::N_UNDF
        {
            if nlist.n_value == 0 {
                SymbolKind::Import
            } else {
                SymbolKind::Export
            }
        } else if nlist.n_type & goblin::mach::symbols::N_EXT != 0 {
            SymbolKind::Export
        } else {
            SymbolKind::Local
        };
        let raw = name.to_string();
        // Mach-O C names carry one ABI underscore. Clang stores C++ as
        // `__Z3fooi` and Rust as `__R…`. The mangled spelling drops that one
        // underscore. A name that is already `_Z…` or `_R…` stays.
        // Other names drop one leading underscore, not every underscore.
        let stripped = raw.strip_prefix('_').unwrap_or(raw.as_str());
        let mangled = if stripped.starts_with("_Z") || stripped.starts_with("_R") {
            stripped
        } else if raw.starts_with("_Z") || raw.starts_with("_R") {
            raw.as_str()
        } else {
            ""
        };
        let (stored, demangled) = if mangled.starts_with("_Z") || mangled.starts_with("_R") {
            (mangled.to_string(), crate::demangle::any(mangled))
        } else {
            (stripped.to_string(), crate::demangle::any(stripped))
        };
        symbols.push(Symbol {
            addr: nlist.n_value,
            size: 0,
            name: stored,
            demangled,
            kind,
        });
    }

    Ok(Target {
        path,
        format: Format::MachO,
        arch,
        bits: if mo.is_64 { 64 } else { 32 },
        little_endian: true,
        entry: u64::from(mo.entry),
        sections,
        symbols,
        bytes,
        page_map: None,
    })
}

fn load_elf(bytes: Vec<u8>, path: String) -> Result<Target> {
    let elf = goblin::elf::Elf::parse(&bytes)
        .map_err(|e| Error::Parse(format!("elf: {e}")))?;
    let arch = match elf.header.e_machine {
        goblin::elf::header::EM_386 => Arch::X86,
        goblin::elf::header::EM_X86_64 => Arch::X86_64,
        goblin::elf::header::EM_ARM => Arch::Arm,
        goblin::elf::header::EM_AARCH64 => Arch::Arm64,
        _ => Arch::Unknown,
    };

    let shstr = &elf.shdr_strtab;
    let sections: Vec<Section> = elf
        .section_headers
        .iter()
        .map(|sh| {
            let flags = sh.sh_flags;
            Section {
                name: shstr.get_at(sh.sh_name).unwrap_or("").to_string(),
                addr: sh.sh_addr,
                size: sh.sh_size,
                file_offset: sh.sh_offset,
                perms: crate::section_perms(
                    flags & u64::from(goblin::elf::section_header::SHF_ALLOC) != 0,
                    flags & u64::from(goblin::elf::section_header::SHF_WRITE) != 0,
                    flags & u64::from(goblin::elf::section_header::SHF_EXECINSTR) != 0,
                ),
                sh_type: Some(sh_type_name(sh.sh_type)),
                sh_flags: Some(sh_flag_names(flags)),
            }
        })
        .collect();

    let mut symbols: Vec<Symbol> = elf
        .syms
        .iter()
        .map(|s| {
            Symbol::new(
                s.st_value,
                s.st_size,
                elf.strtab.get_at(s.st_name).unwrap_or(""),
                if s.is_import() {
                    SymbolKind::Import
                } else if s.st_shndx != 0 && s.st_name != 0 {
                    SymbolKind::Export
                } else {
                    SymbolKind::Local
                },
            )
        })
        .collect();
    for dynsym in elf.dynsyms.iter() {
        let name = elf.dynstrtab.get_at(dynsym.st_name).unwrap_or("").to_string();
        if dynsym.is_import()
            && !name.is_empty()
            && !symbols.iter().any(|s| s.name == name)
        {
            symbols.push(Symbol::new(0, 0, name, SymbolKind::Import));
        }
    }

    Ok(Target {
        path,
        format: Format::Elf,
        arch,
        bits: if elf.is_64 { 64 } else { 32 },
        little_endian: elf.little_endian,
        entry: elf.entry,
        sections,
        symbols,
        bytes,
        page_map: None,
    })
}

/// `sh_type` name for the common ids; unknown ids stay `0x…`.
fn sh_type_name(ty: u32) -> String {
    use goblin::elf::section_header as sh;
    let name = match ty {
        sh::SHT_NULL => "NULL",
        sh::SHT_PROGBITS => "PROGBITS",
        sh::SHT_SYMTAB => "SYMTAB",
        sh::SHT_STRTAB => "STRTAB",
        sh::SHT_RELA => "RELA",
        sh::SHT_HASH => "HASH",
        sh::SHT_DYNAMIC => "DYNAMIC",
        sh::SHT_NOTE => "NOTE",
        sh::SHT_NOBITS => "NOBITS",
        sh::SHT_REL => "REL",
        sh::SHT_DYNSYM => "DYNSYM",
        sh::SHT_INIT_ARRAY => "INIT_ARRAY",
        sh::SHT_FINI_ARRAY => "FINI_ARRAY",
        sh::SHT_GROUP => "GROUP",
        0x6ffffff6 => "GNU_HASH",
        0x6ffffffd => "VERDEF",
        0x6ffffffe => "VERNEED",
        0x6fffffff => "VERSYM",
        _ => return format!("0x{ty:x}"),
    };
    name.to_string()
}

/// SHF_ flag names not already visible in the `perms` string. WRITE, ALLOC,
/// and EXECINSTR map onto the `rwx` bits and are excluded.
fn sh_flag_names(flags: u64) -> Vec<String> {
    const SHF_MASKOS: u64 = 0x0ff00000;
    let mut out = Vec::new();
    let mut push = |bit: u64, name: &str| {
        if flags & bit != 0 {
            out.push(name.to_string());
        }
    };
    push(0x10, "MERGE");
    push(0x20, "STRINGS");
    push(0x40, "INFO_LINK");
    push(0x80, "LINK_ORDER");
    push(0x100, "OS_NONCONFORMING");
    push(0x200, "GROUP");
    push(0x400, "TLS");
    push(0x800, "COMPRESSED");
    push(0x8000_0000, "EXCLUDE");
    if flags & SHF_MASKOS != 0 {
        out.push(format!("os-0x{:x}", flags & SHF_MASKOS));
    }
    out
}

fn load_pe(bytes: Vec<u8>, path: String) -> Result<Target> {
    let pe = goblin::pe::PE::parse(&bytes)
        .map_err(|e| Error::Parse(format!("pe: {e}")))?;
    let machine = pe.header.coff_header.machine;
    let arch = match machine {
        goblin::pe::header::COFF_MACHINE_X86 => Arch::X86,
        goblin::pe::header::COFF_MACHINE_X86_64 => Arch::X86_64,
        goblin::pe::header::COFF_MACHINE_ARMNT => Arch::Arm,
        _ => Arch::Unknown,
    };

    let sections: Vec<Section> = pe
        .sections
        .iter()
        .map(|s| {
            let flags = s.characteristics;
            Section {
                name: String::from_utf8_lossy(&s.name).trim_end_matches('\0').to_string(),
                addr: u64::from(s.virtual_address),
                size: u64::from(s.virtual_size),
                file_offset: u64::from(s.pointer_to_raw_data),
                perms: crate::section_perms(
                    flags & goblin::pe::section_table::IMAGE_SCN_MEM_READ != 0,
                    flags & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE != 0,
                    flags & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0,
                ),
                sh_type: None,
                sh_flags: None,
            }
        })
        .collect();

    let mut symbols: Vec<Symbol> = pe
        .exports
        .iter()
        .map(|e| Symbol::new(e.rva as u64, 0, e.name.unwrap_or(""), SymbolKind::Export))
        .collect();
    for imp in pe.imports.iter() {
        symbols.push(Symbol::new(0, 0, imp.name.clone(), SymbolKind::Import));
    }

    Ok(Target {
        path,
        format: Format::Pe,
        arch,
        bits: if machine == goblin::pe::header::COFF_MACHINE_X86_64 { 64 } else { 32 },
        little_endian: true,
        entry: pe.entry as u64,
        sections,
        symbols,
        bytes,
        page_map: None,
    })
}

#[cfg(test)]
mod tests {
    use super::{load_elf, load_macho};
    use crate::SymbolKind;

    #[test]
    fn elf_section_names_use_the_string_table_offset() {
        let target = load_elf(elf_with_named_sections(), "fixture.elf".into()).unwrap();
        let names: Vec<_> = target.sections.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["", ".text", ".shstrtab"]);
        assert_eq!(target.sections[1].perms, "r-x");
        assert_eq!(target.sections[1].addr, 0x1000);
        assert_eq!(target.sections[1].sh_type.as_deref(), Some("PROGBITS"));
        assert_eq!(
            target.sections[1].sh_flags.as_deref(),
            Some(&["MERGE".to_string()][..])
        );
        assert_eq!(target.sections[2].sh_type.as_deref(), Some("STRTAB"));
        assert!(target.sections[2].sh_flags.as_ref().unwrap().is_empty());
        assert_eq!(target.sections[0].sh_type.as_deref(), Some("NULL"));
    }

    /// `.shstrtab` starts at offset 7. Using the section index would read `text`.
    fn elf_with_named_sections() -> Vec<u8> {
        let shstr = b"\0.text\0.shstrtab\0";
        let shstr_off = 64u64;
        let shoff = shstr_off + shstr.len() as u64;
        let mut file = vec![0u8; shoff as usize + 3 * 64];
        file[0..4].copy_from_slice(b"\x7fELF");
        file[4] = 2;
        file[5] = 1;
        file[6] = 1;
        file[16..18].copy_from_slice(&1u16.to_le_bytes());
        file[18..20].copy_from_slice(&62u16.to_le_bytes());
        file[20..24].copy_from_slice(&1u32.to_le_bytes());
        file[40..48].copy_from_slice(&shoff.to_le_bytes());
        file[52..54].copy_from_slice(&64u16.to_le_bytes());
        file[58..60].copy_from_slice(&64u16.to_le_bytes());
        file[60..62].copy_from_slice(&3u16.to_le_bytes());
        file[62..64].copy_from_slice(&2u16.to_le_bytes());
        file[shstr_off as usize..shstr_off as usize + shstr.len()].copy_from_slice(shstr);
        write_shdr(&mut file, shoff, 1, 1, 1, 0x16, 0x1000, 0, 0);
        write_shdr(&mut file, shoff, 2, 7, 3, 0, 0, shstr_off, shstr.len() as u64);
        file
    }

    fn write_shdr(
        buf: &mut [u8],
        shoff: u64,
        index: usize,
        name: u32,
        ty: u32,
        flags: u64,
        addr: u64,
        off: u64,
        size: u64,
    ) {
        let at = shoff as usize + index * 64;
        buf[at..at + 4].copy_from_slice(&name.to_le_bytes());
        buf[at + 4..at + 8].copy_from_slice(&ty.to_le_bytes());
        buf[at + 8..at + 16].copy_from_slice(&flags.to_le_bytes());
        buf[at + 16..at + 24].copy_from_slice(&addr.to_le_bytes());
        buf[at + 24..at + 32].copy_from_slice(&off.to_le_bytes());
        buf[at + 32..at + 40].copy_from_slice(&size.to_le_bytes());
        buf[at + 48..at + 56].copy_from_slice(&1u64.to_le_bytes());
    }

    #[test]
    fn macho_symbols_skip_stabs() {
        let target = load_macho(macho_with_stab(), "fixture.o".into()).unwrap();
        let got: Vec<_> = target
            .symbols
            .iter()
            .map(|s| (s.name.as_str(), s.kind, s.addr))
            .collect();
        assert_eq!(
            got,
            [
                ("main", SymbolKind::Local, 0x1000),
                ("printf", SymbolKind::Import, 0),
            ]
        );
    }

    /// `file.c` is an `N_SO` stab (`n_type` 0x64). A defined `main` and an undefined `printf` stay.
    fn macho_with_stab() -> Vec<u8> {
        let strs = b"\0main\0file.c\0printf\0";
        let symoff = 56u32;
        let nsyms = 3u32;
        let stroff = symoff + nsyms * 16;
        let mut file = vec![0u8; stroff as usize + strs.len()];
        file[0..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());
        file[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
        file[12..16].copy_from_slice(&1u32.to_le_bytes());
        file[16..20].copy_from_slice(&1u32.to_le_bytes());
        file[20..24].copy_from_slice(&24u32.to_le_bytes());
        file[32..36].copy_from_slice(&2u32.to_le_bytes());
        file[36..40].copy_from_slice(&24u32.to_le_bytes());
        file[40..44].copy_from_slice(&symoff.to_le_bytes());
        file[44..48].copy_from_slice(&nsyms.to_le_bytes());
        file[48..52].copy_from_slice(&stroff.to_le_bytes());
        file[52..56].copy_from_slice(&(strs.len() as u32).to_le_bytes());
        write_nlist(&mut file, symoff as usize, 1, 0x0e, 1, 0x1000);
        write_nlist(&mut file, symoff as usize + 16, 6, 0x64, 0, 0);
        write_nlist(&mut file, symoff as usize + 32, 13, 0x01, 0, 0);
        let at = stroff as usize;
        file[at..at + strs.len()].copy_from_slice(strs);
        file
    }

    fn write_nlist(buf: &mut [u8], at: usize, strx: u32, n_type: u8, n_sect: u8, value: u64) {
        buf[at..at + 4].copy_from_slice(&strx.to_le_bytes());
        buf[at + 4] = n_type;
        buf[at + 5] = n_sect;
        buf[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn itanium_name_is_demangled_and_the_raw_name_stays() {
        let target = load_macho(macho_with_itanium(), "fixture.o".into()).unwrap();
        let mangled = target
            .symbols
            .iter()
            .find(|s| s.name == "_Z3fooi")
            .expect("raw name");
        assert_eq!(mangled.demangled.as_deref(), Some("foo(int)"));
        let plain = target.symbols.iter().find(|s| s.name == "plain").expect("plain");
        assert_eq!(plain.demangled, None);
        let broken = target.symbols.iter().find(|s| s.name == "_Z3").expect("broken");
        assert_eq!(broken.demangled, None);
        let header = crate::headers::emit(&target);
        assert!(header.contains("foo(int)"), "{header}");
        assert!(header.contains("plain"), "{header}");
    }

    /// Clang `-c` stores `__Z3fooi`. One ABI underscore comes off, the raw
    /// name stays `_Z3fooi`, and the demangled form is `foo(int)`.
    #[test]
    fn clang_itanium_underscore_is_demangled_through_load_macho() {
        let bytes = macho_with_clang_itanium();
        assert!(bytes.windows(8).any(|w| w == b"__Z3fooi"));
        let target = load_macho(bytes, "clang.o".into()).unwrap();
        let foo = target
            .symbols
            .iter()
            .find(|s| s.name == "_Z3fooi")
            .expect("raw name");
        assert_eq!(foo.demangled.as_deref(), Some("foo(int)"));
        assert!(target.symbols.iter().all(|s| s.name != "Z3fooi"));
        let bar = target
            .symbols
            .iter()
            .find(|s| s.name == "_Z3barv")
            .expect("bar");
        assert_eq!(bar.demangled.as_deref(), Some("bar()"));
        let header = crate::headers::emit(&target);
        assert!(header.contains("foo(int)"), "{header}");
        assert!(header.contains("bar()"), "{header}");
    }

    #[test]
    fn clang_rust_v0_underscore_is_demangled_through_load_macho() {
        let strs = b"\0__RNvC3_foo3_bar\0";
        let symoff = 56u32;
        let nsyms = 1u32;
        let stroff = symoff + nsyms * 16;
        let mut file = vec![0u8; stroff as usize + strs.len()];
        file[0..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());
        file[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
        file[12..16].copy_from_slice(&1u32.to_le_bytes());
        file[16..20].copy_from_slice(&1u32.to_le_bytes());
        file[20..24].copy_from_slice(&24u32.to_le_bytes());
        file[32..36].copy_from_slice(&2u32.to_le_bytes());
        file[36..40].copy_from_slice(&24u32.to_le_bytes());
        file[40..44].copy_from_slice(&symoff.to_le_bytes());
        file[44..48].copy_from_slice(&nsyms.to_le_bytes());
        file[48..52].copy_from_slice(&stroff.to_le_bytes());
        file[52..56].copy_from_slice(&(strs.len() as u32).to_le_bytes());
        write_nlist(&mut file, symoff as usize, 1, 0x0f, 1, 0x1000);
        file[stroff as usize..].copy_from_slice(strs);
        let target = load_macho(file, "rust.o".into()).unwrap();
        let sym = target.symbols.iter().find(|s| s.name == "_RNvC3_foo3_bar").expect("raw");
        assert_eq!(sym.demangled.as_deref(), Some("foo::bar"));
    }

    /// Swift stores `_$s…` in the string table. One ABI underscore comes off,
    /// the raw name stays `$s…`, and the demangled form is `module.name`. A
    /// name that does not demangle keeps its raw name and no demangled form.
    #[test]
    fn swift_symbol_is_demangled_through_load_macho() {
        let strs = b"\0_$s4main3fooyyF\0_$s4main9\0";
        let symoff = 56u32;
        let nsyms = 2u32;
        let stroff = symoff + nsyms * 16;
        let mut file = vec![0u8; stroff as usize + strs.len()];
        file[0..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());
        file[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
        file[12..16].copy_from_slice(&1u32.to_le_bytes());
        file[16..20].copy_from_slice(&1u32.to_le_bytes());
        file[20..24].copy_from_slice(&24u32.to_le_bytes());
        file[32..36].copy_from_slice(&2u32.to_le_bytes());
        file[36..40].copy_from_slice(&24u32.to_le_bytes());
        file[40..44].copy_from_slice(&symoff.to_le_bytes());
        file[44..48].copy_from_slice(&nsyms.to_le_bytes());
        file[48..52].copy_from_slice(&stroff.to_le_bytes());
        file[52..56].copy_from_slice(&(strs.len() as u32).to_le_bytes());
        write_nlist(&mut file, symoff as usize, 1, 0x0f, 1, 0x1000);
        write_nlist(&mut file, symoff as usize + 16, 17, 0x0f, 1, 0x1010);
        file[stroff as usize..].copy_from_slice(strs);
        let target = load_macho(file, "swift.o".into()).unwrap();
        let sym = target
            .symbols
            .iter()
            .find(|s| s.name == "$s4main3fooyyF")
            .expect("raw name");
        assert_eq!(sym.demangled.as_deref(), Some("main.foo"));
        let broken = target
            .symbols
            .iter()
            .find(|s| s.name == "$s4main9")
            .expect("broken");
        assert_eq!(broken.demangled, None);
        // Headers print a Swift demangle as a comment (`/* main.foo */`),
        // never a declaration; the failed demangle stays absent.
        let header = crate::headers::emit(&target);
        assert!(header.contains("/* main.foo */"), "{header}");
        assert!(!header.contains("extern void $s4main3fooyyF"), "{header}");
        assert!(!header.contains("$s4main9"), "{header}");
    }

    fn macho_with_clang_itanium() -> Vec<u8> {
        let strs = b"\0__Z3fooi\0__Z3barv\0";
        let symoff = 56u32;
        let nsyms = 2u32;
        let stroff = symoff + nsyms * 16;
        let mut file = vec![0u8; stroff as usize + strs.len()];
        file[0..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());
        file[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
        file[12..16].copy_from_slice(&1u32.to_le_bytes());
        file[16..20].copy_from_slice(&1u32.to_le_bytes());
        file[20..24].copy_from_slice(&24u32.to_le_bytes());
        file[32..36].copy_from_slice(&2u32.to_le_bytes());
        file[36..40].copy_from_slice(&24u32.to_le_bytes());
        file[40..44].copy_from_slice(&symoff.to_le_bytes());
        file[44..48].copy_from_slice(&nsyms.to_le_bytes());
        file[48..52].copy_from_slice(&stroff.to_le_bytes());
        file[52..56].copy_from_slice(&(strs.len() as u32).to_le_bytes());
        write_nlist(&mut file, symoff as usize, 1, 0x0f, 1, 0x1000);
        write_nlist(&mut file, symoff as usize + 16, 10, 0x0e, 1, 0x1100);
        file[stroff as usize..stroff as usize + strs.len()].copy_from_slice(strs);
        file
    }

    fn macho_with_itanium() -> Vec<u8> {
        let strs = b"\0_Z3fooi\0plain\0_Z3\0";
        let symoff = 56u32;
        let nsyms = 3u32;
        let stroff = symoff + nsyms * 16;
        let mut file = vec![0u8; stroff as usize + strs.len()];
        file[0..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());
        file[4..8].copy_from_slice(&0x01000007u32.to_le_bytes());
        file[12..16].copy_from_slice(&1u32.to_le_bytes());
        file[16..20].copy_from_slice(&1u32.to_le_bytes());
        file[20..24].copy_from_slice(&24u32.to_le_bytes());
        file[32..36].copy_from_slice(&2u32.to_le_bytes());
        file[36..40].copy_from_slice(&24u32.to_le_bytes());
        file[40..44].copy_from_slice(&symoff.to_le_bytes());
        file[44..48].copy_from_slice(&nsyms.to_le_bytes());
        file[48..52].copy_from_slice(&stroff.to_le_bytes());
        file[52..56].copy_from_slice(&(strs.len() as u32).to_le_bytes());
        write_nlist(&mut file, symoff as usize, 1, 0x0f, 1, 0x1000);
        write_nlist(&mut file, symoff as usize + 16, 9, 0x0e, 1, 0x1100);
        write_nlist(&mut file, symoff as usize + 32, 15, 0x0e, 1, 0x1200);
        file[stroff as usize..stroff as usize + strs.len()].copy_from_slice(strs);
        file
    }

    #[test]
    fn non_host_slice_can_be_section_listed_and_disassembled() {
        let arm = code_slice(0x0100_000c, "__arm", &[0xc0, 0x03, 0x5f, 0xd6]);
        let intel = code_slice(0x0100_0007, "__intel", &[0xcc]);
        let fat = fat_pair(&arm, &intel);
        let path = std::env::temp_dir().join(format!(
            "rea-fat-{}-{}.bin",
            std::process::id(),
            fat.len()
        ));
        std::fs::write(&path, &fat).unwrap();
        let host = if cfg!(target_arch = "aarch64") {
            "arm64"
        } else {
            "x86_64"
        };
        let other = if host == "arm64" { "x86_64" } else { "arm64" };
        let host_name = if host == "arm64" { "__arm" } else { "__intel" };
        let other_name = if other == "arm64" { "__arm" } else { "__intel" };
        let loaded = super::load(&path).unwrap();
        assert_eq!(loaded.sections[0].name, host_name);
        let selected = super::load_arch(&path, Some(other)).unwrap();
        assert_eq!(selected.sections[0].name, other_name);
        assert_ne!(loaded.sections[0].name, selected.sections[0].name);
        let insns = crate::disasm::disassemble(&selected, 0x1000, 1).unwrap();
        let text = format!("{} {}", insns[0].mnemonic, insns[0].operands);
        if other == "x86_64" {
            assert!(text.contains("int3"), "{text}");
        } else {
            assert!(text.contains("ret"), "{text}");
        }
        let again = super::load(&path).unwrap();
        assert_eq!(again.sections[0].name, host_name);
        let _ = std::fs::remove_file(&path);
    }

    /// Type, function, export, and code sections: one defined function `f`
    /// with body `end`, exported as `f` func 0.
    fn wasm_module() -> Vec<u8> {
        let mut bytes = b"\0asm\x01\x00\x00\x00".to_vec();
        bytes.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);
        bytes.extend_from_slice(&[3, 2, 1, 0]);
        bytes.extend_from_slice(&[7, 5, 1, 1, b'f', 0, 0]);
        bytes.extend_from_slice(&[10, 4, 1, 2, 0, 0x0b]);
        bytes
    }

    #[test]
    fn wasm_loads_as_an_identity_target() {
        let bytes = wasm_module();
        let path = std::env::temp_dir().join(format!("rea-wasm-id-{}.wasm", std::process::id()));
        std::fs::write(&path, &bytes).unwrap();
        let target = super::load(&path).unwrap();
        assert_eq!(target.format, crate::Format::Wasm);
        assert_eq!(target.format.as_str(), "wasm");
        assert_eq!(target.arch, crate::Arch::Unknown);
        assert_eq!(target.bits, 32);
        assert!(target.little_endian);
        assert_eq!(target.entry, 0);
        assert!(target.sections.is_empty());
        assert!(target.symbols.is_empty());
        // The deep command still reads the module out of the loaded bytes.
        let module = crate::wasm::inspect(&target.bytes).unwrap();
        assert_eq!(module.sections, vec![1, 3, 7, 10]);
        assert_eq!(module.functions, 1);
        assert_eq!(module.exports.len(), 1);
        // Native-code commands reject the target, and so does `--arch`.
        assert!(target.require_native().is_err());
        let err = super::load_arch(&path, Some("arm64")).unwrap_err().to_string();
        assert!(err.contains("mach-o only"), "{err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wasm_shorter_than_the_header_stays_unrecognized() {
        let path = std::env::temp_dir().join(format!("rea-wasm-short-{}.wasm", std::process::id()));
        std::fs::write(&path, b"\0asm\x01").unwrap();
        let err = super::load(&path).unwrap_err().to_string();
        assert!(err.contains("peek failed"), "{err}");
        let _ = std::fs::remove_file(&path);
    }

    /// One 512-byte page: application id `0x01020304`, and a leaf schema
    /// b-tree with one row — table `notes`, root page 2, NULL SQL.
    fn sqlite_db() -> Vec<u8> {
        let mut db = vec![0u8; 512];
        db[..16].copy_from_slice(b"SQLite format 3\0");
        db[16..18].copy_from_slice(&512u16.to_be_bytes());
        db[18] = 1;
        db[19] = 1;
        db[21] = 64;
        db[22] = 32;
        db[23] = 32;
        db[28..32].copy_from_slice(&1u32.to_be_bytes());
        db[44..48].copy_from_slice(&4u32.to_be_bytes());
        db[56..60].copy_from_slice(&1u32.to_be_bytes());
        db[68..72].copy_from_slice(&0x0102_0304u32.to_be_bytes());
        // Record: header size 6, three text-5 serial types (2*5+13=23),
        // one int8, one NULL; body is table/name/table plus the root page.
        let mut payload: Vec<u8> = vec![6, 23, 23, 23, 1, 0];
        payload.extend_from_slice(b"tablenotesnotes");
        payload.push(2);
        let mut cell = vec![payload.len() as u8, 1];
        cell.extend_from_slice(&payload);
        let at = 512 - cell.len();
        db[at..at + cell.len()].copy_from_slice(&cell);
        db[100] = 0x0d; // leaf table b-tree
        db[103..105].copy_from_slice(&1u16.to_be_bytes());
        db[105..107].copy_from_slice(&(at as u16).to_be_bytes());
        db[108..110].copy_from_slice(&(at as u16).to_be_bytes());
        db
    }

    #[test]
    fn sqlite_loads_as_an_identity_target() {
        let bytes = sqlite_db();
        let path = std::env::temp_dir().join(format!("rea-sqlite-id-{}.db", std::process::id()));
        std::fs::write(&path, &bytes).unwrap();
        let target = super::load(&path).unwrap();
        assert_eq!(target.format, crate::Format::Sqlite);
        assert_eq!(target.format.as_str(), "sqlite");
        assert_eq!(target.arch, crate::Arch::Unknown);
        assert_eq!(target.bits, 64);
        assert!(target.little_endian);
        assert_eq!(target.entry, 0);
        assert!(target.sections.is_empty());
        assert!(target.symbols.is_empty());
        // `rea info` reads the header and the schema out of the loaded bytes.
        let hdr = crate::sqlite::header(&target.bytes).unwrap();
        assert_eq!(hdr.application_id, 0x0102_0304);
        assert_eq!(crate::sqlite::schema(&target.bytes).unwrap().len(), 1);
        // Native-code commands reject the target, and so does `--arch`.
        assert!(target.require_native().is_err());
        let err = super::load_arch(&path, Some("arm64")).unwrap_err().to_string();
        assert!(err.contains("mach-o only"), "{err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_magic_prefix_that_the_header_rejects_does_not_load() {
        let path = std::env::temp_dir().join(format!("rea-sqlite-short-{}.db", std::process::id()));
        std::fs::write(&path, b"SQLite format 3\0junk").unwrap();
        let err = super::load(&path).unwrap_err().to_string();
        assert!(err.contains("not a database header"), "{err}");
        let _ = std::fs::remove_file(&path);
    }

    fn code_slice(cputype: u32, sectname: &str, body: &[u8]) -> Vec<u8> {
        let code_off = 32 + 152;
        // Disassembly reads a 4096-byte window at the section address.
        let filesize = code_off + 4096;
        let mut file = vec![0u8; filesize];
        put_le32(&mut file, 0, 0xfeed_facf);
        put_le32(&mut file, 4, cputype);
        put_le32(&mut file, 12, 2);
        put_le32(&mut file, 16, 1);
        put_le32(&mut file, 20, 152);
        put_le32(&mut file, 32, 0x19);
        put_le32(&mut file, 36, 152);
        file[40..46].copy_from_slice(b"__TEXT");
        put_le64(&mut file, 64, filesize as u64);
        put_le64(&mut file, 80, filesize as u64);
        put_le32(&mut file, 88, 7);
        put_le32(&mut file, 92, 5);
        put_le32(&mut file, 96, 1);
        let sect = 104;
        let name = sectname.as_bytes();
        file[sect..sect + name.len()].copy_from_slice(name);
        file[sect + 16..sect + 22].copy_from_slice(b"__TEXT");
        put_le64(&mut file, sect + 32, 0x1000);
        put_le64(&mut file, sect + 40, body.len() as u64);
        put_le32(&mut file, sect + 48, code_off as u32);
        file[code_off..code_off + body.len()].copy_from_slice(body);
        file
    }

    fn fat_pair(first: &[u8], second: &[u8]) -> Vec<u8> {
        let off1 = 0x1000u32;
        let off2 = off1 + first.len() as u32;
        let mut out = vec![0u8; off2 as usize + second.len()];
        let mut push = |at: usize, v: u32| out[at..at + 4].copy_from_slice(&v.to_be_bytes());
        push(0, 0xcafe_babe);
        push(4, 2);
        push(8, 0x0100_000c);
        push(16, off1);
        push(20, first.len() as u32);
        push(28, 0x0100_0007);
        push(36, off2);
        push(40, second.len() as u32);
        out[off1 as usize..off1 as usize + first.len()].copy_from_slice(first);
        out[off2 as usize..].copy_from_slice(second);
        out
    }

    fn put_le32(file: &mut [u8], at: usize, v: u32) {
        file[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn put_le64(file: &mut [u8], at: usize, v: u64) {
        file[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
}
