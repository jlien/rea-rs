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
        // `__Z3fooi`; the Itanium spelling is `_Z3fooi`. Strip that one
        // underscore and demangle. A name that is already `_Z…` stays.
        // Other names drop one leading underscore, not every underscore.
        let stripped = raw.strip_prefix('_').unwrap_or(raw.as_str());
        let itanium = if stripped.starts_with("_Z") {
            stripped
        } else if raw.starts_with("_Z") {
            raw.as_str()
        } else {
            ""
        };
        let (stored, demangled) = if itanium.starts_with("_Z") {
            (
                itanium.to_string(),
                crate::demangle::itanium(itanium),
            )
        } else {
            (stripped.to_string(), None)
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
        write_shdr(&mut file, shoff, 1, 1, 1, 6, 0x1000, 0, 0);
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
