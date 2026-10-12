//! Loaders producing a uniform [`Target`] for each supported format.

use crate::le::{self, LeImage};
use crate::{Arch, Error, Format, Result, Section, Symbol, SymbolKind, Target};
use std::path::Path;

/// Load and parse a binary from disk. Fat Mach-O binaries are resolved to
/// the host-compatible slice (first entry as fallback).
pub fn load(path: impl AsRef<Path>) -> Result<Target> {
    let path = path.as_ref();
    let bytes = std::fs::read(path).map_err(Error::Io)?;
    let path_str = path.display().to_string();

    // LE images must be checked before goblin: it mispeeks them as PE.
    if le::is_le(&bytes) {
        return load_le(bytes, path_str);
    }

    match {
        let mut cursor = std::io::Cursor::new(&*bytes);
        goblin::peek(&mut cursor).map_err(|e| Error::Parse(format!("peek failed: {e}")))?
    } {
        goblin::Hint::Mach(_) | goblin::Hint::MachFat(_) => load_macho(bytes, path_str),
        goblin::Hint::Elf(_) => load_elf(bytes, path_str),
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
        bytes,
        page_map: Some(page_map),
    })
}

fn load_macho(bytes: Vec<u8>, path: String) -> Result<Target> {
    match goblin::mach::Mach::parse(&bytes)
        .map_err(|e| Error::Parse(format!("mach-o: {e}")))?
    {
        goblin::mach::Mach::Binary(mo) => macho_target(mo, bytes.clone(), path),
        goblin::mach::Mach::Fat(fat) => {
            // Prefer a slice matching this host's arch; else the first.
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
            let idx = arches
                .iter()
                .position(|a| a.cputype() == host)
                .unwrap_or(0);
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
            sections.push(Section {
                name,
                addr: u64::from(sect.addr),
                size: u64::from(sect.size),
                file_offset: u64::from(sect.offset),
            });
        }
    }

    let mut symbols = Vec::new();
    for (name, nlist) in mo.symbols().flatten() {
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
        symbols.push(Symbol {
            addr: nlist.n_value,
            size: 0,
            name: name.trim_start_matches('_').to_string(),
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
        .enumerate()
        .map(|(i, sh)| Section {
            name: shstr
                .get_at(i)
                .unwrap_or("")
                .to_string(),
            addr: sh.sh_addr,
            size: sh.sh_size,
            file_offset: sh.sh_offset,
        })
        .collect();

    let mut symbols: Vec<Symbol> = elf
        .syms
        .iter()
        .map(|s| Symbol {
            addr: s.st_value,
            size: s.st_size,
            name: elf.strtab.get_at(s.st_name).unwrap_or("").to_string(),
            kind: if s.is_import() {
                SymbolKind::Import
            } else if s.st_shndx != 0 && s.st_name != 0 {
                SymbolKind::Export
            } else {
                SymbolKind::Local
            },
        })
        .collect();
    for dynsym in elf.dynsyms.iter() {
        let name = elf.dynstrtab.get_at(dynsym.st_name).unwrap_or("").to_string();
        if dynsym.is_import()
            && !name.is_empty()
            && !symbols.iter().any(|s| s.name == name)
        {
            symbols.push(Symbol { addr: 0, size: 0, name, kind: SymbolKind::Import });
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
        .map(|s| Section {
            name: String::from_utf8_lossy(&s.name).trim_end_matches('\0').to_string(),
            addr: u64::from(s.virtual_address),
            size: u64::from(s.virtual_size),
            file_offset: u64::from(s.pointer_to_raw_data),
        })
        .collect();

    let mut symbols: Vec<Symbol> = pe
        .exports
        .iter()
        .map(|e| Symbol {
            addr: e.rva as u64,
            size: 0,
            name: e.name.unwrap_or("").to_string(),
            kind: SymbolKind::Export,
        })
        .collect();
    for imp in pe.imports.iter() {
        symbols.push(Symbol {
            addr: 0,
            size: 0,
            name: imp.name.to_string(),
            kind: SymbolKind::Import,
        });
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
