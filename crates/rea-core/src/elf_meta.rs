//! Interpreter, needed libraries, soname, rpath, runpath, file type, machine, and GNU build-id from an ELF.

use crate::Error;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ElfFacts {
    /// `rel`, `exec`, `dyn`, `core`, or `type-{n}`.
    pub kind: String,
    /// `x86`, `x86_64`, `arm`, `aarch64`, or `machine-{n}`.
    pub machine: String,
    pub interpreter: Option<String>,
    pub needed: Vec<String>,
    pub soname: Option<String>,
    /// `DT_RPATH` strings. The paths are not searched.
    pub rpath: Vec<String>,
    /// `DT_RUNPATH` strings. The paths are not searched.
    pub runpath: Vec<String>,
    pub build_id: Option<String>, // lowercase hex of the note desc, no dashes
}

/// Parse an ELF image. Failure is `Error::Parse` prefixed with `elf:`.
pub fn facts(bytes: &[u8]) -> crate::Result<ElfFacts> {
    let elf = goblin::elf::Elf::parse(bytes).map_err(|e| Error::Parse(format!("elf: {e}")))?;
    Ok(ElfFacts {
        kind: elf_kind(elf.header.e_type),
        machine: elf_machine(elf.header.e_machine),
        interpreter: elf.interpreter.map(str::to_string),
        needed: elf.libraries.iter().map(|lib| (*lib).to_string()).collect(),
        soname: elf.soname.map(str::to_string),
        rpath: elf.rpaths.iter().map(|path| (*path).to_string()).collect(),
        runpath: elf.runpaths.iter().map(|path| (*path).to_string()).collect(),
        build_id: gnu_build_id(&elf, bytes),
    })
}

fn elf_kind(kind: u16) -> String {
    match kind {
        1 => "rel".to_string(),
        2 => "exec".to_string(),
        3 => "dyn".to_string(),
        4 => "core".to_string(),
        n => format!("type-{n}"),
    }
}

fn elf_machine(machine: u16) -> String {
    match machine {
        3 => "x86".to_string(),
        40 => "arm".to_string(),
        62 => "x86_64".to_string(),
        183 => "aarch64".to_string(),
        n => format!("machine-{n}"),
    }
}

fn gnu_build_id(elf: &goblin::elf::Elf<'_>, bytes: &[u8]) -> Option<String> {
    let notes = elf.iter_note_headers(bytes)?;
    for note in notes {
        let Ok(note) = note else {
            continue;
        };
        if note.n_type == goblin::elf::note::NT_GNU_BUILD_ID && note.name == "GNU" {
            return Some(note.desc.iter().map(|byte| format!("{byte:02x}")).collect());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_elf() {
        let err = facts(b"not an elf").unwrap_err();
        assert!(matches!(err, Error::Parse(_)));
    }

    #[test]
    fn reads_interpreter_needed_and_build_id() {
        let bytes = elf64_fixture();
        let got = facts(&bytes).unwrap();
        assert_eq!(
            got.interpreter.as_deref(),
            Some("/lib64/ld-linux-x86-64.so.2")
        );
        assert_eq!(got.needed, vec!["libc.so.6".to_string()]);
        assert_eq!(got.soname.as_deref(), Some("libexample.so"));
        assert_eq!(got.kind, "dyn");
        assert_eq!(got.machine, "x86_64");
        assert_eq!(got.rpath, vec!["/opt/rpath".to_string()]);
        assert_eq!(got.runpath, vec!["/opt/run".to_string()]);
        assert_eq!(got.build_id.as_deref(), Some("01020304"));
    }

    /// ELF64 with PT_INTERP, a GNU build-id PT_NOTE, and a PT_DYNAMIC that
    /// carries DT_NEEDED / DT_SONAME. PT_LOAD uses `p_vaddr == p_offset` so
    /// goblin can translate `DT_STRTAB`.
    fn elf64_fixture() -> Vec<u8> {
        const ET_DYN: u16 = 3;
        const EM_X86_64: u16 = 62;
        const PT_LOAD: u32 = 1;
        const PT_DYNAMIC: u32 = 2;
        const PT_INTERP: u32 = 3;
        const PT_NOTE: u32 = 4;
        const DT_NULL: u64 = 0;
        const DT_NEEDED: u64 = 1;
        const DT_STRTAB: u64 = 5;
        const DT_STRSZ: u64 = 10;
        const DT_SONAME: u64 = 14;
        const DT_RPATH: u64 = 15;
        const DT_RUNPATH: u64 = 29;
        const PHNUM: usize = 4;
        const EHSZ: usize = 64;
        const PHSZ: usize = 56;

        let interp = b"/lib64/ld-linux-x86-64.so.2\0";
        // Leading NUL keeps DT_NEEDED and DT_SONAME off offset 0 (goblin treats soname 0 as absent).
        let dynstr = b"\0libc.so.6\0libexample.so\0/opt/rpath\0/opt/run\0";
        let needed_off = 1u64;
        let soname_off = (1 + b"libc.so.6\0".len()) as u64;
        let rpath_off = soname_off + b"libexample.so\0".len() as u64;
        let runpath_off = rpath_off + b"/opt/rpath\0".len() as u64;

        let mut file = vec![0u8; EHSZ + PHNUM * PHSZ];

        let interp_off = file.len();
        file.extend_from_slice(interp);

        let note_off = file.len();
        // Nhdr32 even for ELF64: goblin decodes align 4/8 notes as three u32s.
        file.extend_from_slice(&4u32.to_le_bytes());
        file.extend_from_slice(&4u32.to_le_bytes());
        file.extend_from_slice(&3u32.to_le_bytes());
        file.extend_from_slice(b"GNU\0");
        file.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        let note_sz = (file.len() - note_off) as u64;

        let dyn_off = file.len();
        let dyn_sz = (7 * 16) as u64;
        file.resize(file.len() + dyn_sz as usize, 0);

        let str_off = file.len() as u64;
        file.extend_from_slice(dynstr);

        let dyns = [
            (DT_NEEDED, needed_off),
            (DT_STRTAB, str_off),
            (DT_STRSZ, dynstr.len() as u64),
            (DT_SONAME, soname_off),
            (DT_RPATH, rpath_off),
            (DT_RUNPATH, runpath_off),
            (DT_NULL, 0),
        ];
        for (i, (tag, val)) in dyns.iter().enumerate() {
            let at = dyn_off + i * 16;
            file[at..at + 8].copy_from_slice(&tag.to_le_bytes());
            file[at + 8..at + 16].copy_from_slice(&val.to_le_bytes());
        }

        file[0..4].copy_from_slice(b"\x7fELF");
        file[4] = 2;
        file[5] = 1;
        file[6] = 1;
        file[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        file[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        file[20..24].copy_from_slice(&1u32.to_le_bytes());
        file[32..40].copy_from_slice(&(EHSZ as u64).to_le_bytes());
        file[52..54].copy_from_slice(&(EHSZ as u16).to_le_bytes());
        file[54..56].copy_from_slice(&(PHSZ as u16).to_le_bytes());
        file[56..58].copy_from_slice(&(PHNUM as u16).to_le_bytes());

        let file_len = file.len() as u64;
        write_phdr(
            &mut file,
            0,
            PT_INTERP,
            interp_off as u64,
            interp.len() as u64,
            1,
        );
        write_phdr(&mut file, 1, PT_NOTE, note_off as u64, note_sz, 4);
        write_phdr(&mut file, 2, PT_DYNAMIC, dyn_off as u64, dyn_sz, 8);
        write_phdr(&mut file, 3, PT_LOAD, 0, file_len, 1);
        file
    }

    fn write_phdr(buf: &mut [u8], index: usize, ty: u32, off: u64, filesz: u64, align: u64) {
        const PF_R: u32 = 4;
        let at = 64 + index * 56;
        buf[at..at + 4].copy_from_slice(&ty.to_le_bytes());
        buf[at + 4..at + 8].copy_from_slice(&PF_R.to_le_bytes());
        buf[at + 8..at + 16].copy_from_slice(&off.to_le_bytes());
        buf[at + 16..at + 24].copy_from_slice(&off.to_le_bytes());
        buf[at + 24..at + 32].copy_from_slice(&off.to_le_bytes());
        buf[at + 32..at + 40].copy_from_slice(&filesz.to_le_bytes());
        buf[at + 40..at + 48].copy_from_slice(&filesz.to_le_bytes());
        buf[at + 48..at + 56].copy_from_slice(&align.to_le_bytes());
    }
}
