//! Interpreter, needed libraries, soname, rpath, runpath, file type, machine,
//! notes, and GNU build-id from an ELF.

use crate::Error;

/// Descriptor cap for rendered notes. Longer descriptors are truncated and the
/// last bytes replaced by `, …`.
const DESC_CAP: usize = 128;

/// One parsed ELF note: the owning name, the type id (named when known), and
/// the descriptor as capped hex.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NoteFact {
    /// Note owner, e.g. `GNU` or `core`. No trailing NUL.
    pub name: String,
    /// `NT_GNU_BUILD_ID` and friends; `0x…` when the table does not know it.
    pub type_: String,
    /// Descriptor hex, at most [`DESC_CAP`] bytes; longer runs end with `, …`.
    pub desc: String,
    /// True when the descriptor was longer than [`DESC_CAP`] bytes.
    pub truncated: bool,
}

/// One GNU property (type, datasz, data) from a `NT_GNU_PROPERTY_TYPE_0` note.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GnuProperty {
    /// `x86 ISA`, `x86 feature 1 (IBT and SHSTK)`, `x86 feature 2 (APX)`,
    /// `needed`, or `0x…` for unknown property types.
    pub type_: String,
    /// Named bit list for the x86 property types; decimal `data` for others.
    pub data: String,
}

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
    /// Notes from PT_NOTE segments and SHT_NOTE sections, in that order.
    pub notes: Vec<NoteFact>,
    /// Decoded properties from `NT_GNU_PROPERTY_TYPE_0` notes.
    pub gnu_properties: Vec<GnuProperty>,
}

/// Parse an ELF image. Failure is `Error::Parse` prefixed with `elf:`.
pub fn facts(bytes: &[u8]) -> crate::Result<ElfFacts> {
    let elf = goblin::elf::Elf::parse(bytes).map_err(|e| Error::Parse(format!("elf: {e}")))?;
    let notes = collect_notes(&elf, bytes);
    let gnu_properties = notes
        .iter()
        .filter(|n| n.type_ == "NT_GNU_PROPERTY_TYPE_0" && n.name == "GNU" && !n.truncated)
        .filter_map(|n| hex_desc(&n.desc).map(|d| (d, n)))
        .flat_map(|(d, _)| parse_gnu_properties(&d))
        .collect();
    Ok(ElfFacts {
        kind: elf_kind(elf.header.e_type),
        machine: elf_machine(elf.header.e_machine),
        interpreter: elf.interpreter.map(str::to_string),
        needed: elf.libraries.iter().map(|lib| (*lib).to_string()).collect(),
        soname: elf.soname.map(str::to_string),
        rpath: elf.rpaths.iter().map(|path| (*path).to_string()).collect(),
        runpath: elf.runpaths.iter().map(|path| (*path).to_string()).collect(),
        build_id: gnu_build_id(&elf, bytes),
        notes,
        gnu_properties,
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

/// Known `n_type` values, split by note owner: ids collide between the GNU
/// table (1..=5) and the core table. The table is owned here; goblin's is
/// partial.
fn note_type_name(owner: &str, ty: u32) -> String {
    let known = if owner == "GNU" {
        match ty {
            1 => "NT_GNU_ABI_TAG",
            2 => "NT_GNU_HWCAP",
            3 => "NT_GNU_BUILD_ID",
            4 => "NT_GNU_GOLD_VERSION",
            5 => "NT_GNU_PROPERTY_TYPE_0",
            _ => return format!("0x{ty:x}"),
        }
    } else {
        match ty {
            0x1 => "NT_PRSTATUS",
            0x2 => "NT_PRFPREG",
            0x3 => "NT_PRPSINFO",
            0x4 => "NT_PRXREG",
            0x6 => "NT_AUXV",
            0x4649_4c45 => "NT_FILE",
            0x5349_4749 => "NT_SIGINFO",
            _ => return format!("0x{ty:x}"),
        }
    };
    known.to_string()
}

/// Notes from PT_NOTE segments first, then SHT_NOTE sections. A note whose
/// bytes do not parse is skipped.
fn collect_notes(elf: &goblin::elf::Elf<'_>, bytes: &[u8]) -> Vec<NoteFact> {
    let mut out = Vec::new();
    let mut push = |iter: Option<goblin::elf::note::NoteIterator<'_>>| {
        let notes = match iter {
            Some(notes) => notes,
            None => return,
        };
        for note in notes {
            let Ok(note) = note else {
                continue;
            };
            let truncated = note.desc.len() > DESC_CAP;
            let desc = note
                .desc
                .iter()
                .take(DESC_CAP)
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join("");
            out.push(NoteFact {
                name: note.name.to_string(),
                type_: note_type_name(note.name, note.n_type),
                desc: if truncated { format!("{desc}, …") } else { desc },
                truncated,
            });
        }
    };
    push(elf.iter_note_headers(bytes));
    push(elf.iter_note_sections(bytes, None));
    out
}

/// Parse a GNU property note descriptor (type u32, datasz u32, data) into
/// readable rows. Unknown property types keep their hex id and raw data words.
fn parse_gnu_properties(desc: &[u8]) -> Vec<GnuProperty> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while desc.len() >= at + 8 {
        let ty = u32::from_le_bytes(desc[at..at + 4].try_into().unwrap());
        let datasz = u32::from_le_bytes(desc[at + 4..at + 8].try_into().unwrap()) as usize;
        let data = desc.get(at + 8..at + 8 + datasz);
        let Some(data) = data else {
            break;
        };
        at += 8 + datasz;
        at += (4 - at % 4) % 4; // properties pad to 4 bytes
        match ty {
            0xc000_8002 => {
                // GNU_PROPERTY_X86_FEATURE_1_AND: IBT (1), SHSTK (2).
                let bits = data.first().copied().unwrap_or(0) as u32
                    | u32::from(data.get(1).copied().unwrap_or(0)) << 8
                    | u32::from(data.get(2).copied().unwrap_or(0)) << 16
                    | u32::from(data.get(3).copied().unwrap_or(0)) << 24;
                let mut names = Vec::new();
                if bits & 1 != 0 {
                    names.push("IBT");
                }
                if bits & 2 != 0 {
                    names.push("SHSTK");
                }
                if !names.is_empty() {
                    out.push(GnuProperty {
                        type_: "x86 feature 1".to_string(),
                        data: names.join(" and "),
                    });
                }
            }
            0xc000_8003 => {
                // GNU_PROPERTY_X86_ISA_1_NEEDED: bit0 baseline, bit1 SSE, bit2 SSE2...
                const ISA: [&str; 9] = [
                    "baseline",
                    "SSE",
                    "SSE2",
                    "SSE3",
                    "SSSE3",
                    "SSE4_1",
                    "SSE4_2",
                    "AVX",
                    "AVX2",
                ];
                let bits = data.first().copied().unwrap_or(0) as u32
                    | u32::from(data.get(1).copied().unwrap_or(0)) << 8
                    | u32::from(data.get(2).copied().unwrap_or(0)) << 16
                    | u32::from(data.get(3).copied().unwrap_or(0)) << 24;
                let names: Vec<&str> = ISA
                    .iter()
                    .enumerate()
                    .filter(|(bit, _)| bits & (1 << bit) != 0)
                    .map(|(_, name)| *name)
                    .collect();
                if !names.is_empty() {
                    out.push(GnuProperty {
                        type_: "x86 ISA needed".to_string(),
                        data: names.join(", "),
                    });
                }
            }
            _ => {
                let words: Vec<String> = data
                    .chunks(4)
                    .map(|word| {
                        let mut raw = [0u8; 4];
                        raw[..word.len()].copy_from_slice(word);
                        format!("0x{:x}", u32::from_le_bytes(raw))
                    })
                    .collect();
                out.push(GnuProperty {
                    type_: format!("0x{ty:x}"),
                    data: words.join(" "),
                });
            }
        }
    }
    out
}

/// The descriptor of a rendered note back to bytes; empty when not hex.
fn hex_desc(desc: &str) -> Option<Vec<u8>> {
    if desc.is_empty() || desc.len() % 2 != 0 {
        return None;
    }
    (0..desc.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&desc[i..i + 2], 16).ok())
        .collect()
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
        assert_eq!(got.notes.len(), 4);
        assert_eq!(got.notes[0].name, "GNU");
        assert_eq!(got.notes[0].type_, "NT_GNU_BUILD_ID");
        assert_eq!(got.notes[0].desc, "01020304");
        assert!(!got.notes[0].truncated);
        assert_eq!(got.notes[1].name, "GNU");
        assert_eq!(got.notes[1].type_, "NT_GNU_PROPERTY_TYPE_0");
        assert_eq!(got.notes[1].desc.len(), 48); // 24 descriptor bytes as hex
        // Unknown types stay numeric, whatever the owner.
        assert_eq!(got.notes[2].name, "core");
        assert_eq!(got.notes[2].type_, "0x1234");
        assert_eq!(got.notes[2].desc, "abcd");
        assert_eq!(got.notes[3].type_, "0x7");
        assert_eq!(got.notes[3].desc.chars().count(), 256 + 3); // 128 bytes plus ", …"
        assert!(got.notes[3].desc.ends_with(", …"));
        assert!(got.notes[3].truncated);
        assert_eq!(
            got.gnu_properties,
            vec![
                GnuProperty {
                    type_: "x86 feature 1".into(),
                    data: "IBT and SHSTK".into()
                },
                GnuProperty {
                    type_: "0xc0000002".into(),
                    data: "0xdeadbeef".into()
                },
            ]
        );
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
        // Build-id note.
        file.extend_from_slice(&4u32.to_le_bytes());
        file.extend_from_slice(&4u32.to_le_bytes());
        file.extend_from_slice(&3u32.to_le_bytes());
        file.extend_from_slice(b"GNU\0");
        file.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        // GNU property note: an x86 feature-1 entry (IBT|SHSTK) followed by an
        // unknown property type that must render as hex.
        let mut prop = Vec::new();
        prop.extend_from_slice(&4u32.to_le_bytes()); // namesz
        prop.extend_from_slice(&24u32.to_le_bytes()); // descsz
        prop.extend_from_slice(&5u32.to_le_bytes()); // NT_GNU_PROPERTY_TYPE_0
        prop.extend_from_slice(b"GNU\0");
        prop.extend_from_slice(&0xc000_8002u32.to_le_bytes()); // x86 feature 1
        prop.extend_from_slice(&4u32.to_le_bytes());
        prop.extend_from_slice(&3u32.to_le_bytes()); // IBT | SHSTK
        prop.extend_from_slice(&0xc000_0002u32.to_le_bytes()); // unknown
        prop.extend_from_slice(&4u32.to_le_bytes());
        prop.extend_from_slice(&0xdead_beefu32.to_le_bytes());
        file.extend_from_slice(&prop);
        let note_sz = (file.len() - note_off) as u64;

        let dyn_off = file.len();
        let dyn_sz = (7 * 16) as u64;
        file.resize(file.len() + dyn_sz as usize, 0);

        let str_off = file.len() as u64;
        file.extend_from_slice(dynstr);

        // An SHT_NOTE section owned by `core`: one unknown type and one whose
        // descriptor exceeds the render cap.
        let note2_off = file.len() as u64;
        let push_note = |file: &mut Vec<u8>, name: &[u8], ty: u32, desc: &[u8]| {
            let start = file.len();
            file.extend_from_slice(&(name.len() as u32 + 1).to_le_bytes());
            file.extend_from_slice(&(desc.len() as u32).to_le_bytes());
            file.extend_from_slice(&ty.to_le_bytes());
            file.extend_from_slice(name);
            file.push(0);
            while (file.len() - start) % 4 != 0 {
                file.push(0);
            }
            file.extend_from_slice(desc);
            while (file.len() - start) % 4 != 0 {
                file.push(0);
            }
        };
        push_note(&mut file, b"core", 0x1234, &[0xab, 0xcd]);
        let big: Vec<u8> = (0..136u32).map(|i| (i % 251) as u8).collect();
        push_note(&mut file, b"core", 0x7, &big);
        let note2_sz = (file.len() as u64 - note2_off) as u64;

        // Section header table: NULL, the note section, a PROGBITS with extra
        // flags, and .shstrtab.
        let shstr = b"\0.note.core\0.progbits\0.shstrtab\0";
        let shstr_off = file.len() as u64;
        file.extend_from_slice(shstr);
        let shoff = file.len() as u64;
        file.resize(file.len() + 4 * 64, 0);

        let write_shdr = |buf: &mut [u8], index: usize, name: u32, ty: u32, flags: u64, off: u64, size: u64, align: u64| {
            let at = shoff as usize + index * 64;
            buf[at..at + 4].copy_from_slice(&name.to_le_bytes());
            buf[at + 4..at + 8].copy_from_slice(&ty.to_le_bytes());
            buf[at + 8..at + 16].copy_from_slice(&flags.to_le_bytes());
            buf[at + 16..at + 24].copy_from_slice(&0u64.to_le_bytes());
            buf[at + 24..at + 32].copy_from_slice(&off.to_le_bytes());
            buf[at + 32..at + 40].copy_from_slice(&size.to_le_bytes());
            buf[at + 48..at + 56].copy_from_slice(&align.to_le_bytes());
        };
        write_shdr(&mut file, 0, 0, 0, 0, 0, 0, 0);
        write_shdr(&mut file, 1, 1, 7, 2, note2_off, note2_sz, 4);
        write_shdr(&mut file, 2, 12, 1, 0x16, 0, 0, 1);
        write_shdr(&mut file, 3, 22, 3, 0, shstr_off, shstr.len() as u64, 1);

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
        file[40..48].copy_from_slice(&shoff.to_le_bytes());
        file[52..54].copy_from_slice(&(EHSZ as u16).to_le_bytes());
        file[54..56].copy_from_slice(&(PHSZ as u16).to_le_bytes());
        file[56..58].copy_from_slice(&(PHNUM as u16).to_le_bytes());
        file[58..60].copy_from_slice(&64u16.to_le_bytes());
        file[60..62].copy_from_slice(&4u16.to_le_bytes());
        file[62..64].copy_from_slice(&3u16.to_le_bytes());

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
