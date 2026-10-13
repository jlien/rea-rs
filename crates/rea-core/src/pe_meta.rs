//! PE data directories, CLR runtime header, CodeView PDB path, and root resource type ids.

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PeDirectory {
    pub name: String,
    pub rva: u32,
    pub size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PeFacts {
    pub directories: Vec<PeDirectory>,
    /// True when the CLR runtime header data directory is present and non-zero.
    pub has_clr: bool,
    /// Parsed CLR header when at least 24 bytes are mapped at its RVA. `None` if the directory is absent or those bytes are missing. A short header does not fail the PE parse.
    pub clr: Option<ClrHeader>,
    /// Root resource-directory type ids (the low 16 bits) when the entry is an integer id. Named entries are skipped. Empty if there is no resource directory.
    pub resource_type_ids: Vec<u32>,
    /// First CodeView PDB 7.0 or 2.0 record in the debug directory. Other debug types are skipped. `None` when the directory is absent, unmapped, or has no CodeView path.
    pub pdb: Option<PePdb>,
}

/// A CodeView PDB filename from the debug directory.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PePdb {
    pub path: String,
    /// PDB 7.0 GUID, `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`. PDB 2.0 has none.
    pub guid: Option<String>,
    pub age: u32,
}

/// Leading `IMAGE_COR20_HEADER` fields, the BSJB version string, and metadata stream headers.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ClrHeader {
    pub major_runtime: u16,
    pub minor_runtime: u16,
    pub metadata_rva: u32,
    pub metadata_size: u32,
    pub flags: u32,
    pub entry_point: u32,
    /// UTF-8 metadata version with trailing NULs removed. `None` when the root is not BSJB or the version bytes are unusable.
    pub version: Option<String>,
    /// Stream headers fully inside the metadata blob and the file, in directory order. Empty when `version` is `None`.
    pub streams: Vec<ClrStream>,
}

/// One metadata stream header. `offset` is relative to the start of the metadata root.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ClrStream {
    pub name: String,
    pub offset: u32,
    pub size: u32,
}

/// Root `IMAGE_RESOURCE_DIRECTORY` type ids.
///
/// `dir` starts at the directory. Named entries are skipped. Integer ids contribute their low 16 bits. Does not recurse.
pub(crate) fn resource_type_ids(dir: &[u8]) -> Result<Vec<u32>> {
    if dir.len() < 16 {
        return Err(Error::Parse("pe: truncated resource directory".into()));
    }
    let named = usize::from(u16::from_le_bytes([dir[12], dir[13]]));
    let ids = usize::from(u16::from_le_bytes([dir[14], dir[15]]));
    let id_at = 16 + named * 8;
    let id_bytes = ids
        .checked_mul(8)
        .ok_or_else(|| Error::Parse("pe: truncated resource directory".into()))?;
    let id_end = id_at
        .checked_add(id_bytes)
        .ok_or_else(|| Error::Parse("pe: truncated resource directory".into()))?;
    if dir.len() < id_end {
        return Err(Error::Parse("pe: truncated resource directory".into()));
    }
    let mut type_ids = Vec::with_capacity(ids);
    for i in 0..ids {
        let at = id_at + i * 8;
        let name_or_id = u32::from_le_bytes([dir[at], dir[at + 1], dir[at + 2], dir[at + 3]]);
        if name_or_id & 0x8000_0000 == 0 {
            type_ids.push(name_or_id & 0xffff);
        }
    }
    Ok(type_ids)
}

fn section_file_offset(
    sections: &[goblin::pe::section_table::SectionTable],
    rva: u32,
) -> Option<usize> {
    let rva = u64::from(rva);
    sections.iter().find_map(|section| {
        if section.pointer_to_raw_data == 0 {
            return None;
        }
        let start = u64::from(section.virtual_address);
        let span = u64::from(section.virtual_size).max(u64::from(section.size_of_raw_data));
        let end = start + span;
        if rva >= start && rva < end {
            usize::try_from(u64::from(section.pointer_to_raw_data) + (rva - start)).ok()
        } else {
            None
        }
    })
}

/// First 24 bytes of `IMAGE_COR20_HEADER`, plus the metadata version and stream headers at `metadata_off`.
///
/// `cb` is not reported. Fewer than 24 header bytes is `None`, not a PE parse error. A bad or oversized version still returns the header with `version: None` and empty `streams`.
fn parse_clr(header: &[u8], file: &[u8], metadata_off: Option<usize>) -> Option<ClrHeader> {
    if header.len() < 24 {
        return None;
    }
    let metadata_size = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);
    let (version, streams) = metadata_version(file, metadata_off, metadata_size);
    Some(ClrHeader {
        major_runtime: u16::from_le_bytes([header[4], header[5]]),
        minor_runtime: u16::from_le_bytes([header[6], header[7]]),
        metadata_rva: u32::from_le_bytes([header[8], header[9], header[10], header[11]]),
        metadata_size,
        flags: u32::from_le_bytes([header[16], header[17], header[18], header[19]]),
        entry_point: u32::from_le_bytes([header[20], header[21], header[22], header[23]]),
        version,
        streams,
    })
}

/// BSJB version string and the stream headers that follow it.
///
/// Caps `version_length` at 256 and rejects lengths past the metadata blob or the file. A bad signature or unusable version yields no streams. Stream headers that run past `metadata_size` or the file are dropped; the version is kept.
fn metadata_version(
    file: &[u8],
    metadata_off: Option<usize>,
    metadata_size: u32,
) -> (Option<String>, Vec<ClrStream>) {
    let Some((version, version_length, off)) = bsjb_version(file, metadata_off, metadata_size)
    else {
        return (None, Vec::new());
    };
    (
        Some(version),
        metadata_streams(file, off, metadata_size, version_length),
    )
}

/// BSJB version string. Caps `version_length` at 256 and rejects lengths past the metadata blob or the file.
fn bsjb_version(
    file: &[u8],
    metadata_off: Option<usize>,
    metadata_size: u32,
) -> Option<(String, u32, usize)> {
    const MAX_VERSION_LEN: u32 = 256;
    const BSJB: u32 = 0x424A_5342;
    let off = metadata_off?;
    let sig = file.get(off..off.checked_add(4)?)?;
    if u32::from_le_bytes([sig[0], sig[1], sig[2], sig[3]]) != BSJB {
        return None;
    }
    let len_at = off.checked_add(12)?;
    let len_bytes = file.get(len_at..len_at.checked_add(4)?)?;
    let version_length =
        u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]);
    if version_length > MAX_VERSION_LEN {
        return None;
    }
    let version_end = 16u32.checked_add(version_length)?;
    if version_end > metadata_size {
        return None;
    }
    let start = off.checked_add(16)?;
    let end = off.checked_add(version_end as usize)?;
    let raw = file.get(start..end)?;
    let version = std::str::from_utf8(raw)
        .ok()?
        .trim_end_matches('\0')
        .to_string();
    Some((version, version_length, off))
}

/// Stream directory after the version bytes.
///
/// Flags sit at `metadata_off + 16 + version_length`. That length already includes padding and is not realigned. At most 16 streams are read. A name is at most 32 bytes including the NUL; a non-UTF-8 name ends the list. An empty name after trim is skipped. Only records whose padded header fits in the metadata blob and the file are returned.
fn metadata_streams(
    file: &[u8],
    metadata_off: usize,
    metadata_size: u32,
    version_length: u32,
) -> Vec<ClrStream> {
    const MAX_STREAMS: usize = 16;
    const MAX_NAME_LEN: usize = 32;

    let Some(blob_end) = metadata_off.checked_add(metadata_size as usize) else {
        return Vec::new();
    };
    let meta_end = blob_end.min(file.len());
    let Some(at) = metadata_off
        .checked_add(16)
        .and_then(|at| at.checked_add(version_length as usize))
    else {
        return Vec::new();
    };
    if at.checked_add(4).map(|end| end > meta_end).unwrap_or(true) {
        return Vec::new();
    }
    // u16 flags, then u16 stream_count. COR20 flags already live on ClrHeader.
    let stream_count =
        usize::from(u16::from_le_bytes([file[at + 2], file[at + 3]])).min(MAX_STREAMS);
    let mut pos = at + 4;
    let mut streams = Vec::with_capacity(stream_count);
    for _ in 0..stream_count {
        if pos.checked_add(8).map(|end| end > meta_end).unwrap_or(true) {
            break;
        }
        let offset = u32::from_le_bytes([file[pos], file[pos + 1], file[pos + 2], file[pos + 3]]);
        let size = u32::from_le_bytes([file[pos + 4], file[pos + 5], file[pos + 6], file[pos + 7]]);
        let name_at = pos + 8;
        let window_len = MAX_NAME_LEN.min(meta_end.saturating_sub(name_at));
        if window_len == 0 {
            break;
        }
        let window = &file[name_at..name_at + window_len];
        let Some(nul_rel) = window.iter().position(|&b| b == 0) else {
            break;
        };
        let Ok(name) = std::str::from_utf8(&window[..nul_rel]) else {
            break;
        };
        let Some(after_nul) = name_at.checked_add(nul_rel).and_then(|p| p.checked_add(1)) else {
            break;
        };
        let Some(rel) = after_nul.checked_sub(metadata_off) else {
            break;
        };
        // Pad so the record ends on a 4-byte boundary from the metadata root.
        let Some(aligned_rel) = rel.checked_add(3).map(|sum| sum & !3) else {
            break;
        };
        let Some(record_end) = metadata_off.checked_add(aligned_rel) else {
            break;
        };
        if record_end > meta_end {
            break;
        }
        pos = record_end;
        if name.trim().is_empty() {
            continue;
        }
        streams.push(ClrStream {
            name: name.to_string(),
            offset,
            size,
        });
    }
    streams
}

pub fn facts(bytes: &[u8]) -> Result<PeFacts> {
    let pe = goblin::pe::PE::parse(bytes).map_err(|e| Error::Parse(format!("pe: {e}")))?;
    let Some(optional) = pe.header.optional_header else {
        return Ok(PeFacts {
            directories: Vec::new(),
            has_clr: false,
            clr: None,
            resource_type_ids: Vec::new(),
            pdb: None,
        });
    };

    let directories = optional
        .data_directories
        .dirs()
        .map(|(ty, dir)| PeDirectory {
            name: format!("{ty:?}"),
            rva: dir.virtual_address,
            size: dir.size,
        })
        .collect();
    let clr_dir = optional.data_directories.get_clr_runtime_header();
    let has_clr = clr_dir.is_some_and(|dir| dir.size != 0 || dir.virtual_address != 0);
    let clr = clr_dir.and_then(|dir| {
        let off = section_file_offset(&pe.sections, dir.virtual_address)?;
        let header = bytes.get(off..)?;
        let metadata_off = header.get(8..12).and_then(|raw| {
            let rva = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
            section_file_offset(&pe.sections, rva)
        });
        parse_clr(header, bytes, metadata_off)
    });
    let resource_type_ids = if let Some(dir) = optional.data_directories.get_resource_table() {
        let off = section_file_offset(&pe.sections, dir.virtual_address).ok_or_else(|| {
            Error::Parse(format!(
                "pe: resource directory RVA {:#x} is not in a section",
                dir.virtual_address
            ))
        })?;
        let blob = bytes
            .get(off..)
            .ok_or_else(|| Error::Parse("pe: truncated resource directory".into()))?;
        resource_type_ids(blob)?
    } else {
        Vec::new()
    };
    let pdb = optional.data_directories.get_debug_table().and_then(|dir| {
        if dir.size == 0 {
            return None;
        }
        let off = section_file_offset(&pe.sections, dir.virtual_address)?;
        codeview_pdb(bytes, off, dir.size)
    });

    Ok(PeFacts {
        directories,
        has_clr,
        clr,
        resource_type_ids,
        pdb,
    })
}

const DEBUG_ENTRY: usize = 28;
const DEBUG_CODEVIEW: u32 = 2;
const CODEVIEW_RSDS: u32 = 0x5344_5352;
const CODEVIEW_NB10: u32 = 0x3031_424e;

/// Walk up to 16 debug-directory entries. A short entry ends the walk. A CodeView record that does not fit is skipped.
fn codeview_pdb(bytes: &[u8], dir_off: usize, dir_size: u32) -> Option<PePdb> {
    let count = (dir_size as usize / DEBUG_ENTRY).min(16);
    for i in 0..count {
        let at = dir_off + i * DEBUG_ENTRY;
        let Some(entry) = bytes.get(at..at + DEBUG_ENTRY) else {
            break;
        };
        let data_type = u32::from_le_bytes(entry[12..16].try_into().unwrap());
        if data_type != DEBUG_CODEVIEW {
            continue;
        }
        let size_of_data = u32::from_le_bytes(entry[16..20].try_into().unwrap()) as usize;
        let raw = u32::from_le_bytes(entry[24..28].try_into().unwrap()) as usize;
        if let Some(pdb) = read_codeview(bytes, raw, size_of_data) {
            return Some(pdb);
        }
    }
    None
}

fn read_codeview(bytes: &[u8], raw: usize, size_of_data: usize) -> Option<PePdb> {
    let magic = u32::from_le_bytes(bytes.get(raw..raw + 4)?.try_into().ok()?);
    if magic == CODEVIEW_RSDS {
        if size_of_data < 24 {
            return None;
        }
        let guid = bytes.get(raw + 4..raw + 20)?;
        let age = u32::from_le_bytes(bytes.get(raw + 20..raw + 24)?.try_into().ok()?);
        let name = bytes.get(raw + 24..raw + size_of_data)?;
        return Some(PePdb {
            path: c_string(name),
            guid: Some(guid_string(guid)),
            age,
        });
    }
    if magic == CODEVIEW_NB10 {
        if size_of_data < 16 {
            return None;
        }
        let age = u32::from_le_bytes(bytes.get(raw + 12..raw + 16)?.try_into().ok()?);
        let name = bytes.get(raw + 16..raw + size_of_data)?;
        return Some(PePdb {
            path: c_string(name),
            guid: None,
            age,
        });
    }
    None
}

fn c_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// PDB 7.0 GUID. The first three fields are little-endian. The last eight bytes are raw.
fn guid_string(b: &[u8]) -> String {
    let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let d2 = u16::from_le_bytes([b[4], b[5]]);
    let d3 = u16::from_le_bytes([b[6], b[7]]);
    format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_id_entries() {
        let mut dir = vec![0u8; 16];
        dir[14] = 2;
        dir.extend_from_slice(&3u32.to_le_bytes());
        dir.extend_from_slice(&0u32.to_le_bytes());
        dir.extend_from_slice(&16u32.to_le_bytes());
        dir.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(resource_type_ids(&dir).unwrap(), vec![3, 16]);
    }

    #[test]
    fn skips_named_entries_and_string_ids() {
        let mut dir = vec![0u8; 16];
        dir[12] = 1; // one named entry
        dir[14] = 2; // two id entries; the second has the name bit set
        dir.extend_from_slice(&0x8000_0001u32.to_le_bytes());
        dir.extend_from_slice(&0u32.to_le_bytes());
        dir.extend_from_slice(&3u32.to_le_bytes());
        dir.extend_from_slice(&0u32.to_le_bytes());
        dir.extend_from_slice(&0x8000_0010u32.to_le_bytes());
        dir.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(resource_type_ids(&dir).unwrap(), vec![3]);
    }

    #[test]
    fn truncated_directory_is_parse_error() {
        let err = resource_type_ids(&[0u8; 15]).unwrap_err();
        assert!(matches!(err, Error::Parse(_)));
    }

    #[test]
    fn rejects_non_pe() {
        assert!(facts(b"not a pe").is_err());
    }

    fn push_debug_entry(buf: &mut Vec<u8>, data_type: u32, size_of_data: u32, raw: u32) {
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&data_type.to_le_bytes());
        buf.extend_from_slice(&size_of_data.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&raw.to_le_bytes());
    }

    #[test]
    fn codeview_rsds_after_another_debug_type() {
        let path = b"hello.pdb\0";
        let mut cv = Vec::new();
        cv.extend_from_slice(&CODEVIEW_RSDS.to_le_bytes());
        cv.extend_from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]);
        cv.extend_from_slice(&2u32.to_le_bytes());
        cv.extend_from_slice(path);
        let mut bytes = Vec::new();
        push_debug_entry(&mut bytes, 1, 0, 0);
        let raw = (DEBUG_ENTRY * 2) as u32;
        push_debug_entry(&mut bytes, DEBUG_CODEVIEW, cv.len() as u32, raw);
        bytes.extend_from_slice(&cv);
        let got = codeview_pdb(&bytes, 0, (DEBUG_ENTRY * 2) as u32).unwrap();
        assert_eq!(got.path, "hello.pdb");
        assert_eq!(
            got.guid.as_deref(),
            Some("04030201-0605-0807-090a-0b0c0d0e0f10")
        );
        assert_eq!(got.age, 2);
    }

    #[test]
    fn codeview_nb10_has_no_guid() {
        let mut cv = Vec::new();
        cv.extend_from_slice(&CODEVIEW_NB10.to_le_bytes());
        cv.extend_from_slice(&0u32.to_le_bytes());
        cv.extend_from_slice(&0u32.to_le_bytes());
        cv.extend_from_slice(&4u32.to_le_bytes());
        cv.extend_from_slice(b"old.pdb\0");
        let mut bytes = Vec::new();
        push_debug_entry(&mut bytes, DEBUG_CODEVIEW, cv.len() as u32, DEBUG_ENTRY as u32);
        bytes.extend_from_slice(&cv);
        let got = codeview_pdb(&bytes, 0, DEBUG_ENTRY as u32).unwrap();
        assert_eq!(got.path, "old.pdb");
        assert_eq!(got.guid, None);
        assert_eq!(got.age, 4);
    }

    #[test]
    fn codeview_missing_when_record_does_not_fit() {
        let mut bytes = Vec::new();
        push_debug_entry(&mut bytes, DEBUG_CODEVIEW, 24, 1000);
        assert!(codeview_pdb(&bytes, 0, DEBUG_ENTRY as u32).is_none());
        assert!(codeview_pdb(&bytes, 0, 10).is_none());
    }

    fn cor20_header(
        major: u16,
        minor: u16,
        metadata_rva: u32,
        metadata_size: u32,
        flags: u32,
        entry_point: u32,
    ) -> [u8; 24] {
        let mut header = [0u8; 24];
        header[0..4].copy_from_slice(&72u32.to_le_bytes());
        header[4..6].copy_from_slice(&major.to_le_bytes());
        header[6..8].copy_from_slice(&minor.to_le_bytes());
        header[8..12].copy_from_slice(&metadata_rva.to_le_bytes());
        header[12..16].copy_from_slice(&metadata_size.to_le_bytes());
        header[16..20].copy_from_slice(&flags.to_le_bytes());
        header[20..24].copy_from_slice(&entry_point.to_le_bytes());
        header
    }

    fn metadata_root(version: &[u8]) -> Vec<u8> {
        let mut root = Vec::new();
        root.extend_from_slice(&0x424A_5342u32.to_le_bytes());
        root.extend_from_slice(&1u16.to_le_bytes());
        root.extend_from_slice(&1u16.to_le_bytes());
        root.extend_from_slice(&0u32.to_le_bytes());
        root.extend_from_slice(&u32::try_from(version.len()).unwrap().to_le_bytes());
        root.extend_from_slice(version);
        root
    }

    /// NUL-terminated name, then extra NULs so the record ends on a 4-byte boundary of `meta`.
    fn append_stream(meta: &mut Vec<u8>, offset: u32, size: u32, name: &str) {
        meta.extend_from_slice(&offset.to_le_bytes());
        meta.extend_from_slice(&size.to_le_bytes());
        meta.extend_from_slice(name.as_bytes());
        meta.push(0);
        while meta.len() % 4 != 0 {
            meta.push(0);
        }
    }

    #[test]
    fn clr_reads_runtime_and_version() {
        let header = cor20_header(2, 5, 0x2000, 0x100, 1, 0x0600_0001);
        let mut meta = metadata_root(b"v4.0.30319\0\0");
        meta.extend_from_slice(&0u16.to_le_bytes());
        meta.extend_from_slice(&2u16.to_le_bytes());
        append_stream(&mut meta, 0x6c, 0x10, "#~");
        append_stream(&mut meta, 0x80, 0x20, "#Strings");
        let metadata_off = 32;
        let mut file = vec![0u8; metadata_off];
        file.extend_from_slice(&meta);
        let got = parse_clr(&header, &file, Some(metadata_off)).unwrap();
        assert_eq!(got.major_runtime, 2);
        assert_eq!(got.minor_runtime, 5);
        assert_eq!(got.metadata_rva, 0x2000);
        assert_eq!(got.metadata_size, 0x100);
        assert_eq!(got.flags, 1);
        assert_eq!(got.entry_point, 0x0600_0001);
        assert_eq!(got.version.as_deref(), Some("v4.0.30319"));
        assert_eq!(
            got.streams,
            vec![
                ClrStream {
                    name: "#~".to_string(),
                    offset: 0x6c,
                    size: 0x10,
                },
                ClrStream {
                    name: "#Strings".to_string(),
                    offset: 0x80,
                    size: 0x20,
                },
            ]
        );
    }

    #[test]
    fn clr_bad_signature_keeps_runtime_version() {
        let header = cor20_header(2, 5, 0x2000, 0x100, 1, 0x0600_0001);
        let mut meta = metadata_root(b"v4.0.30319\0\0");
        meta[0..4].copy_from_slice(b"XXXX");
        let got = parse_clr(&header, &meta, Some(0)).unwrap();
        assert!(got.version.is_none());
        assert!(got.streams.is_empty());
        assert_eq!(got.major_runtime, 2);
        assert_eq!(got.minor_runtime, 5);
    }

    #[test]
    fn clr_stream_count_past_buffer_keeps_version() {
        let header = cor20_header(2, 5, 0x2000, 0x100, 1, 0x0600_0001);
        let mut meta = metadata_root(b"v4.0.30319\0\0");
        meta.extend_from_slice(&0u16.to_le_bytes());
        meta.extend_from_slice(&50u16.to_le_bytes());
        let got = parse_clr(&header, &meta, Some(0)).unwrap();
        assert_eq!(got.version.as_deref(), Some("v4.0.30319"));
        assert!(got.streams.is_empty());

        let mut partial = metadata_root(b"v4.0.30319\0\0");
        partial.extend_from_slice(&0u16.to_le_bytes());
        partial.extend_from_slice(&2u16.to_le_bytes());
        append_stream(&mut partial, 0x6c, 0x10, "#~");
        partial.extend_from_slice(&0x80u32.to_le_bytes());
        let got = parse_clr(&header, &partial, Some(0)).unwrap();
        assert_eq!(got.version.as_deref(), Some("v4.0.30319"));
        assert_eq!(got.streams.len(), 1);
        assert_eq!(got.streams[0].name, "#~");
        assert_eq!(got.streams[0].offset, 0x6c);
        assert_eq!(got.streams[0].size, 0x10);

        let mut full = metadata_root(b"v4.0.30319\0\0");
        full.extend_from_slice(&0u16.to_le_bytes());
        full.extend_from_slice(&1u16.to_le_bytes());
        append_stream(&mut full, 0x6c, 0x10, "#~");
        let short_blob = cor20_header(2, 5, 0x2000, 32, 1, 0x0600_0001);
        let got = parse_clr(&short_blob, &full, Some(0)).unwrap();
        assert_eq!(got.version.as_deref(), Some("v4.0.30319"));
        assert!(got.streams.is_empty());
    }

    #[test]
    fn clr_stream_names_skip_empty_and_stop() {
        let header = cor20_header(2, 5, 0x2000, 0x200, 1, 1);
        let mut meta = metadata_root(b"v4.0.30319\0\0");
        meta.extend_from_slice(&0u16.to_le_bytes());
        meta.extend_from_slice(&3u16.to_le_bytes());
        append_stream(&mut meta, 0x6c, 0x10, "#~");
        append_stream(&mut meta, 1, 1, "");
        append_stream(&mut meta, 0x80, 0x20, "#Strings");
        let got = parse_clr(&header, &meta, Some(0)).unwrap();
        assert_eq!(
            got.streams
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>(),
            vec!["#~", "#Strings"]
        );

        let mut bad = metadata_root(b"v4.0.30319\0\0");
        bad.extend_from_slice(&0u16.to_le_bytes());
        bad.extend_from_slice(&3u16.to_le_bytes());
        append_stream(&mut bad, 0x6c, 0x10, "#~");
        bad.extend_from_slice(&2u32.to_le_bytes());
        bad.extend_from_slice(&2u32.to_le_bytes());
        bad.extend_from_slice(&[0xff, 0xfe, 0x00]);
        while bad.len() % 4 != 0 {
            bad.push(0);
        }
        append_stream(&mut bad, 0x80, 0x20, "#Strings");
        let got = parse_clr(&header, &bad, Some(0)).unwrap();
        assert_eq!(got.version.as_deref(), Some("v4.0.30319"));
        assert_eq!(got.streams.len(), 1);
        assert_eq!(got.streams[0].name, "#~");

        let mut capped = metadata_root(b"v4");
        capped.extend_from_slice(&0u16.to_le_bytes());
        capped.extend_from_slice(&2u16.to_le_bytes());
        append_stream(&mut capped, 0x6c, 0x10, "#~");
        append_stream(&mut capped, 0x80, 0x20, "#Strings");
        let got = parse_clr(&header, &capped, Some(0)).unwrap();
        assert_eq!(got.version.as_deref(), Some("v4"));
        assert_eq!(
            got.streams
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>(),
            vec!["#~", "#Strings"]
        );

        let mut many = metadata_root(b"v4.0.30319\0\0");
        many.extend_from_slice(&0u16.to_le_bytes());
        many.extend_from_slice(&17u16.to_le_bytes());
        for i in 0..17 {
            append_stream(&mut many, i, 1, &format!("s{i}"));
        }
        let got = parse_clr(&header, &many, Some(0)).unwrap();
        assert_eq!(got.streams.len(), 16);
        assert_eq!(got.streams[15].name, "s15");

        let mut long = metadata_root(b"v4.0.30319\0\0");
        long.extend_from_slice(&0u16.to_le_bytes());
        long.extend_from_slice(&3u16.to_le_bytes());
        append_stream(&mut long, 0x6c, 0x10, &"a".repeat(31));
        long.extend_from_slice(&1u32.to_le_bytes());
        long.extend_from_slice(&1u32.to_le_bytes());
        long.extend(std::iter::repeat(b'b').take(32));
        append_stream(&mut long, 0x80, 0x20, "#Strings");
        let got = parse_clr(&header, &long, Some(0)).unwrap();
        assert_eq!(got.streams.len(), 1);
        assert_eq!(got.streams[0].name, "a".repeat(31));
    }

    #[test]
    fn clr_short_header_is_none() {
        assert!(parse_clr(&[0u8; 23], b"", None).is_none());
    }

    #[test]
    fn clr_version_none_when_unusable() {
        let header = cor20_header(2, 5, 0x2000, 0x100, 1, 0x0600_0001);
        let unmapped = parse_clr(&header, b"", None).unwrap();
        assert!(unmapped.version.is_none());
        assert_eq!(unmapped.entry_point, 0x0600_0001);

        let meta = metadata_root(b"v4.0.30319\0\0");
        let exact = cor20_header(2, 5, 0x2000, 28, 1, 0x0600_0001);
        assert_eq!(
            parse_clr(&exact, &meta, Some(0))
                .unwrap()
                .version
                .as_deref(),
            Some("v4.0.30319")
        );
        let one_short = cor20_header(2, 5, 0x2000, 27, 1, 0x0600_0001);
        assert!(parse_clr(&one_short, &meta, Some(0))
            .unwrap()
            .version
            .is_none());

        assert!(parse_clr(&header, &meta[..16], Some(0))
            .unwrap()
            .version
            .is_none());
        assert!(parse_clr(&header, &metadata_root(&[0xff, 0xfe]), Some(0))
            .unwrap()
            .version
            .is_none());

        let mut over = vec![0u8; 16 + 257];
        over[0..4].copy_from_slice(&0x424A_5342u32.to_le_bytes());
        over[12..16].copy_from_slice(&257u32.to_le_bytes());
        over[16..].fill(b'a');
        let big = cor20_header(2, 5, 0x2000, 16 + 257, 1, 1);
        assert!(parse_clr(&big, &over, Some(0)).unwrap().version.is_none());
    }
}
