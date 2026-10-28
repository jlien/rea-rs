//! PE data directories, subsystem, image base, COFF timestamp, CLR runtime header, CodeView PDB path, and resource type, name, language, and data-entry size.

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PeDirectory {
    pub name: String,
    pub rva: u32,
    pub size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PeFacts {
    /// COFF `TimeDateStamp`, seconds since the Unix epoch.
    pub timestamp: u32,
    /// `timestamp` as `YYYY-MM-DDTHH:MM:SSZ`. Year 1970 when the stamp is zero.
    pub timestamp_utc: String,
    /// `windows-gui`, `windows-cui`, or `subsystem-{n}`. `None` when the optional header is absent.
    pub subsystem: Option<String>,
    /// Optional-header image base. `None` when the optional header is absent.
    pub image_base: Option<u64>,
    pub directories: Vec<PeDirectory>,
    /// True when the CLR runtime header data directory is present and non-zero.
    pub has_clr: bool,
    /// Parsed CLR header when at least 24 bytes are mapped at its RVA. `None` if the directory is absent or those bytes are missing. A short header does not fail the PE parse.
    pub clr: Option<ClrHeader>,
    /// Root resource-directory type ids (the low 16 bits) when the entry is an integer id. Named entries are skipped. Empty if there is no resource directory.
    pub resource_type_ids: Vec<u32>,
    /// Resource directory through the data-entry header and, when the RVA is mapped, the payload bytes.
    pub resources: Vec<PeResource>,
    /// First CodeView PDB 7.0 or 2.0 record in the debug directory. Other debug types are skipped. `None` when the directory is absent, unmapped, or has no CodeView path.
    pub pdb: Option<PePdb>,
    /// Bytes past the last section's raw data. `None` when the file ends on that boundary or has no raw section.
    pub overlay: Option<crate::Overlay>,
}

/// One resource type, the names under it, and the language id under each name.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PeResource {
    /// Integer type id as a decimal string, or the UTF-16 name when the root entry is named.
    pub ty: String,
    /// Name level. Integer ids are decimal strings. Named entries are UTF-16.
    pub names: Vec<PeResourceName>,
}

/// One resource name and the language entries under it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PeResourceName {
    /// Integer id as a decimal string, or the UTF-16 name.
    pub name: String,
    /// Language level. Each entry may carry a data-entry size and code page.
    pub languages: Vec<PeResourceLang>,
}

/// One language id and the `IMAGE_RESOURCE_DATA_ENTRY` header under it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PeResourceLang {
    /// Integer id as a decimal string, or the UTF-16 name.
    pub lang: String,
    /// `Size` from the data entry. `None` when this level is not a data entry.
    pub size: Option<u32>,
    /// `CodePage` from the data entry. `None` when this level is not a data entry.
    pub code_page: Option<u32>,
    /// Payload bytes at `OffsetToData`, limited to `size`. `None` when the RVA is not mapped or the bytes do not fit. A missing payload does not fail the PE parse.
    pub payload: Option<Vec<u8>>,
}

/// A CodeView PDB filename from the debug directory.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PePdb {
    pub path: String,
    /// PDB 7.0 GUID, `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`. PDB 2.0 has none.
    pub guid: Option<String>,
    pub age: u32,
}

/// Leading `IMAGE_COR20_HEADER` fields, the BSJB version string, metadata stream headers, table row counts, and type, field, method, parameter, member-ref, module-ref, and assembly names, plus each member-ref's resolved parent.
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
    /// Row counts from the `#~` stream, or `#-` when `#~` is absent. Empty when that stream is missing or shorter than its header.
    pub tables: Vec<ClrTable>,
    /// Names from `Module`, `TypeRef`, and `TypeDef`, with `Field` and `MethodDef` names on each `TypeDef` and `Param` names on each method.
    pub types: Vec<ClrType>,
    /// `MemberRef` names, in table order. Empty when that table or the string heap is missing.
    pub member_refs: Vec<String>,
    /// Method or field signature for each `member_refs` entry. `None` when the blob is missing or does not fit.
    pub member_ref_signatures: Vec<Option<String>>,
    /// One element text per `TypeSpec` row — what `sig_type` returns for that row's blob payload: a primitive, `ptr`, `byref`, `szarray`, or `class` / `valuetype` with a coded index. Blob index 0, or a blob `sig_type` rejects, is `None`.
    pub typespec_signatures: Vec<Option<String>>,
    /// One text per `StandAloneSig` row — what `method_sig` returns for that row's blob: a `field` signature or a `ret(params)` method signature. Blob index 0, or a blob `method_sig` rejects, is `None`.
    pub standalone_sigs: Vec<Option<String>>,
    /// Resolved `MemberRefParent` for each `member_refs` entry. TypeDef and TypeRef parents become names when that row is in the name lists; `ModuleRef`, `MethodDef`, and `TypeSpec` stay as `ModuleRef#N`, `MethodDef#N`, and `TypeSpec#N`. Empty when the parent row does not fit.
    pub member_ref_parents: Vec<String>,
    /// One `ClrAssembly` per `Assembly` row, in table order.
    pub assemblies: Vec<ClrAssembly>,
    /// One `ClrAssembly` per `AssemblyRef` row, in table order.
    pub assembly_refs: Vec<ClrAssembly>,
    /// `ModuleRef` names, in table order.
    pub module_refs: Vec<String>,
    /// One `ClrConstant` per `Constant` row, in table order. Empty when the table is absent or a row does not fit.
    pub constants: Vec<ClrConstant>,
}

/// A metadata blob: its byte length plus hex of at most the first 32 bytes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ClrBlob {
    /// Full byte length of the blob.
    pub len: usize,
    /// Lowercase hex of the first 32 bytes.
    pub hex: String,
}

/// One `Constant` row: the element-type name, the `HasConstant` parent, and the value blob. The value is not evaluated.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ClrConstant {
    /// The element-type byte as `sig_type` names that tag (`int32`, `string`, and the rest of its match). A tag the single byte cannot name stays empty.
    pub kind: String,
    /// `Field#N`, `Param#N`, or `Property#N` from the `HasConstant` coded index. Any other tag stays empty.
    pub parent: String,
    /// The value blob: length plus hex of at most the first 32 bytes. `None` for blob index 0 or a blob that does not fit.
    pub value: Option<ClrBlob>,
}

/// Version numbers, name, culture, public-key blob, hash-algorithm id, flags word, and hash-value blob from one `Assembly` or `AssemblyRef` row.
///
/// On `Assembly` the blob is the public key and the hash-algorithm id is present; on `AssemblyRef` it is the public-key-or-token, the hash-value blob is present, and the hash-algorithm id is not. No strong-name check runs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ClrAssembly {
    pub major_version: u16,
    pub minor_version: u16,
    pub build_number: u16,
    pub revision_number: u16,
    /// Assembly name.
    pub name: String,
    /// Culture string. Empty when absent.
    pub culture: String,
    /// Blob length plus hex of at most the first 32 bytes. `None` when the blob index is 0 or the blob does not fit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<ClrBlob>,
    /// Hash-algorithm id from an `Assembly` row, as stored. Absent on `AssemblyRef`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_alg_id: Option<u32>,
    /// Flags word, as stored.
    pub flags: u32,
    /// `HashValue` blob from an `AssemblyRef` row: length plus hex of at most the first 32 bytes. `None` on `Assembly`, or when the blob index is 0 or the blob does not fit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_value: Option<ClrBlob>,
}

/// A type or module name from the metadata tables.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ClrType {
    /// `Module`, `TypeRef`, or `TypeDef`.
    pub table: String,
    pub namespace: String,
    pub name: String,
    /// `Field` rows owned by a `TypeDef`, in table order. Empty for `Module` and `TypeRef`.
    pub fields: Vec<ClrField>,
    /// `MethodDef` rows owned by a `TypeDef`, in table order. Empty for `Module` and `TypeRef`.
    pub methods: Vec<ClrMethod>,
    /// `Property` rows owned by a `TypeDef`. Empty when `PropertyMap` is absent.
    pub properties: Vec<ClrProperty>,
    /// `Event` rows owned by a `TypeDef`. Empty when `EventMap` is absent.
    pub events: Vec<ClrEvent>,
    /// Names of the interfaces a `TypeDef` implements, resolved where the `InterfaceImpl` target row exists. Empty for `Module` and `TypeRef`.
    pub interfaces: Vec<String>,
}

/// A field name and its decoded signature.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ClrField {
    pub name: String,
    /// Field signature such as `field int32`. `None` when the blob index is 0 or the blob does not fit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// A method name and the `Param` rows it owns.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ClrMethod {
    pub name: String,
    /// `Param` names in table order, each with its sequence number.
    pub params: Vec<ClrParam>,
    /// Method signature such as `void(int32)`. `None` when the blob index is 0 or the blob does not fit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// IL opcode names. Empty when the RVA is 0 or the body does not fit. At most 48 instructions. A `call`, `callvirt`, or `newobj` token in the MethodDef (`0x06`) or MemberRef (`0x0A`) table prints the stored row name beside the hex when that row exists; `ldstr` and unstored rows stay hex.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub il: Vec<String>,
    /// Method RVA. Zero when the row has no body.
    pub rva: u32,
}

/// A parameter name and its `Param` sequence number. Zero is the return value.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ClrParam {
    pub name: String,
    pub sequence: u16,
}

/// A property name and its decoded signature.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ClrProperty {
    pub name: String,
    /// Property signature such as `int32(int16)` where the parameters are index parameters. `None` when the blob index is 0 or the blob does not fit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// An event name and its decoded signature.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ClrEvent {
    pub name: String,
    /// The EventType coded index resolved to a name, which stands in for a signature. `None` when the index is 0 or the row does not exist.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// One metadata table named in the `#~` / `#-` header, with its row count.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ClrTable {
    pub name: String,
    pub rows: u32,
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
    let mut type_ids = Vec::new();
    for entry in directory_entries(dir, 0)? {
        if entry.name_or_id & 0x8000_0000 == 0 {
            type_ids.push(entry.name_or_id & 0xffff);
        }
    }
    Ok(type_ids)
}

/// Root types, the name under each type, and the language id under each name.
///
/// A language entry that points at a data entry contributes its size and code page. `OffsetToData` is followed only when `file` and `sections` are passed. A further directory under a language id stays unread. A short directory, name, or data-entry header is an error. A payload that does not fit leaves `payload` empty.
#[cfg(test)]
pub(crate) fn resource_tree(dir: &[u8]) -> Result<Vec<PeResource>> {
    walk_resources(dir, None, None)
}

fn walk_resources(
    dir: &[u8],
    sections: Option<&[goblin::pe::section_table::SectionTable]>,
    file: Option<&[u8]>,
) -> Result<Vec<PeResource>> {
    let mut out = Vec::new();
    for entry in directory_entries(dir, 0)? {
        out.push(PeResource {
            ty: entry_label(dir, entry.name_or_id)?,
            names: named_children(dir, entry.offset, sections, file)?,
        });
    }
    Ok(out)
}

fn named_children(
    dir: &[u8],
    offset: u32,
    sections: Option<&[goblin::pe::section_table::SectionTable]>,
    file: Option<&[u8]>,
) -> Result<Vec<PeResourceName>> {
    if offset & 0x8000_0000 == 0 {
        return Ok(Vec::new());
    }
    let sub = (offset & 0x7fff_ffff) as usize;
    let mut names = Vec::new();
    for child in directory_entries(dir, sub)? {
        names.push(PeResourceName {
            name: entry_label(dir, child.name_or_id)?,
            languages: language_entries(dir, child.offset, sections, file)?,
        });
    }
    Ok(names)
}

/// Language ids in the directory `offset` points at.
///
/// A data-entry offset contributes size and code page. An offset with the subdirectory bit set records the id only.
fn language_entries(
    dir: &[u8],
    offset: u32,
    sections: Option<&[goblin::pe::section_table::SectionTable]>,
    file: Option<&[u8]>,
) -> Result<Vec<PeResourceLang>> {
    if offset & 0x8000_0000 == 0 {
        return Ok(Vec::new());
    }
    let sub = (offset & 0x7fff_ffff) as usize;
    let mut langs = Vec::new();
    for child in directory_entries(dir, sub)? {
        let data = data_entry(dir, child.offset)?;
        let payload = data.and_then(|(_, _, rva, size)| {
            let sections = sections?;
            let file = file?;
            read_payload(sections, file, rva, size)
        });
        langs.push(PeResourceLang {
            lang: entry_label(dir, child.name_or_id)?,
            size: data.map(|d| d.0),
            code_page: data.map(|d| d.1),
            payload,
        });
    }
    Ok(langs)
}

fn read_payload(
    sections: &[goblin::pe::section_table::SectionTable],
    file: &[u8],
    rva: u32,
    size: u32,
) -> Option<Vec<u8>> {
    if size > 65_536 {
        return None;
    }
    let off = section_file_offset(sections, rva)?;
    let end = off.checked_add(size as usize)?;
    file.get(off..end).map(|bytes| bytes.to_vec())
}

/// `Size`, `CodePage`, and `OffsetToData` from an `IMAGE_RESOURCE_DATA_ENTRY`.
///
/// Offset 0 and a subdirectory offset are not data entries.
fn data_entry(dir: &[u8], offset: u32) -> Result<Option<(u32, u32, u32, u32)>> {
    if offset & 0x8000_0000 != 0 || offset == 0 {
        return Ok(None);
    }
    let at = offset as usize;
    let raw = dir
        .get(at..at.saturating_add(16))
        .filter(|b| b.len() == 16)
        .ok_or_else(|| Error::Parse("pe: truncated resource data".into()))?;
    let rva = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let size = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let code_page = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
    Ok(Some((size, code_page, rva, size)))
}

struct DirEntry {
    name_or_id: u32,
    offset: u32,
}

fn directory_entries(dir: &[u8], at: usize) -> Result<Vec<DirEntry>> {
    let header = dir
        .get(at..at.saturating_add(16))
        .filter(|h| h.len() == 16)
        .ok_or_else(|| Error::Parse("pe: truncated resource directory".into()))?;
    let named = usize::from(u16::from_le_bytes([header[12], header[13]]));
    let ids = usize::from(u16::from_le_bytes([header[14], header[15]]));
    let count = named
        .checked_add(ids)
        .ok_or_else(|| Error::Parse("pe: truncated resource directory".into()))?;
    let nbytes = count
        .checked_mul(8)
        .ok_or_else(|| Error::Parse("pe: truncated resource directory".into()))?;
    let start = at
        .checked_add(16)
        .ok_or_else(|| Error::Parse("pe: truncated resource directory".into()))?;
    let end = start
        .checked_add(nbytes)
        .ok_or_else(|| Error::Parse("pe: truncated resource directory".into()))?;
    let table = dir
        .get(start..end)
        .ok_or_else(|| Error::Parse("pe: truncated resource directory".into()))?;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let e = &table[i * 8..i * 8 + 8];
        out.push(DirEntry {
            name_or_id: u32::from_le_bytes([e[0], e[1], e[2], e[3]]),
            offset: u32::from_le_bytes([e[4], e[5], e[6], e[7]]),
        });
    }
    Ok(out)
}

fn entry_label(dir: &[u8], name_or_id: u32) -> Result<String> {
    if name_or_id & 0x8000_0000 == 0 {
        return Ok((name_or_id & 0xffff).to_string());
    }
    let at = (name_or_id & 0x7fff_ffff) as usize;
    let len_bytes = dir
        .get(at..at.saturating_add(2))
        .filter(|b| b.len() == 2)
        .ok_or_else(|| Error::Parse("pe: truncated resource name".into()))?;
    let nchars = usize::from(u16::from_le_bytes([len_bytes[0], len_bytes[1]]));
    if nchars > 256 {
        return Err(Error::Parse("pe: resource name is too long".into()));
    }
    let nbytes = nchars
        .checked_mul(2)
        .ok_or_else(|| Error::Parse("pe: truncated resource name".into()))?;
    let raw = dir
        .get(at + 2..at + 2 + nbytes)
        .ok_or_else(|| Error::Parse("pe: truncated resource name".into()))?;
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Ok(String::from_utf16_lossy(&units))
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
    let tables = metadata_tables(file, metadata_off, &streams);
    let meta = read_metadata_names(file, metadata_off, &streams);
    Some(ClrHeader {
        major_runtime: u16::from_le_bytes([header[4], header[5]]),
        minor_runtime: u16::from_le_bytes([header[6], header[7]]),
        metadata_rva: u32::from_le_bytes([header[8], header[9], header[10], header[11]]),
        metadata_size,
        flags: u32::from_le_bytes([header[16], header[17], header[18], header[19]]),
        entry_point: u32::from_le_bytes([header[20], header[21], header[22], header[23]]),
        version,
        streams,
        tables,
        types: meta.types,
        member_refs: meta.member_refs,
        member_ref_parents: meta.member_ref_parents,
        member_ref_signatures: meta.member_ref_signatures,
        typespec_signatures: meta.typespec_signatures,
        standalone_sigs: meta.standalone_sigs,
        assemblies: meta.assemblies,
        assembly_refs: meta.assembly_refs,
        module_refs: meta.module_refs,
        constants: meta.constants,
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

/// Row counts from the compressed `#~` stream, or the uncompressed `#-` stream.
///
/// The 24-byte header is reserved, version bytes, heap sizes, a reserved byte, then the valid and sorted bitmasks. One little-endian `u32` follows for each set bit, lowest bit first. A short stream yields no tables.
fn metadata_tables(file: &[u8], metadata_off: Option<usize>, streams: &[ClrStream]) -> Vec<ClrTable> {
    let Some(root) = metadata_off else {
        return Vec::new();
    };
    let Some(stream) = streams
        .iter()
        .find(|stream| stream.name == "#~")
        .or_else(|| streams.iter().find(|stream| stream.name == "#-"))
    else {
        return Vec::new();
    };
    let Some(start) = root.checked_add(stream.offset as usize) else {
        return Vec::new();
    };
    let Some(end) = start.checked_add(stream.size as usize) else {
        return Vec::new();
    };
    let Some(blob) = file.get(start..end) else {
        return Vec::new();
    };
    if blob.len() < 24 {
        return Vec::new();
    }
    let valid = u64::from_le_bytes(blob[8..16].try_into().unwrap());
    let count = valid.count_ones() as usize;
    let Some(need) = count.checked_mul(4).and_then(|rows| rows.checked_add(24)) else {
        return Vec::new();
    };
    if blob.len() < need {
        return Vec::new();
    }
    let mut tables = Vec::with_capacity(count);
    for bit in 0..64u32 {
        if valid & (1u64 << bit) == 0 {
            continue;
        }
        let at = 24 + tables.len() * 4;
        let rows = u32::from_le_bytes(blob[at..at + 4].try_into().unwrap());
        tables.push(ClrTable {
            name: table_name(bit),
            rows,
        });
    }
    tables
}

fn table_name(index: u32) -> String {
    const NAMES: [&str; 45] = [
        "Module",
        "TypeRef",
        "TypeDef",
        "FieldPtr",
        "Field",
        "MethodPtr",
        "MethodDef",
        "ParamPtr",
        "Param",
        "InterfaceImpl",
        "MemberRef",
        "Constant",
        "CustomAttribute",
        "FieldMarshal",
        "DeclSecurity",
        "ClassLayout",
        "FieldLayout",
        "StandAloneSig",
        "EventMap",
        "EventPtr",
        "Event",
        "PropertyMap",
        "PropertyPtr",
        "Property",
        "MethodSemantics",
        "MethodImpl",
        "ModuleRef",
        "TypeSpec",
        "ImplMap",
        "FieldRVA",
        "EncLog",
        "EncMap",
        "Assembly",
        "AssemblyProcessor",
        "AssemblyOS",
        "AssemblyRef",
        "AssemblyRefProcessor",
        "AssemblyRefOS",
        "File",
        "ExportedType",
        "ManifestResource",
        "NestedClass",
        "GenericParam",
        "MethodSpec",
        "GenericParamConstraint",
    ];
    match NAMES.get(index as usize) {
        Some(name) => (*name).to_string(),
        None => format!("table-{index}"),
    }
}

struct MetaRead {
    types: Vec<ClrType>,
    member_refs: Vec<String>,
    member_ref_parents: Vec<String>,
    member_ref_signatures: Vec<Option<String>>,
    typespec_signatures: Vec<Option<String>>,
    standalone_sigs: Vec<Option<String>>,
    assemblies: Vec<ClrAssembly>,
    assembly_refs: Vec<ClrAssembly>,
    module_refs: Vec<String>,
    constants: Vec<ClrConstant>,
}

impl MetaRead {
    fn partial(
        types: Vec<ClrType>,
        member_refs: Vec<String>,
        member_ref_parents: Vec<String>,
    ) -> Self {
        Self {
            types,
            member_refs,
            member_ref_parents,
            member_ref_signatures: Vec::new(),
            typespec_signatures: Vec::new(),
            standalone_sigs: Vec::new(),
            assemblies: Vec::new(),
            assembly_refs: Vec::new(),
            module_refs: Vec::new(),
            constants: Vec::new(),
        }
    }
}

/// `Module`, `TypeRef`, and `TypeDef` names, plus `Field` and `MethodDef` names on each `TypeDef`, `Param` names on each method, `MemberRef` names, and `InterfaceImpl` names on each `TypeDef`.
///
/// `FieldPtr`, `MethodPtr`, and `ParamPtr` rows are read by row size and reorder the `Field`, `MethodDef`, and `Param` names through their one index per row; a pointer table shorter than its list, or an index past the list, leaves the row order in place and does not fail the parse. `InterfaceImpl` rows are read, which keeps later tables aligned the same way a skip does. String, blob, and coded-index widths follow the `#~` heap-size byte and the row counts. A row that does not fit ends the list and keeps the names already read. Each `MemberRef` row also records its `MemberRefParent` coded index resolved against the name lists; a parent that does not resolve leaves the field empty. `Assembly` and `AssemblyRef` rows carry their version numbers, culture, public-key blob, and flags word through `enrich_metadata`; `Assembly` rows also carry the hash-algorithm id, and `AssemblyRef` rows also carry the `HashValue` blob, rendered length-plus-hex. Each `StandAloneSig` row records the `method_sig` text of its blob in `standalone_sigs`. Each `Constant` row records the `sig_type` name of its element-type byte, its `HasConstant` parent as `Field#N` / `Param#N` / `Property#N`, and its value blob rendered length-plus-hex; the value is not evaluated. Signatures, RVAs, and IL are not read.
fn read_metadata_names(
    file: &[u8],
    metadata_off: Option<usize>,
    streams: &[ClrStream],
) -> MetaRead {
    let Some(root) = metadata_off else {
        return MetaRead::partial(Vec::new(), Vec::new(), Vec::new());
    };
    let Some(blob) = stream_bytes(file, root, streams, "#~")
        .or_else(|| stream_bytes(file, root, streams, "#-"))
    else {
        return MetaRead::partial(Vec::new(), Vec::new(), Vec::new());
    };
    let Some(strings) = stream_bytes(file, root, streams, "#Strings") else {
        return MetaRead::partial(Vec::new(), Vec::new(), Vec::new());
    };
    if blob.len() < 24 {
        return MetaRead::partial(Vec::new(), Vec::new(), Vec::new());
    }
    let valid = u64::from_le_bytes(blob[8..16].try_into().unwrap());
    let count = valid.count_ones() as usize;
    let Some(header_end) = count.checked_mul(4).and_then(|n| n.checked_add(24)) else {
        return MetaRead::partial(Vec::new(), Vec::new(), Vec::new());
    };
    if blob.len() < header_end {
        return MetaRead::partial(Vec::new(), Vec::new(), Vec::new());
    }
    let str_w = if blob[6] & 0x01 != 0 { 4 } else { 2 };
    let guid_w = if blob[6] & 0x02 != 0 { 4 } else { 2 };
    let blob_w = if blob[6] & 0x04 != 0 { 4 } else { 2 };
    let module_rows = rows_at(blob, valid, 0);
    let typeref_rows = rows_at(blob, valid, 1);
    let typedef_rows = rows_at(blob, valid, 2);
    let field_rows = rows_at(blob, valid, 4);
    let method_rows = rows_at(blob, valid, 6);
    let scope_w = coded_width(
        module_rows
            .max(rows_at(blob, valid, 26))
            .max(rows_at(blob, valid, 35))
            .max(typeref_rows),
        2,
    );
    let extends_w = coded_width(
        typedef_rows.max(typeref_rows).max(rows_at(blob, valid, 27)),
        2,
    );
    let field_w = index_width(field_rows);
    let method_w = index_width(method_rows);
    let param_rows = rows_at(blob, valid, 8);
    let param_w = index_width(param_rows);
    let module_size = 2 + str_w + guid_w * 3;
    let typeref_size = scope_w + str_w * 2;
    let typedef_size = 4 + str_w * 2 + extends_w + field_w + method_w;
    let field_list_at = 4 + str_w * 2 + extends_w;
    let method_list_at = field_list_at + field_w;
    let field_size = 2 + str_w + blob_w;
    let method_size = 8 + str_w + blob_w + param_w;
    let param_list_at = 8 + str_w + blob_w;
    let param_size = 4 + str_w;
    let typedef_w = index_width(typedef_rows);
    let interface_size = typedef_w + extends_w;
    let member_parent_w = coded_width(
        typedef_rows
            .max(typeref_rows)
            .max(method_rows)
            .max(rows_at(blob, valid, 26))
            .max(rows_at(blob, valid, 27)),
        3,
    );
    let member_size = member_parent_w + str_w + blob_w;

    let mut cursor = header_end;
    let mut out = Vec::new();
    let mut member_refs = Vec::new();
    let mut member_parents = Vec::new();
    // Index into `out`, then the 1-based FieldList and MethodList for each TypeDef.
    let mut typedefs: Vec<(usize, u32, u32)> = Vec::new();
    // Index into `out` for each TypeRef row, 1-based row order.
    let mut typerefs: Vec<usize> = Vec::new();
    // 1-based TypeDef row and the resolved interface name for each InterfaceImpl row.
    let mut interfaces: Vec<(u32, String)> = Vec::new();
    // Method name and its 1-based ParamList, in MethodDef order.
    let mut method_recs: Vec<(String, u32)> = Vec::new();
    let mut params_attached = false;
    // One index per Field, MethodDef, or Param row, read from the pointer tables.
    let mut field_ptrs: Vec<u32> = Vec::new();
    let mut method_ptrs: Vec<u32> = Vec::new();
    let mut param_ptrs: Vec<u32> = Vec::new();
    for bit in 0..11u32 {
        if valid & (1u64 << bit) == 0 {
            continue;
        }
        match bit {
            0 | 1 | 2 => {
                let (rows, size, table) = match bit {
                    0 => (module_rows, module_size, "Module"),
                    1 => (typeref_rows, typeref_size, "TypeRef"),
                    _ => (typedef_rows, typedef_size, "TypeDef"),
                };
                for _ in 0..rows {
                    let Some(end) = cursor.checked_add(size) else {
                        return MetaRead::partial(out, member_refs, member_parents);
                    };
                    if end > blob.len() {
                        return MetaRead::partial(out, member_refs, member_parents);
                    }
                    let row = &blob[cursor..end];
                    let (namespace, name) = match bit {
                        0 => (
                            String::new(),
                            heap_string(strings, read_index(row, 2, str_w)),
                        ),
                        1 => (
                            heap_string(strings, read_index(row, scope_w + str_w, str_w)),
                            heap_string(strings, read_index(row, scope_w, str_w)),
                        ),
                        _ => (
                            heap_string(strings, read_index(row, 4 + str_w, str_w)),
                            heap_string(strings, read_index(row, 4, str_w)),
                        ),
                    };
                    if bit == 1 {
                        typerefs.push(out.len());
                    }
                    if bit == 2 {
                        typedefs.push((
                            out.len(),
                            read_index(row, field_list_at, field_w),
                            read_index(row, method_list_at, method_w),
                        ));
                    }
                    out.push(ClrType {
                        table: table.to_string(),
                        namespace,
                        name,
                        fields: Vec::new(),
                        methods: Vec::new(),
                        properties: Vec::new(),
                        events: Vec::new(),
                        interfaces: Vec::new(),
                    });
                    cursor = end;
                }
            }
            3 | 5 => {
                let rows = rows_at(blob, valid, bit);
                let size = if bit == 3 { field_w } else { method_w };
                let mut ptrs = Vec::new();
                let mut fit = true;
                for _ in 0..rows {
                    let Some(end) = cursor.checked_add(size) else {
                        fit = false;
                        break;
                    };
                    if end > blob.len() {
                        fit = false;
                        break;
                    }
                    ptrs.push(read_index(&blob[cursor..end], 0, size));
                    cursor = end;
                }
                if !fit {
                    return MetaRead::partial(out, member_refs, member_parents);
                }
                if bit == 3 {
                    field_ptrs = ptrs;
                } else {
                    method_ptrs = ptrs;
                }
            }
            4 => {
                let mut names = Vec::new();
                for _ in 0..field_rows {
                    let Some(end) = cursor.checked_add(field_size) else {
                        attach_field_names(&mut out, &typedefs, &names);
                        return MetaRead::partial(out, member_refs, member_parents);
                    };
                    if end > blob.len() {
                        attach_field_names(&mut out, &typedefs, &names);
                        return MetaRead::partial(out, member_refs, member_parents);
                    }
                    let row = &blob[cursor..end];
                    names.push(heap_string(strings, read_index(row, 2, str_w)));
                    cursor = end;
                }
                if let Some(ordered) = ptr_order(&names, &field_ptrs) {
                    names = ordered;
                }
                attach_field_names(&mut out, &typedefs, &names);
            }
            6 => {
                for _ in 0..method_rows {
                    let Some(end) = cursor.checked_add(method_size) else {
                        attach_methods(&mut out, &typedefs, &method_recs, &[]);
                        return MetaRead::partial(out, member_refs, member_parents);
                    };
                    if end > blob.len() {
                        attach_methods(&mut out, &typedefs, &method_recs, &[]);
                        return MetaRead::partial(out, member_refs, member_parents);
                    }
                    let row = &blob[cursor..end];
                    method_recs.push((
                        heap_string(strings, read_index(row, 8, str_w)),
                        read_index(row, param_list_at, param_w),
                    ));
                    cursor = end;
                }
                if let Some(ordered) = ptr_order(&method_recs, &method_ptrs) {
                    method_recs = ordered;
                }
            }
            7 => {
                let rows = rows_at(blob, valid, 7);
                let mut ptrs = Vec::new();
                let mut fit = true;
                for _ in 0..rows {
                    let Some(end) = cursor.checked_add(param_w) else {
                        fit = false;
                        break;
                    };
                    if end > blob.len() {
                        fit = false;
                        break;
                    }
                    ptrs.push(read_index(&blob[cursor..end], 0, param_w));
                    cursor = end;
                }
                if !fit {
                    attach_methods(&mut out, &typedefs, &method_recs, &[]);
                    return MetaRead::partial(out, member_refs, member_parents);
                }
                param_ptrs = ptrs;
            }
            8 => {
                let mut names: Vec<(u16, String)> = Vec::new();
                for _ in 0..param_rows {
                    let Some(end) = cursor.checked_add(param_size) else {
                        attach_methods(&mut out, &typedefs, &method_recs, &names);
                        return MetaRead::partial(out, member_refs, member_parents);
                    };
                    if end > blob.len() {
                        attach_methods(&mut out, &typedefs, &method_recs, &names);
                        return MetaRead::partial(out, member_refs, member_parents);
                    }
                    let row = &blob[cursor..end];
                    names.push((
                        u16::from_le_bytes([row[0], row[1]]),
                        heap_string(strings, read_index(row, 4, str_w)),
                    ));
                    cursor = end;
                }
                if let Some(ordered) = ptr_order(&names, &param_ptrs) {
                    names = ordered;
                }
                attach_methods(&mut out, &typedefs, &method_recs, &names);
                params_attached = true;
            }
            9 => {
                let rows = rows_at(blob, valid, 9);
                for _ in 0..rows {
                    let Some(end) = cursor.checked_add(interface_size) else {
                        attach_interfaces(&mut out, &typedefs, &interfaces);
                        if !params_attached {
                            attach_methods(&mut out, &typedefs, &method_recs, &[]);
                        }
                        return MetaRead::partial(out, member_refs, member_parents);
                    };
                    if end > blob.len() {
                        attach_interfaces(&mut out, &typedefs, &interfaces);
                        if !params_attached {
                            attach_methods(&mut out, &typedefs, &method_recs, &[]);
                        }
                        return MetaRead::partial(out, member_refs, member_parents);
                    }
                    let row = &blob[cursor..end];
                    let owner = read_index(row, 0, typedef_w);
                    let coded = read_index(row, typedef_w, extends_w);
                    let target = (coded >> 2) as usize;
                    let resolved = match coded & 0x3 {
                        0 => target
                            .checked_sub(1)
                            .and_then(|row| typedefs.get(row))
                            .map(|&(at, _, _)| at)
                            .and_then(|at| qualified_name(&out, at)),
                        1 => target
                            .checked_sub(1)
                            .and_then(|row| typerefs.get(row))
                            .copied()
                            .and_then(|at| qualified_name(&out, at)),
                        // A TypeSpec has no name; the row number stands in for it.
                        _ => Some(format!("typespec-{target}")),
                    };
                    if let (Some(resolved), true) =
                        (resolved, owner >= 1 && (owner as usize) <= typedefs.len())
                    {
                        interfaces.push((owner, resolved));
                    }
                    cursor = end;
                }
            }
            _ => {
                let rows = rows_at(blob, valid, 10);
                for _ in 0..rows {
                    let Some(end) = cursor.checked_add(member_size) else {
                        if !params_attached {
                            attach_methods(&mut out, &typedefs, &method_recs, &[]);
                        }
                        return MetaRead::partial(out, member_refs, member_parents);
                    };
                    if end > blob.len() {
                        if !params_attached {
                            attach_methods(&mut out, &typedefs, &method_recs, &[]);
                        }
                        return MetaRead::partial(out, member_refs, member_parents);
                    }
                    let row = &blob[cursor..end];
                    member_refs.push(heap_string(
                        strings,
                        read_index(row, member_parent_w, str_w),
                    ));
                    member_parents.push(member_parent_name(
                        read_index(row, 0, member_parent_w),
                        &out,
                        &typedefs,
                        &typerefs,
                    ));
                    cursor = end;
                }
            }
        }
    }
    if !params_attached {
        attach_methods(&mut out, &typedefs, &method_recs, &[]);
    }
    attach_interfaces(&mut out, &typedefs, &interfaces);
    let blobs = stream_bytes(file, root, streams, "#Blob");
    let (member_ref_signatures, assemblies, assembly_refs, module_refs, typespec_signatures, standalone_sigs, constants) =
        enrich_metadata(&mut out, &member_refs, blobs, blob, strings, &field_ptrs, &method_ptrs);
    MetaRead {
        types: out,
        member_refs,
        member_ref_parents: member_parents,
        member_ref_signatures,
        typespec_signatures,
        standalone_sigs,
        assemblies,
        assembly_refs,
        module_refs,
        constants,
    }
}

/// Field and method signatures, assembly, assembly-ref, and module-ref rows, properties, events, `StandAloneSig` blobs, and `Constant` rows. A row that does not fit keeps what was already read. `field_ptrs` and `method_ptrs` reorder the signature and RVA records the same way the names were reordered, so each record stays on its row.
fn enrich_metadata(
    types: &mut [ClrType],
    member_refs: &[String],
    blobs: Option<&[u8]>,
    tilde: &[u8],
    strings: &[u8],
    field_ptrs: &[u32],
    method_ptrs: &[u32],
) -> (
    Vec<Option<String>>,
    Vec<ClrAssembly>,
    Vec<ClrAssembly>,
    Vec<String>,
    Vec<Option<String>>,
    Vec<Option<String>>,
    Vec<ClrConstant>,
) {
    let none_sigs = vec![None; member_refs.len()];
    if tilde.len() < 24 {
        return (none_sigs, Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    }
    let valid = u64::from_le_bytes(tilde[8..16].try_into().unwrap());
    let count = valid.count_ones() as usize;
    let Some(header_end) = count.checked_mul(4).and_then(|n| n.checked_add(24)) else {
        return (none_sigs, Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    };
    if tilde.len() < header_end {
        return (none_sigs, Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    }
    let str_w = if tilde[6] & 1 != 0 { 4 } else { 2 };
    let guid_w = if tilde[6] & 2 != 0 { 4 } else { 2 };
    let blob_w = if tilde[6] & 4 != 0 { 4 } else { 2 };
    let rows = |bit: u32| rows_at(tilde, valid, bit);
    let module_rows = rows(0);
    let typeref_rows = rows(1);
    let typedef_rows = rows(2);
    let field_rows = rows(4);
    let method_rows = rows(6);
    let param_rows = rows(8);
    let member_rows = rows(10);
    let event_rows = rows(20);
    let property_rows = rows(23);
    let moduleref_rows = rows(26);
    let typespec_rows = rows(27);
    let assembly_rows = rows(32);
    let assemblyref_rows = rows(35);
    let file_rows = rows(38);
    let exported_rows = rows(39);
    let generic_rows = rows(42);
    let scope_w = coded_width(
        module_rows
            .max(moduleref_rows)
            .max(assemblyref_rows)
            .max(typeref_rows),
        2,
    );
    let extends_w = coded_width(typedef_rows.max(typeref_rows).max(typespec_rows), 2);
    let field_w = index_width(field_rows);
    let method_w = index_width(method_rows);
    let param_w = index_width(param_rows);
    let typedef_w = index_width(typedef_rows);
    let event_w = index_width(event_rows);
    let property_w = index_width(property_rows);
    let member_parent_w = coded_width(
        typedef_rows
            .max(typeref_rows)
            .max(method_rows)
            .max(moduleref_rows)
            .max(typespec_rows),
        3,
    );
    let has_constant_w = coded_width(field_rows.max(param_rows).max(property_rows), 2);
    let has_marshal_w = coded_width(field_rows.max(param_rows), 1);
    let has_decl_w = coded_width(typedef_rows.max(method_rows).max(assembly_rows), 2);
    let has_semantics_w = coded_width(event_rows.max(property_rows), 1);
    let method_or_ref_w = coded_width(method_rows.max(member_rows), 1);
    let forwarded_w = coded_width(field_rows.max(method_rows), 1);
    let impl_w = coded_width(file_rows.max(assemblyref_rows).max(exported_rows), 2);
    let custom_bits = [
        6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43,
    ];
    let custom_parent_w = coded_width(custom_bits.iter().map(|bit| rows(*bit)).max().unwrap_or(0), 5);
    let custom_type_w = coded_width(method_rows.max(member_rows), 3);
    let width = |bit: u32| -> Option<usize> {
        Some(match bit {
            0 => 2 + str_w + guid_w * 3,
            1 => scope_w + str_w * 2,
            2 => 4 + str_w * 2 + extends_w + field_w + method_w,
            3 => field_w,
            4 => 2 + str_w + blob_w,
            5 => method_w,
            6 => 8 + str_w + blob_w + param_w,
            7 => param_w,
            8 => 4 + str_w,
            9 => typedef_w + extends_w,
            10 => member_parent_w + str_w + blob_w,
            11 => 2 + has_constant_w + blob_w,
            12 => custom_parent_w + custom_type_w + blob_w,
            13 => has_marshal_w + blob_w,
            14 => 2 + has_decl_w + blob_w,
            15 => 6 + typedef_w,
            16 => 4 + field_w,
            17 => blob_w,
            18 => typedef_w + event_w,
            19 => event_w,
            20 => 2 + str_w + extends_w,
            21 => typedef_w + property_w,
            22 => property_w,
            23 => 2 + str_w + blob_w,
            24 => 2 + method_w + has_semantics_w,
            25 => typedef_w + method_or_ref_w * 2,
            26 => str_w,
            27 => blob_w,
            28 => 2 + forwarded_w + str_w + index_width(moduleref_rows),
            29 => 4 + field_w,
            30 => 8,
            31 => 4,
            32 => 16 + blob_w + str_w * 2,
            33 => 4,
            34 => 12,
            35 => 12 + blob_w * 2 + str_w * 2,
            36 => 4 + index_width(assemblyref_rows),
            37 => 12 + index_width(assemblyref_rows),
            38 => 4 + str_w + blob_w,
            39 => 8 + str_w * 2 + impl_w,
            40 => 8 + str_w + impl_w,
            41 => typedef_w * 2,
            42 => 4 + coded_width(typedef_rows.max(method_rows), 1) + str_w,
            43 => method_or_ref_w + blob_w,
            44 => index_width(generic_rows) + extends_w,
            _ => return None,
        })
    };

    let mut cursor = header_end;
    let mut method_recs = Vec::new();
    let mut field_sigs = Vec::new();
    let mut member_sigs = Vec::new();
    let mut assemblies = Vec::new();
    let mut assembly_refs = Vec::new();
    let mut module_refs = Vec::new();
    // One decoded element text per TypeSpec row, from `sig_type`.
    let mut typespec_sigs = Vec::new();
    // One method-signature text per StandAloneSig row, from `method_sig`.
    let mut standalone_sigs = Vec::new();
    // One row per Constant row: element-type name, HasConstant parent, value blob.
    let mut constants = Vec::new();
    let mut event_maps = Vec::new();
    let mut property_maps = Vec::new();
    // Name and signature from the blob, per Event row.
    let mut event_names: Vec<(String, Option<String>)> = Vec::new();
    // Name and signature from the blob, per Property row.
    let mut property_names: Vec<(String, Option<String>)> = Vec::new();
    let mut fields_done = false;
    let mut methods_done = false;
    let mut members_done = false;
    // Index into `types` for each 1-based TypeDef and TypeRef row.
    let typedef_at: Vec<usize> = types
        .iter()
        .enumerate()
        .filter(|(_, ty)| ty.table == "TypeDef")
        .map(|(index, _)| index)
        .collect();
    let typeref_at: Vec<usize> = types
        .iter()
        .enumerate()
        .filter(|(_, ty)| ty.table == "TypeRef")
        .map(|(index, _)| index)
        .collect();
    for bit in 0..45u32 {
        if valid & (1u64 << bit) == 0 {
            continue;
        }
        let Some(size) = width(bit) else {
            break;
        };
        let mut fit = true;
        for _ in 0..rows(bit) {
            let Some(end) = cursor.checked_add(size) else {
                fit = false;
                break;
            };
            if end > tilde.len() {
                fit = false;
                break;
            }
            let row = &tilde[cursor..end];
            match bit {
                4 => {
                    let sig = blobs.and_then(|heap| {
                        crate::clr_sig::method_sig(heap, read_index(row, 2 + str_w, blob_w))
                    });
                    field_sigs.push(sig);
                }
                6 => {
                    let rva = u32::from_le_bytes([row[0], row[1], row[2], row[3]]);
                    let sig = blobs.and_then(|heap| {
                        crate::clr_sig::method_sig(heap, read_index(row, 8 + str_w, blob_w))
                    });
                    method_recs.push((rva, sig));
                }
                10 => {
                    let sig = blobs.and_then(|heap| {
                        crate::clr_sig::method_sig(
                            heap,
                            read_index(row, member_parent_w + str_w, blob_w),
                        )
                    });
                    member_sigs.push(sig);
                }
                11 => {
                    // A `Constant` row: the element-type byte is named by
                    // `sig_type`'s own match on the single byte; a tag whose
                    // name needs more bytes stays empty. `HasConstant` is a
                    // two-bit coded index over Field, Param, and Property.
                    // The value blob is length-plus-hex; index 0 or a blob
                    // that does not fit stays empty. The value is not
                    // evaluated.
                    let kind = crate::clr_sig::sig_type(&row[..1], 0, 0)
                        .map(|(text, _)| text)
                        .unwrap_or_default();
                    let coded = read_index(row, 2, has_constant_w);
                    let parent = match (coded & 0x3, coded >> 2) {
                        (0, n) if n != 0 => format!("Field#{n}"),
                        (1, n) if n != 0 => format!("Param#{n}"),
                        (2, n) if n != 0 => format!("Property#{n}"),
                        _ => String::new(),
                    };
                    let value = blobs
                        .and_then(|heap| heap_blob(heap, read_index(row, 2 + has_constant_w, blob_w)))
                        .map(render_blob);
                    constants.push(ClrConstant { kind, parent, value });
                }
                17 => {
                    // A StandAloneSig blob is the `MethodSig` text `method_sig`
                    // already parses; index 0 or a rejected blob stays empty.
                    let sig = blobs.and_then(|heap| {
                        crate::clr_sig::method_sig(heap, read_index(row, 0, blob_w))
                    });
                    standalone_sigs.push(sig);
                }
                18 => event_maps.push((
                    read_index(row, 0, typedef_w),
                    read_index(row, typedef_w, event_w),
                )),
                20 => {
                    // EventType is a TypeDefOrRef coded index; the resolved name stands in for a signature.
                    let coded = read_index(row, 2 + str_w, extends_w);
                    let target = (coded >> 2) as usize;
                    let sig = match coded & 0x3 {
                        0 => target
                            .checked_sub(1)
                            .and_then(|r| typedef_at.get(r))
                            .copied()
                            .and_then(|at| qualified_name(types, at)),
                        1 => target
                            .checked_sub(1)
                            .and_then(|r| typeref_at.get(r))
                            .copied()
                            .and_then(|at| qualified_name(types, at)),
                        _ => Some(format!("typespec-{target}")),
                    };
                    event_names.push((heap_string(strings, read_index(row, 2, str_w)), sig));
                }
                21 => property_maps.push((
                    read_index(row, 0, typedef_w),
                    read_index(row, typedef_w, property_w),
                )),
                23 => {
                    property_names.push((
                        heap_string(strings, read_index(row, 2, str_w)),
                        blobs.and_then(|heap| {
                            crate::clr_sig::property_sig(heap, read_index(row, 2 + str_w, blob_w))
                        }),
                    ));
                }
                26 => module_refs.push(heap_string(strings, read_index(row, 0, str_w))),
                27 => {
                    // The blob payload is one element the `sig_type` parser
                    // accepts; index 0 or a rejected blob stays empty.
                    let sig = blobs
                        .and_then(|heap| heap_blob(heap, read_index(row, 0, blob_w)))
                        .and_then(|payload| {
                            crate::clr_sig::sig_type(payload, 0, 0).map(|(text, _)| text)
                        });
                    typespec_sigs.push(sig);
                }
                32 => {
                    let public_key = blobs
                        .and_then(|heap| heap_blob(heap, read_index(row, 16, blob_w)))
                        .map(render_blob);
                    assemblies.push(ClrAssembly {
                        major_version: u16::from_le_bytes([row[4], row[5]]),
                        minor_version: u16::from_le_bytes([row[6], row[7]]),
                        build_number: u16::from_le_bytes([row[8], row[9]]),
                        revision_number: u16::from_le_bytes([row[10], row[11]]),
                        name: heap_string(strings, read_index(row, 16 + blob_w, str_w)),
                        culture: heap_string(strings, read_index(row, 16 + blob_w + str_w, str_w)),
                        public_key,
                        hash_alg_id: Some(u32::from_le_bytes([row[0], row[1], row[2], row[3]])),
                        flags: u32::from_le_bytes([row[12], row[13], row[14], row[15]]),
                        hash_value: None,
                    });
                }
                35 => {
                    let public_key = blobs
                        .and_then(|heap| heap_blob(heap, read_index(row, 12, blob_w)))
                        .map(render_blob);
                    let hash_value = blobs
                        .and_then(|heap| {
                            heap_blob(heap, read_index(row, 12 + blob_w + str_w * 2, blob_w))
                        })
                        .map(render_blob);
                    assembly_refs.push(ClrAssembly {
                        major_version: u16::from_le_bytes([row[0], row[1]]),
                        minor_version: u16::from_le_bytes([row[2], row[3]]),
                        build_number: u16::from_le_bytes([row[4], row[5]]),
                        revision_number: u16::from_le_bytes([row[6], row[7]]),
                        name: heap_string(strings, read_index(row, 12 + blob_w, str_w)),
                        culture: heap_string(strings, read_index(row, 12 + blob_w + str_w, str_w)),
                        public_key,
                        hash_alg_id: None,
                        flags: u32::from_le_bytes([row[8], row[9], row[10], row[11]]),
                        hash_value,
                    });
                }
                _ => {}
            }
            cursor = end;
        }
        if !fit {
            break;
        }
        if bit == 4 {
            fields_done = true;
        }
        if bit == 6 {
            methods_done = true;
        }
        if bit == 10 {
            members_done = true;
        }
    }
    if fields_done {
        if let Some(ordered) = ptr_order(&field_sigs, field_ptrs) {
            field_sigs = ordered;
        }
        let count: usize = types.iter().map(|ty| ty.fields.len()).sum();
        if count == field_sigs.len() {
            let mut index = 0;
            for ty in types.iter_mut() {
                for field in &mut ty.fields {
                    field.signature = field_sigs[index].clone();
                    index += 1;
                }
            }
        }
    }
    if methods_done {
        if let Some(ordered) = ptr_order(&method_recs, method_ptrs) {
            method_recs = ordered;
        }
        let count: usize = types.iter().map(|ty| ty.methods.len()).sum();
        if count == method_recs.len() {
            let mut index = 0;
            for ty in types.iter_mut() {
                for method in &mut ty.methods {
                    method.rva = method_recs[index].0;
                    method.signature = method_recs[index].1.clone();
                    index += 1;
                }
            }
        }
    }
    attach_mapped(types, &property_maps, &property_names, true);
    attach_mapped(types, &event_maps, &event_names, false);
    let signatures = if members_done && member_sigs.len() == member_refs.len() {
        member_sigs
    } else {
        none_sigs
    };
    (signatures, assemblies, assembly_refs, module_refs, typespec_sigs, standalone_sigs, constants)
}

fn attach_mapped(
    types: &mut [ClrType],
    maps: &[(u32, u32)],
    names: &[(String, Option<String>)],
    properties: bool,
) {
    if maps.is_empty() {
        return;
    }
    let typedefs: Vec<usize> = types
        .iter()
        .enumerate()
        .filter(|(_, ty)| ty.table == "TypeDef")
        .map(|(index, _)| index)
        .collect();
    let lists: Vec<u32> = maps.iter().map(|row| row.1).collect();
    for (index, &(parent, _)) in maps.iter().enumerate() {
        if parent == 0 {
            continue;
        }
        let Some(&at) = typedefs.get(parent as usize - 1) else {
            continue;
        };
        let (start, end) = list_span(&lists, index, names.len());
        let owned = names[start..end]
            .iter()
            .map(|(name, signature)| (name.clone(), signature.clone()))
            .collect::<Vec<(String, Option<String>)>>();
        if properties {
            types[at].properties = owned
                .into_iter()
                .map(|(name, signature)| ClrProperty { name, signature })
                .collect();
        } else {
            types[at].events = owned
                .into_iter()
                .map(|(name, signature)| ClrEvent { name, signature })
                .collect();
        }
    }
}

/// One `MemberRefParent` coded index resolved to a display string. TypeDef and TypeRef rows become names when read; `ModuleRef`, `MethodDef`, and `TypeSpec` stay as `ModuleRef#N`, `MethodDef#N`, and `TypeSpec#N`. An unknown tag or a row that is not in the name lists is empty.
fn member_parent_name(
    coded: u32,
    types: &[ClrType],
    typedefs: &[(usize, u32, u32)],
    typerefs: &[usize],
) -> String {
    let tag = coded & 0x7;
    let target = (coded >> 3) as usize;
    match tag {
        0 => target
            .checked_sub(1)
            .and_then(|row| typedefs.get(row))
            .map(|&(at, _, _)| at)
            .and_then(|at| qualified_name(types, at)),
        1 => target
            .checked_sub(1)
            .and_then(|row| typerefs.get(row))
            .copied()
            .and_then(|at| qualified_name(types, at)),
        2 => Some(format!("ModuleRef#{target}")),
        3 => Some(format!("MethodDef#{target}")),
        4 => Some(format!("TypeSpec#{target}")),
        _ => None,
    }
    .unwrap_or_default()
}

/// `Namespace.Name` for the `types` entry at `at`.
fn qualified_name(types: &[ClrType], at: usize) -> Option<String> {
    let ty = types.get(at)?;
    if ty.namespace.is_empty() {
        Some(ty.name.clone())
    } else {
        Some(format!("{}.{}", ty.namespace, ty.name))
    }
}

/// Each InterfaceImpl row names one interface of one TypeDef. The 1-based TypeDef row picks the owner.
fn attach_interfaces(
    out: &mut [ClrType],
    typedefs: &[(usize, u32, u32)],
    interfaces: &[(u32, String)],
) {
    if interfaces.is_empty() {
        return;
    }
    for (index, &(at, _, _)) in typedefs.iter().enumerate() {
        let row = index as u32 + 1;
        out[at].interfaces = interfaces
            .iter()
            .filter(|(owner, _)| *owner == row)
            .map(|(_, name)| name.clone())
            .collect();
    }
}

/// `FieldList` is 1-based. Each TypeDef owns names up to the next list, or the end of `Field`.
fn attach_field_names(out: &mut [ClrType], typedefs: &[(usize, u32, u32)], names: &[String]) {
    let lists: Vec<u32> = typedefs.iter().map(|row| row.1).collect();
    for (index, &(at, _, _)) in typedefs.iter().enumerate() {
        let (start, end) = list_span(&lists, index, names.len());
        out[at].fields = names[start..end]
            .iter()
            .map(|name| ClrField {
                name: name.clone(),
                signature: None,
            })
            .collect();
    }
}

/// `MethodList` and `ParamList` are 1-based. Each method owns parameter names up to the next list.
fn attach_methods(
    out: &mut [ClrType],
    typedefs: &[(usize, u32, u32)],
    recs: &[(String, u32)],
    params: &[(u16, String)],
) {
    let param_lists: Vec<u32> = recs.iter().map(|rec| rec.1).collect();
    let methods: Vec<ClrMethod> = recs
        .iter()
        .enumerate()
        .map(|(index, (name, _))| {
            let (start, end) = list_span(&param_lists, index, params.len());
            ClrMethod {
                name: name.clone(),
                params: params[start..end]
                    .iter()
                    .map(|(sequence, name)| ClrParam {
                        name: name.clone(),
                        sequence: *sequence,
                    })
                    .collect(),
                signature: None,
                il: Vec::new(),
                rva: 0,
            }
        })
        .collect();
    let method_lists: Vec<u32> = typedefs.iter().map(|row| row.2).collect();
    for (index, &(at, _, _)) in typedefs.iter().enumerate() {
        let (start, end) = list_span(&method_lists, index, methods.len());
        out[at].methods = methods[start..end].to_vec();
    }
}

fn list_span(lists: &[u32], index: usize, len: usize) -> (usize, usize) {
    let start = (lists[index].saturating_sub(1) as usize).min(len);
    let end = match lists.get(index + 1) {
        Some(&next) => (next.saturating_sub(1) as usize).max(start).min(len),
        None => len,
    };
    (start, end)
}

/// `items` reordered through a pointer table. `Some` only when the table holds one in-range index per list row; otherwise the row order stands and the caller keeps `items` as read.
fn ptr_order<T: Clone>(items: &[T], ptrs: &[u32]) -> Option<Vec<T>> {
    if ptrs.len() != items.len() {
        return None;
    }
    items
        .iter()
        .enumerate()
        .map(|(index, _)| {
            ptrs[index]
                .checked_sub(1)
                .filter(|&row| (row as usize) < items.len())
                .map(|row| items[row as usize].clone())
        })
        .collect()
}

fn stream_bytes<'a>(
    file: &'a [u8],
    root: usize,
    streams: &[ClrStream],
    name: &str,
) -> Option<&'a [u8]> {
    let stream = streams.iter().find(|stream| stream.name == name)?;
    let start = root.checked_add(stream.offset as usize)?;
    let end = start.checked_add(stream.size as usize)?;
    if start >= file.len() {
        return None;
    }
    file.get(start..end.min(file.len()))
}

fn rows_at(blob: &[u8], valid: u64, bit: u32) -> u32 {
    if valid & (1u64 << bit) == 0 {
        return 0;
    }
    let mut prior = 0usize;
    for earlier in 0..bit {
        if valid & (1u64 << earlier) != 0 {
            prior += 1;
        }
    }
    let at = 24 + prior * 4;
    u32::from_le_bytes(blob[at..at + 4].try_into().unwrap())
}

fn index_width(rows: u32) -> usize {
    if rows < 0x1_0000 { 2 } else { 4 }
}

fn coded_width(max_rows: u32, tag_bits: u32) -> usize {
    let small_limit = 1u32 << (16 - tag_bits);
    if max_rows < small_limit { 2 } else { 4 }
}

fn read_index(row: &[u8], at: usize, width: usize) -> u32 {
    if width == 2 {
        u32::from(u16::from_le_bytes([row[at], row[at + 1]]))
    } else {
        u32::from_le_bytes([row[at], row[at + 1], row[at + 2], row[at + 3]])
    }
}

fn heap_string(strings: &[u8], index: u32) -> String {
    let start = index as usize;
    if start >= strings.len() {
        return String::new();
    }
    let rest = &strings[start..];
    let end = rest.iter().position(|byte| *byte == 0).unwrap_or(rest.len());
    String::from_utf8_lossy(&rest[..end.min(512)]).into_owned()
}

/// Blob-heap bytes at `index`. `None` for index 0, a length prefix that does not fit, or a blob past the heap.
fn heap_blob(blobs: &[u8], index: u32) -> Option<&[u8]> {
    let mut at = index as usize;
    if at == 0 || at >= blobs.len() {
        return None;
    }
    let first = blobs[at];
    at += 1;
    let len = if first < 0x80 {
        usize::from(first)
    } else if first < 0xC0 {
        let second = *blobs.get(at)?;
        at += 1;
        (usize::from(first & 0x3f) << 8) | usize::from(second)
    } else {
        // Four bytes total from the first byte, masked to 29 bits
        // (ECMA-335 II.24.2.4). The first byte counts as data, so nothing
        // is skipped.
        let raw: [u8; 4] = blobs.get(at - 1..at + 3)?.try_into().ok()?;
        at += 3;
        (u32::from_be_bytes(raw) & 0x1fff_ffff) as usize
    };
    let end = at.checked_add(len)?;
    if end > blobs.len() {
        return None;
    }
    Some(&blobs[at..end])
}

/// Blob length plus hex of at most the first 32 bytes.
fn render_blob(bytes: &[u8]) -> ClrBlob {
    ClrBlob {
        len: bytes.len(),
        hex: bytes
            .iter()
            .take(32)
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    }
}

pub fn facts(bytes: &[u8]) -> Result<PeFacts> {
    let pe = goblin::pe::PE::parse(bytes).map_err(|e| Error::Parse(format!("pe: {e}")))?;
    let timestamp = pe.header.coff_header.time_date_stamp;
    let Some(optional) = pe.header.optional_header else {
        return Ok(PeFacts {
            timestamp,
            timestamp_utc: unix_utc(timestamp),
            subsystem: None,
            image_base: None,
            directories: Vec::new(),
            has_clr: false,
            clr: None,
            resource_type_ids: Vec::new(),
            resources: Vec::new(),
            pdb: None,
            overlay: None,
        });
    };
    let subsystem = Some(subsystem_name(optional.windows_fields.subsystem));
    let image_base = Some(optional.windows_fields.image_base);

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
        let mut header = parse_clr(header, bytes, metadata_off)?;
        attach_il(&mut header, bytes, &pe.sections);
        Some(header)
    });
    let (resource_type_ids, resources) =
        if let Some(dir) = optional.data_directories.get_resource_table() {
            let off = section_file_offset(&pe.sections, dir.virtual_address).ok_or_else(|| {
                Error::Parse(format!(
                    "pe: resource directory RVA {:#x} is not in a section",
                    dir.virtual_address
                ))
            })?;
            let blob = bytes
                .get(off..)
                .ok_or_else(|| Error::Parse("pe: truncated resource directory".into()))?;
            (
                resource_type_ids(blob)?,
                walk_resources(blob, Some(pe.sections.as_slice()), Some(bytes))?,
            )
        } else {
            (Vec::new(), Vec::new())
        };
    let overlay = crate::trailing_overlay(pe_image_end(&pe.sections), bytes.len() as u64);
    let pdb = optional.data_directories.get_debug_table().and_then(|dir| {
        if dir.size == 0 {
            return None;
        }
        let off = section_file_offset(&pe.sections, dir.virtual_address)?;
        codeview_pdb(bytes, off, dir.size)
    });

    Ok(PeFacts {
        timestamp,
        timestamp_utc: unix_utc(timestamp),
        subsystem,
        image_base,
        directories,
        has_clr,
        clr,
        resource_type_ids,
        resources,
        pdb,
        overlay,
    })
}

fn attach_il(
    header: &mut ClrHeader,
    file: &[u8],
    sections: &[goblin::pe::section_table::SectionTable],
) {
    // MethodDef names in table order: each TypeDef's method list is
    // contiguous and ascending, so the stored names across the TypeDefs are
    // the MethodDef rows. `call`, `callvirt`, and `newobj` MethodDef and
    // MemberRef tokens print the row name beside the hex when it is stored.
    let method_defs: Vec<String> = header
        .types
        .iter()
        .filter(|ty| ty.table == "TypeDef")
        .flat_map(|ty| ty.methods.iter().map(|m| m.name.clone()))
        .collect();
    let member_refs = header.member_refs.clone();
    for ty in &mut header.types {
        for method in &mut ty.methods {
            if method.rva == 0 {
                continue;
            }
            let Some(off) = section_file_offset(sections, method.rva) else {
                continue;
            };
            let Some(bytes) = file.get(off..) else {
                continue;
            };
            method.il = crate::clr_sig::il_ops_resolved(bytes, &method_defs, &member_refs);
        }
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` from a Unix timestamp. The date is proleptic Gregorian.
fn unix_utc(secs: u32) -> String {
    let days = i64::from(secs / 86_400);
    let rem = secs % 86_400;
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    (year, month as u32, day as u32)
}

fn pe_image_end(sections: &[goblin::pe::section_table::SectionTable]) -> u64 {
    sections
        .iter()
        .map(|section| {
            u64::from(section.pointer_to_raw_data).saturating_add(u64::from(section.size_of_raw_data))
        })
        .max()
        .unwrap_or(0)
}

fn subsystem_name(subsystem: u16) -> String {
    match subsystem {
        1 => "native".to_string(),
        2 => "windows-gui".to_string(),
        3 => "windows-cui".to_string(),
        5 => "os2".to_string(),
        7 => "posix".to_string(),
        9 => "windows-ce".to_string(),
        10 => "efi-application".to_string(),
        11 => "efi-boot".to_string(),
        12 => "efi-runtime".to_string(),
        13 => "efi-rom".to_string(),
        14 => "xbox".to_string(),
        16 => "windows-boot".to_string(),
        n => format!("subsystem-{n}"),
    }
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
    use crate::clr_sig::il_ops_resolved;

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
    fn resource_data_entry_keeps_size_and_skips_payload() {
        let bytes = resource_name_fixture();
        let tree = resource_tree(&bytes).unwrap();
        assert_eq!(
            tree,
            vec![
                PeResource {
                    ty: "VER".into(),
                    names: vec![res_name("2", &[])],
                },
                PeResource {
                    ty: "16".into(),
                    names: vec![
                        res_name("App", &[]),
                        res_name(
                            "1",
                            &[("1033", None, None), ("1040", Some(4), Some(1252))],
                        ),
                    ],
                },
            ]
        );
        assert_eq!(resource_type_ids(&bytes).unwrap(), vec![16]);
        assert!(!format!("{tree:?}").contains("SECRET"));
        assert!(!format!("{tree:?}").contains("9999"));
    }

    fn res_name(name: &str, languages: &[(&str, Option<u32>, Option<u32>)]) -> PeResourceName {
        PeResourceName {
            name: name.into(),
            languages: languages
                .iter()
                .map(|(lang, size, code_page)| PeResourceLang {
                    lang: (*lang).into(),
                    size: *size,
                    code_page: *code_page,
                    payload: None,
                })
                .collect(),
        }
    }

    #[test]
    fn truncated_resource_data_is_an_error() {
        let mut dir = vec![0u8; 100];
        dir[14] = 1;
        write_res_entry(&mut dir, 16, 16, 0x8000_0000 | 32);
        dir[32 + 14] = 1;
        write_res_entry(&mut dir, 48, 1, 0x8000_0000 | 64);
        dir[64 + 14] = 1;
        write_res_entry(&mut dir, 80, 1033, 90);
        let err = resource_tree(&dir).unwrap_err();
        assert!(matches!(err, Error::Parse(ref msg) if msg == "pe: truncated resource data"));
    }

    #[test]
    fn resource_name_longer_than_256_chars_is_an_error() {
        let mut dir = vec![0u8; 16];
        dir[12] = 1;
        dir.extend_from_slice(&0x8000_0020u32.to_le_bytes());
        dir.extend_from_slice(&0u32.to_le_bytes());
        dir.resize(32 + 2, 0);
        dir[32] = 1;
        dir[33] = 1;
        let err = resource_tree(&dir).unwrap_err();
        assert!(matches!(err, Error::Parse(ref msg) if msg == "pe: resource name is too long"));
    }

    /// Named type `VER` with id name `2`. Type `16` with names `App` and `1`.
    /// `1` has language `1033`, which points at a directory containing `9999`, and language `1040`,
    /// whose data entry reports size 4 and code page 1252. The payload bytes are `SECRET`.
    fn resource_name_fixture() -> Vec<u8> {
        let mut dir = vec![0u8; 202];
        dir[12] = 1;
        dir[14] = 1;
        write_res_entry(&mut dir, 16, 0x8000_0000 | 88, 0x8000_0000 | 32);
        write_res_entry(&mut dir, 24, 16, 0x8000_0000 | 56);
        dir[32 + 14] = 1;
        write_res_entry(&mut dir, 48, 2, 0);
        dir[56 + 12] = 1;
        dir[56 + 14] = 1;
        write_res_entry(&mut dir, 72, 0x8000_0000 | 96, 0);
        write_res_entry(&mut dir, 80, 1, 0x8000_0000 | 104);
        write_utf16_name(&mut dir, 88, "VER");
        write_utf16_name(&mut dir, 96, "App");
        dir[104 + 14] = 2;
        write_res_entry(&mut dir, 120, 1033, 0x8000_0000 | 140);
        write_res_entry(&mut dir, 128, 1040, 180);
        dir[140 + 14] = 1;
        write_res_entry(&mut dir, 156, 9999, 0);
        dir[180..184].copy_from_slice(&0x2000u32.to_le_bytes());
        dir[184..188].copy_from_slice(&4u32.to_le_bytes());
        dir[188..192].copy_from_slice(&1252u32.to_le_bytes());
        dir[196..202].copy_from_slice(b"SECRET");
        dir
    }

    fn write_res_entry(buf: &mut [u8], at: usize, name_or_id: u32, offset: u32) {
        buf[at..at + 4].copy_from_slice(&name_or_id.to_le_bytes());
        buf[at + 4..at + 8].copy_from_slice(&offset.to_le_bytes());
    }

    fn write_utf16_name(buf: &mut [u8], at: usize, name: &str) {
        let units: Vec<u16> = name.encode_utf16().collect();
        buf[at..at + 2].copy_from_slice(&(units.len() as u16).to_le_bytes());
        for (i, unit) in units.iter().enumerate() {
            let pos = at + 2 + i * 2;
            buf[pos..pos + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }

    #[test]
    fn rejects_non_pe() {
        assert!(facts(b"not a pe").is_err());
    }

    #[test]
    fn reads_subsystem_image_base_and_timestamp() {
        let got = facts(&minimal_pe()).unwrap();
        assert_eq!(got.timestamp, 0x1020_3040);
        assert_eq!(got.subsystem.as_deref(), Some("windows-cui"));
        assert_eq!(got.image_base, Some(0x4000_00));
        assert!(got.directories.is_empty());
        assert!(!got.has_clr);
        assert!(got.resources.is_empty());
        assert_eq!(got.pdb, None);
        assert_eq!(got.overlay, None);
    }

    #[test]
    fn reads_resource_payload_and_overlay() {
        let bytes = pe_with_resource_payload();
        let got = facts(&bytes).unwrap();
        let lang = &got.resources[0].names[0].languages[0];
        assert_eq!(lang.lang, "1033");
        assert_eq!(lang.size, Some(4));
        assert_eq!(lang.payload.as_deref(), Some(b"SECR".as_slice()));
        assert_ne!(
            lang.payload.as_deref(),
            Some(lang.size.unwrap().to_le_bytes().as_slice())
        );
        let overlay = got.overlay.expect("overlay");
        assert_eq!(overlay.size, 5);
        assert_eq!(&bytes[overlay.offset as usize..], b"EXTRA");

        let mut short = bytes.clone();
        short.truncate(overlay.offset as usize);
        let got = facts(&short).unwrap();
        assert_eq!(got.overlay, None);
        assert_eq!(
            got.resources[0].names[0].languages[0].payload.as_deref(),
            Some(b"SECR".as_slice())
        );
    }

    /// One `.rsrc` section. Language 1033 points at `SECR`. `EXTRA` follows the raw section.
    fn pe_with_resource_payload() -> Vec<u8> {
        let mut dir = vec![0u8; 116];
        dir[14] = 1;
        write_res_entry(&mut dir, 16, 16, 0x8000_0000 | 32);
        dir[32 + 14] = 1;
        write_res_entry(&mut dir, 48, 1, 0x8000_0000 | 64);
        dir[64 + 14] = 1;
        write_res_entry(&mut dir, 80, 1033, 96);
        let rva = 0x2000u32 + 112;
        dir[96..100].copy_from_slice(&rva.to_le_bytes());
        dir[100..104].copy_from_slice(&4u32.to_le_bytes());
        dir[104..108].copy_from_slice(&1252u32.to_le_bytes());
        dir[112..116].copy_from_slice(b"SECR");

        let mut bytes = vec![0u8; 0x400];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x14cu16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&120u16.to_le_bytes());
        let opt = 0x98;
        bytes[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes());
        bytes[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        bytes[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes());
        bytes[opt + 60..opt + 64].copy_from_slice(&0x400u32.to_le_bytes());
        bytes[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
        bytes[opt + 92..opt + 96].copy_from_slice(&3u32.to_le_bytes());
        bytes[opt + 112..opt + 116].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[opt + 116..opt + 120].copy_from_slice(&(dir.len() as u32).to_le_bytes());
        let sect = opt + 120;
        bytes[sect..sect + 5].copy_from_slice(b".rsrc");
        bytes[sect + 8..sect + 12].copy_from_slice(&(dir.len() as u32).to_le_bytes());
        bytes[sect + 12..sect + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[sect + 16..sect + 20].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[sect + 20..sect + 24].copy_from_slice(&0x400u32.to_le_bytes());
        bytes[sect + 36..sect + 40].copy_from_slice(&0x4000_0000u32.to_le_bytes());
        bytes.resize(0x400 + 0x200, 0);
        bytes[0x400..0x400 + dir.len()].copy_from_slice(&dir);
        bytes.extend_from_slice(b"EXTRA");
        bytes
    }

    /// PE32 with no sections and no data directories.
    fn minimal_pe() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x80];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes.extend_from_slice(b"PE\0\0");
        bytes.extend_from_slice(&0x14c_u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0x1020_3040u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&96u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        let mut optional = vec![0u8; 96];
        optional[0..2].copy_from_slice(&0x10bu16.to_le_bytes());
        optional[28..32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        optional[28 + 40..28 + 42].copy_from_slice(&3u16.to_le_bytes());
        bytes.extend_from_slice(&optional);
        bytes
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

    fn tilde_header(valid: u64, rows: &[u32]) -> Vec<u8> {
        let mut blob = vec![0u8; 24];
        blob[4] = 2;
        blob[7] = 1;
        blob[8..16].copy_from_slice(&valid.to_le_bytes());
        for row in rows {
            blob.extend_from_slice(&row.to_le_bytes());
        }
        blob
    }

    #[test]
    fn clr_table_counts_follow_valid_bits() {
        let blob = tilde_header(1 | (1 << 2) | (1 << 6), &[1, 4, 9]);
        let streams = vec![ClrStream {
            name: "#~".into(),
            offset: 0,
            size: blob.len() as u32,
        }];
        let tables = metadata_tables(&blob, Some(0), &streams);
        assert_eq!(
            tables,
            vec![
                ClrTable {
                    name: "Module".into(),
                    rows: 1
                },
                ClrTable {
                    name: "TypeDef".into(),
                    rows: 4
                },
                ClrTable {
                    name: "MethodDef".into(),
                    rows: 9
                },
            ]
        );
    }

    #[test]
    fn clr_uncompressed_stream_is_used_when_tilde_is_absent() {
        let blob = tilde_header(1u64 << 32, &[2]);
        let streams = vec![ClrStream {
            name: "#-".into(),
            offset: 0,
            size: blob.len() as u32,
        }];
        let tables = metadata_tables(&blob, Some(0), &streams);
        assert_eq!(tables[0].name, "Assembly");
        assert_eq!(tables[0].rows, 2);
    }

    #[test]
    fn clr_short_table_stream_is_empty() {
        let streams = vec![ClrStream {
            name: "#~".into(),
            offset: 0,
            size: 16,
        }];
        assert!(metadata_tables(&[0u8; 16], Some(0), &streams).is_empty());
        let unnamed = vec![ClrStream {
            name: "#Strings".into(),
            offset: 0,
            size: 32,
        }];
        assert!(metadata_tables(&tilde_header(1, &[1]), Some(0), &unnamed).is_empty());
    }

    fn with_strings(tilde: &[u8], strings: &[u8]) -> (Vec<u8>, Vec<ClrStream>) {
        let mut file = tilde.to_vec();
        let strings_at = file.len() as u32;
        file.extend_from_slice(strings);
        let streams = vec![
            ClrStream {
                name: "#~".into(),
                offset: 0,
                size: strings_at,
            },
            ClrStream {
                name: "#Strings".into(),
                offset: strings_at,
                size: strings.len() as u32,
            },
        ];
        (file, streams)
    }

    /// `with_strings` plus a `#Blob` heap appended after the strings.
    fn with_blobs(tilde: &[u8], strings: &[u8], blobs: &[u8]) -> (Vec<u8>, Vec<ClrStream>) {
        let (mut file, mut streams) = with_strings(tilde, strings);
        let blob_at = file.len() as u32;
        file.extend_from_slice(blobs);
        streams.push(ClrStream {
            name: "#Blob".into(),
            offset: blob_at,
            size: blobs.len() as u32,
        });
        (file, streams)
    }

    #[test]
    fn clr_type_names_from_module_and_typedef() {
        let mut tilde = tilde_header(1 | (1 << 2), &[1, 1]);
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&[0u8; 6]);
        tilde.extend_from_slice(&0u32.to_le_bytes());
        tilde.extend_from_slice(&13u16.to_le_bytes());
        tilde.extend_from_slice(&7u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        let mut strings = vec![0u8];
        strings.extend_from_slice(b"Hello\0World\0App\0");
        let (file, streams) = with_strings(&tilde, &strings);
        let types = read_metadata_names(&file, Some(0), &streams).types;
        assert_eq!(
            types,
            vec![
                ClrType {
                    table: "Module".into(),
                    namespace: "".into(),
                    name: "Hello".into(),
                    fields: vec![],
                    methods: vec![],
                    properties: vec![],
                    events: vec![],
                    interfaces: vec![],
                },
                ClrType {
                    table: "TypeDef".into(),
                    namespace: "World".into(),
                    name: "App".into(),
                    fields: vec![],
                    methods: vec![],
                    properties: vec![],
                    events: vec![],
                    interfaces: vec![],
                },
            ]
        );
    }

    #[test]
    fn clr_typedef_uses_a_wide_field_index() {
        let mut tilde = tilde_header(1 | (1 << 2) | (1 << 4), &[1, 2, 70_000]);
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&[0u8; 6]);
        for (name, namespace) in [(5u16, 7u16), (10u16, 12u16)] {
            tilde.extend_from_slice(&0u32.to_le_bytes());
            tilde.extend_from_slice(&name.to_le_bytes());
            tilde.extend_from_slice(&namespace.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&0u32.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
        }
        let mut strings = vec![0u8];
        strings.extend_from_slice(b"Mod\0A\0N1\0B\0N2\0");
        let (file, streams) = with_strings(&tilde, &strings);
        let types = read_metadata_names(&file, Some(0), &streams).types;
        assert_eq!(types[1].name, "A");
        assert_eq!(types[1].namespace, "N1");
        assert_eq!(types[2].name, "B");
        assert_eq!(types[2].namespace, "N2");
        assert!(types[1].methods.is_empty());
    }

    #[test]
    fn clr_typedef_methods_skip_the_field_row() {
        // TypeDef, Field, MethodDef. The field row sits between the types and the methods.
        let mut tilde = tilde_header((1 << 2) | (1 << 4) | (1 << 6), &[2, 1, 3]);
        for (name, namespace, methods) in [(1u16, 5u16, 1u16), (17u16, 0u16, 3u16)] {
            tilde.extend_from_slice(&0u32.to_le_bytes());
            tilde.extend_from_slice(&name.to_le_bytes());
            tilde.extend_from_slice(&namespace.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&1u16.to_le_bytes());
            tilde.extend_from_slice(&methods.to_le_bytes());
        }
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&28u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        for name in [8u16, 12u16, 23u16] {
            tilde.extend_from_slice(&0u32.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&name.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&1u16.to_le_bytes());
        }
        let mut strings = vec![0u8];
        strings.extend_from_slice(b"App\0Ns\0Run\0Stop\0Other\0Done\0Fld\0");
        let (file, streams) = with_strings(&tilde, &strings);
        let types = read_metadata_names(&file, Some(0), &streams).types;
        assert_eq!(types[0].table, "TypeDef");
        assert_eq!(types[0].namespace, "Ns");
        assert_eq!(types[0].name, "App");
        assert_eq!(
            types[0].methods,
            vec![clr_method("Run", &[]), clr_method("Stop", &[])]
        );
        assert!(types[0].fields.is_empty());
        assert_eq!(types[1].name, "Other");
        assert_eq!(types[1].namespace, "");
        assert_eq!(types[1].methods, vec![clr_method("Done", &[])]);
        assert_eq!(types[1].fields, vec![clr_field("Fld")]);
    }

    #[test]
    fn clr_typedef_fields_follow_the_field_list() {
        // FieldPtr sits between TypeDef and Field. Its one row is shorter than the Field list, so the row order stands.
        let mut tilde = tilde_header((1 << 2) | (1 << 3) | (1 << 4) | (1 << 6), &[2, 1, 2, 2]);
        for (name, namespace, fields, methods) in
            [(1u16, 5u16, 1u16, 1u16), (12u16, 0u16, 2u16, 2u16)]
        {
            tilde.extend_from_slice(&0u32.to_le_bytes());
            tilde.extend_from_slice(&name.to_le_bytes());
            tilde.extend_from_slice(&namespace.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&fields.to_le_bytes());
            tilde.extend_from_slice(&methods.to_le_bytes());
        }
        tilde.extend_from_slice(&1u16.to_le_bytes());
        for name in [23u16, 27u16] {
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&name.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
        }
        for name in [8u16, 18u16] {
            tilde.extend_from_slice(&0u32.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&name.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&1u16.to_le_bytes());
        }
        let mut strings = vec![0u8];
        strings.extend_from_slice(b"App\0Ns\0Run\0Other\0Done\0Fld\0More\0");
        let (file, streams) = with_strings(&tilde, &strings);
        let types = read_metadata_names(&file, Some(0), &streams).types;
        assert_eq!(types[0].name, "App");
        assert_eq!(types[0].namespace, "Ns");
        assert_eq!(types[0].fields, vec![clr_field("Fld")]);
        assert_eq!(types[0].methods, vec![clr_method("Run", &[])]);
        assert_eq!(types[1].name, "Other");
        assert_eq!(types[1].fields, vec![clr_field("More")]);
        assert_eq!(types[1].methods, vec![clr_method("Done", &[])]);
    }

    #[test]
    fn clr_method_params_skip_the_param_ptr_row() {
        // ParamPtr sits between MethodDef and Param. Its one row is shorter than the Param list, so the row order stands.
        let mut tilde = tilde_header((1 << 2) | (1 << 6) | (1 << 7) | (1 << 8), &[1, 2, 1, 3]);
        tilde.extend_from_slice(&0u32.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&5u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        for (name, params) in [(8u16, 1u16), (12u16, 3u16)] {
            tilde.extend_from_slice(&0u32.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&name.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&params.to_le_bytes());
        }
        tilde.extend_from_slice(&1u16.to_le_bytes());
        for (seq, name) in [(1u16, 17u16), (2u16, 19u16), (1u16, 21u16)] {
            tilde.extend_from_slice(&seq.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&name.to_le_bytes());
        }
        let mut strings = vec![0u8];
        strings.extend_from_slice(b"App\0Ns\0Run\0Stop\0a\0b\0c\0");
        let (file, streams) = with_strings(&tilde, &strings);
        let types = read_metadata_names(&file, Some(0), &streams).types;
        assert_eq!(types[0].name, "App");
        assert_eq!(types[0].namespace, "Ns");
        assert_eq!(
            types[0].methods,
            vec![
                clr_method("Run", &[("a", 1), ("b", 2)]),
                clr_method("Stop", &[("c", 1)])
            ]
        );
    }

    #[test]
    fn clr_field_ptr_orders_the_field_names() {
        // FieldPtr row 1 points at Field 2 and row 2 at Field 1; the owned names move.
        let mut tilde = tilde_header((1 << 2) | (1 << 3) | (1 << 4) | (1 << 6), &[2, 2, 2, 2]);
        for (name, namespace, fields, methods) in
            [(1u16, 5u16, 1u16, 1u16), (12u16, 0u16, 2u16, 2u16)]
        {
            tilde.extend_from_slice(&0u32.to_le_bytes());
            tilde.extend_from_slice(&name.to_le_bytes());
            tilde.extend_from_slice(&namespace.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&fields.to_le_bytes());
            tilde.extend_from_slice(&methods.to_le_bytes());
        }
        tilde.extend_from_slice(&2u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        for name in [23u16, 27u16] {
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&name.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
        }
        for name in [8u16, 18u16] {
            tilde.extend_from_slice(&0u32.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&name.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&1u16.to_le_bytes());
        }
        let mut strings = vec![0u8];
        strings.extend_from_slice(b"App\0Ns\0Run\0Other\0Done\0Fld\0More\0");
        let (file, streams) = with_strings(&tilde, &strings);
        let types = read_metadata_names(&file, Some(0), &streams).types;
        assert_eq!(types[0].name, "App");
        assert_eq!(types[0].fields, vec![clr_field("More")]);
        assert_eq!(types[0].methods, vec![clr_method("Run", &[])]);
        assert_eq!(types[1].name, "Other");
        assert_eq!(types[1].fields, vec![clr_field("Fld")]);
        assert_eq!(types[1].methods, vec![clr_method("Done", &[])]);
    }

    #[test]
    fn clr_field_ptr_short_of_the_list_keeps_row_order() {
        // One FieldPtr row for two Field rows, then a pointer past the list: the row order stands.
        for (rows, ptrs) in [(&[2u32, 1, 2, 2][..], vec![2u16]), (&[2, 2, 2, 2][..], vec![5, 1])] {
            let mut tilde = tilde_header((1 << 2) | (1 << 3) | (1 << 4) | (1 << 6), rows);
            for (name, namespace, fields, methods) in
                [(1u16, 5u16, 1u16, 1u16), (12u16, 0u16, 2u16, 2u16)]
            {
                tilde.extend_from_slice(&0u32.to_le_bytes());
                tilde.extend_from_slice(&name.to_le_bytes());
                tilde.extend_from_slice(&namespace.to_le_bytes());
                tilde.extend_from_slice(&0u16.to_le_bytes());
                tilde.extend_from_slice(&fields.to_le_bytes());
                tilde.extend_from_slice(&methods.to_le_bytes());
            }
            for ptr in ptrs {
                tilde.extend_from_slice(&ptr.to_le_bytes());
            }
            for name in [23u16, 27u16] {
                tilde.extend_from_slice(&0u16.to_le_bytes());
                tilde.extend_from_slice(&name.to_le_bytes());
                tilde.extend_from_slice(&0u16.to_le_bytes());
            }
            for name in [8u16, 18u16] {
                tilde.extend_from_slice(&0u32.to_le_bytes());
                tilde.extend_from_slice(&0u16.to_le_bytes());
                tilde.extend_from_slice(&0u16.to_le_bytes());
                tilde.extend_from_slice(&name.to_le_bytes());
                tilde.extend_from_slice(&0u16.to_le_bytes());
                tilde.extend_from_slice(&1u16.to_le_bytes());
            }
            let mut strings = vec![0u8];
            strings.extend_from_slice(b"App\0Ns\0Run\0Other\0Done\0Fld\0More\0");
            let (file, streams) = with_strings(&tilde, &strings);
            let types = read_metadata_names(&file, Some(0), &streams).types;
            assert_eq!(types[0].fields, vec![clr_field("Fld")]);
            assert_eq!(types[1].fields, vec![clr_field("More")]);
        }
    }

    #[test]
    fn clr_field_ptr_moves_the_signature_with_the_name() {
        // The signature of each Field row follows the name the pointer selects.
        let mut tilde = tilde_header((1 << 2) | (1 << 3) | (1 << 4), &[1, 2, 2]);
        tilde.extend_from_slice(&0u32.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&2u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        for (name, sig) in [(5u16, 1u16), (9u16, 0u16)] {
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&name.to_le_bytes());
            tilde.extend_from_slice(&sig.to_le_bytes());
        }
        let mut strings = vec![0u8];
        strings.extend_from_slice(b"App\0Fld\0Blank\0");
        let mut file = tilde.clone();
        let strings_at = file.len() as u32;
        file.extend_from_slice(&strings);
        let blob_at = file.len() as u32;
        // Entry 1: length 2, field calling convention, int32. Entry 0 is no blob.
        file.extend_from_slice(&[0x00, 0x02, 0x06, 0x08]);
        let streams = vec![
            ClrStream {
                name: "#~".into(),
                offset: 0,
                size: strings_at,
            },
            ClrStream {
                name: "#Strings".into(),
                offset: strings_at,
                size: strings.len() as u32,
            },
            ClrStream {
                name: "#Blob".into(),
                offset: blob_at,
                size: 4,
            },
        ];
        let types = read_metadata_names(&file, Some(0), &streams).types;
        assert_eq!(
            types[0].fields,
            vec![
                ClrField {
                    name: "Blank".into(),
                    signature: None,
                },
                ClrField {
                    name: "Fld".into(),
                    signature: Some("field int32".into()),
                },
            ]
        );
    }

    #[test]
    fn clr_method_ptr_orders_the_method_names() {
        // MethodPtr row 1 points at MethodDef 2 and row 2 at MethodDef 1; the owners move.
        let mut tilde = tilde_header((1 << 2) | (1 << 5) | (1 << 6), &[2, 2, 2]);
        for (name, namespace, fields, methods) in
            [(1u16, 5u16, 0u16, 1u16), (12u16, 0u16, 0u16, 2u16)]
        {
            tilde.extend_from_slice(&0u32.to_le_bytes());
            tilde.extend_from_slice(&name.to_le_bytes());
            tilde.extend_from_slice(&namespace.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&fields.to_le_bytes());
            tilde.extend_from_slice(&methods.to_le_bytes());
        }
        tilde.extend_from_slice(&2u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        for name in [8u16, 18u16] {
            tilde.extend_from_slice(&0u32.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&name.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&1u16.to_le_bytes());
        }
        let mut strings = vec![0u8];
        strings.extend_from_slice(b"App\0Ns\0Run\0Other\0Done\0");
        let (file, streams) = with_strings(&tilde, &strings);
        let types = read_metadata_names(&file, Some(0), &streams).types;
        assert_eq!(types[0].name, "App");
        assert_eq!(types[0].methods, vec![clr_method("Done", &[])]);
        assert!(types[0].fields.is_empty());
        assert_eq!(types[1].name, "Other");
        assert_eq!(types[1].methods, vec![clr_method("Run", &[])]);
    }

    #[test]
    fn clr_param_ptr_orders_the_param_names() {
        // ParamPtr row 1 points at Param 2 and row 2 at Param 1; the sequences move with the names.
        let mut tilde = tilde_header((1 << 2) | (1 << 6) | (1 << 7) | (1 << 8), &[1, 2, 3, 3]);
        tilde.extend_from_slice(&0u32.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&5u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        for (name, params) in [(8u16, 1u16), (12u16, 3u16)] {
            tilde.extend_from_slice(&0u32.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&name.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&params.to_le_bytes());
        }
        tilde.extend_from_slice(&2u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&3u16.to_le_bytes());
        for (seq, name) in [(1u16, 17u16), (2u16, 19u16), (1u16, 21u16)] {
            tilde.extend_from_slice(&seq.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&name.to_le_bytes());
        }
        let mut strings = vec![0u8];
        strings.extend_from_slice(b"App\0Ns\0Run\0Stop\0a\0b\0c\0");
        let (file, streams) = with_strings(&tilde, &strings);
        let types = read_metadata_names(&file, Some(0), &streams).types;
        assert_eq!(
            types[0].methods,
            vec![
                clr_method("Run", &[("b", 2), ("a", 1)]),
                clr_method("Stop", &[("c", 1)])
            ]
        );
    }

    #[test]
    fn clr_member_refs_skip_the_interface_row() {
        // InterfaceImpl sits between Param and MemberRef. Its row is skipped.
        let mut tilde = tilde_header((1 << 9) | (1 << 10), &[1, 2]);
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        for name in [1u16, 7u16] {
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&name.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
        }
        let mut strings = vec![0u8];
        strings.extend_from_slice(b"Write\0Read\0");
        let (file, streams) = with_strings(&tilde, &strings);
        let meta = read_metadata_names(&file, Some(0), &streams);
        assert!(meta.types.is_empty());
        assert_eq!(meta.member_refs, vec!["Write".to_string(), "Read".to_string()]);
    }

    #[test]
    fn clr_member_ref_parents_resolve_and_stay_empty_when_unfit() {
        // TypeRef 1 is Ns.IFace; TypeDef 1 is App. Seven MemberRef rows cover every parent tag,
        // a TypeRef row past the table, and an unknown tag.
        let mut tilde = tilde_header((1 << 1) | (1 << 2) | (1 << 10), &[1, 1, 7]);
        // TypeRef: scope, name, namespace.
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&8u16.to_le_bytes());
        tilde.extend_from_slice(&5u16.to_le_bytes());
        // TypeDef: flags, name, namespace, extends, field list, method list.
        tilde.extend_from_slice(&0u32.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        // MemberRef rows: coded parent, name, blob index 0. Tags: 0 TypeDef, 1 TypeRef,
        // 2 ModuleRef, 3 MethodDef, 4 TypeSpec, then TypeRef row 5 (absent) and tag 5.
        for (coded, name) in [
            (8u16, 14u16),
            (9, 16),
            (10, 18),
            (19, 20),
            (12, 22),
            (41, 24),
            (13, 26),
        ] {
            tilde.extend_from_slice(&coded.to_le_bytes());
            tilde.extend_from_slice(&name.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
        }
        let mut strings = vec![0u8];
        strings.extend_from_slice(b"App\0Ns\0IFace\0a\0b\0c\0d\0e\0f\0g\0");
        let (file, streams) = with_strings(&tilde, &strings);
        let meta = read_metadata_names(&file, Some(0), &streams);
        assert_eq!(
            meta.member_refs,
            vec!["a", "b", "c", "d", "e", "f", "g"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            meta.member_ref_parents,
            vec![
                "App".to_string(),
                "Ns.IFace".to_string(),
                "ModuleRef#1".to_string(),
                "MethodDef#2".to_string(),
                "TypeSpec#1".to_string(),
                String::new(),
                String::new(),
            ]
        );
    }

    #[test]
    fn clr_typespec_blobs_decode_one_element_each() {
        // Five TypeSpec rows: a primitive, a ptr wrapper, a class with a coded
        // index, a blob sig_type rejects, blob index 0, and an index past the heap.
        let mut tilde = tilde_header(1u64 << 27, &[6]);
        for index in [1u16, 3, 6, 9, 0, 50] {
            tilde.extend_from_slice(&index.to_le_bytes());
        }
        let names = vec![0u8];
        let mut blobs = vec![0u8];
        blobs.extend_from_slice(&[0x01, 0x08]);
        blobs.extend_from_slice(&[0x02, 0x0f, 0x08]);
        blobs.extend_from_slice(&[0x02, 0x12, 0x05]);
        blobs.extend_from_slice(&[0x01, 0x15]);
        let (file, streams) = with_blobs(&tilde, &names, &blobs);
        let meta = read_metadata_names(&file, Some(0), &streams);
        assert_eq!(
            meta.typespec_signatures,
            vec![
                Some("int32".to_string()),
                Some("ptr int32".to_string()),
                Some("class typeref-1".to_string()),
                None,
                None,
                None,
            ]
        );
    }

    #[test]
    fn clr_typespec_rows_keep_labels_and_align_member_refs() {
        // One MemberRef row whose TypeSpec parent stays the TypeSpec#1 label
        // even though a TypeSpec table with a decodable blob now exists, and
        // two TypeSpec rows that decode beside it.
        let mut tilde = tilde_header((1 << 10) | (1 << 27), &[1, 2]);
        // MemberRef: coded parent tag 4 (TypeSpec) row 1, name, blob index 0.
        tilde.extend_from_slice(&((1u16 << 3) | 4u16).to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        // TypeSpec rows: blob index 1, then index 0.
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        let names = vec![0u8];
        let mut blobs = vec![0u8];
        blobs.extend_from_slice(&[0x01, 0x08]);
        let (file, streams) = with_blobs(&tilde, &names, &blobs);
        let meta = read_metadata_names(&file, Some(0), &streams);
        assert_eq!(meta.member_ref_parents, vec!["TypeSpec#1".to_string()]);
        assert_eq!(
            meta.typespec_signatures,
            vec![Some("int32".to_string()), None]
        );
    }

    #[test]
    fn clr_standalonesig_rows_decode_method_sigs() {
        // Five StandAloneSig rows: a default-call method sig, a field sig
        // (`field int32` via `method_sig`), a blob `method_sig` rejects
        // (truncated), blob index 0, and an index past the heap.
        let mut tilde = tilde_header(1u64 << 17, &[5]);
        for index in [1u16, 6, 9, 0, 50] {
            tilde.extend_from_slice(&index.to_le_bytes());
        }
        let names = vec![0u8];
        let mut blobs = vec![0u8];
        // index 1: len 4, default call, void ret, one int32 param.
        blobs.extend_from_slice(&[0x04, 0x00, 0x01, 0x01, 0x08]);
        // index 6: len 2, field calling convention 0x06, int32.
        blobs.extend_from_slice(&[0x02, 0x06, 0x08]);
        // index 9: len 1, conv 0x00, then no param count — rejected.
        blobs.extend_from_slice(&[0x01, 0x00]);
        let (file, streams) = with_blobs(&tilde, &names, &blobs);
        let meta = read_metadata_names(&file, Some(0), &streams);
        assert_eq!(
            meta.standalone_sigs,
            vec![
                Some("void(int32)".to_string()),
                Some("field int32".to_string()),
                None,
                None,
                None,
            ]
        );
    }

    #[test]
    fn clr_standalonesig_width_stays_one_blob_index() {
        // A StandAloneSig row next to an Assembly row: the 17 => blob_w width
        // is unchanged, so the Assembly row parses on its expected layout.
        let mut tilde = tilde_header((1u64 << 17) | (1u64 << 32), &[1, 1]);
        // StandAloneSig: blob index 1.
        tilde.extend_from_slice(&1u16.to_le_bytes());
        // Assembly: hash alg id, four version numbers, flags, public key blob
        // index 0, name, culture.
        tilde.extend_from_slice(&0u32.to_le_bytes());
        tilde.extend_from_slice(&[1u8, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0]);
        tilde.extend_from_slice(&0u32.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        let names = vec![0u8];
        let mut blobs = vec![0u8];
        blobs.extend_from_slice(&[0x04, 0x00, 0x01, 0x01, 0x08]);
        let (file, streams) = with_blobs(&tilde, &names, &blobs);
        let meta = read_metadata_names(&file, Some(0), &streams);
        assert_eq!(meta.standalone_sigs, vec![Some("void(int32)".to_string())]);
        assert_eq!(meta.assemblies.len(), 1);
        assert_eq!(meta.assemblies[0].name, "");
        assert_eq!(meta.assemblies[0].major_version, 1);
        assert_eq!(meta.assemblies[0].flags, 5);
    }

    #[test]
    fn clr_constant_rows_decode_type_parent_and_blob() {
        // Five Constant rows: an int32 on Field#1, a string on Param#2, a
        // float64 on Property#3 with blob index 0, an unknown type byte with
        // parent tag 3 and a blob that does not fit, and a class-tagged row
        // (the single byte names nothing) with an index past the heap.
        let mut tilde = tilde_header(1u64 << 11, &[5]);
        for (tag, parent, blob) in
            [(0x08u8, 4u16, 1u16), (0x0e, 9, 6), (0x0d, 14, 0), (0x55, 19, 9), (0x12, 0, 50)]
        {
            tilde.push(tag);
            tilde.push(0);
            tilde.extend_from_slice(&parent.to_le_bytes());
            tilde.extend_from_slice(&blob.to_le_bytes());
        }
        let names = vec![0u8];
        let mut blobs = vec![0u8];
        // index 1: length 4, four payload bytes.
        blobs.extend_from_slice(&[0x04, 0xAA, 0xBB, 0xCC, 0xDD]);
        // index 6: length 1, one payload byte.
        blobs.extend_from_slice(&[0x01, 0x2A]);
        // index 9: claims 5 bytes but carries 1 — does not fit.
        blobs.extend_from_slice(&[0x05, 0x01]);
        let (file, streams) = with_blobs(&tilde, &names, &blobs);
        let meta = read_metadata_names(&file, Some(0), &streams);
        assert_eq!(
            meta.constants,
            vec![
                ClrConstant {
                    kind: "int32".into(),
                    parent: "Field#1".into(),
                    value: Some(ClrBlob { len: 4, hex: "aabbccdd".into() }),
                },
                ClrConstant {
                    kind: "string".into(),
                    parent: "Param#2".into(),
                    value: Some(ClrBlob { len: 1, hex: "2a".into() }),
                },
                ClrConstant {
                    kind: "float64".into(),
                    parent: "Property#3".into(),
                    value: None,
                },
                ClrConstant {
                    kind: String::new(),
                    parent: String::new(),
                    value: None,
                },
                ClrConstant {
                    kind: String::new(),
                    parent: String::new(),
                    value: None,
                },
            ]
        );
    }

    #[test]
    fn clr_constant_width_stays_type_byte_parent_and_blob() {
        // A Constant row next to an Assembly row: the 11 => 2 + has_constant_w
        // + blob_w width is unchanged, so the Assembly row parses on its own
        // layout. A parent coded row of 0 stays empty.
        let mut tilde = tilde_header((1u64 << 11) | (1u64 << 32), &[1, 1]);
        // Constant: type int32, pad, parent coded 0 (tag 0, row 0), blob index 1.
        tilde.extend_from_slice(&[0x08, 0x00]);
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        // Assembly: hash alg id, four version numbers, flags, public key blob
        // index 0, name, culture.
        tilde.extend_from_slice(&0u32.to_le_bytes());
        tilde.extend_from_slice(&[1u8, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0]);
        tilde.extend_from_slice(&0u32.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        let names = vec![0u8];
        let mut blobs = vec![0u8];
        blobs.extend_from_slice(&[0x04, 0x00, 0x01, 0x01, 0x08]);
        let (file, streams) = with_blobs(&tilde, &names, &blobs);
        let meta = read_metadata_names(&file, Some(0), &streams);
        assert_eq!(
            meta.constants,
            vec![ClrConstant {
                kind: "int32".into(),
                parent: String::new(),
                value: Some(ClrBlob { len: 4, hex: "00010108".into() }),
            }]
        );
        assert_eq!(meta.assemblies.len(), 1);
        assert_eq!(meta.assemblies[0].name, "");
        assert_eq!(meta.assemblies[0].major_version, 1);
        assert_eq!(meta.assemblies[0].flags, 5);
    }

    fn clr_method(name: &str, params: &[(&str, u16)]) -> ClrMethod {
        ClrMethod {
            name: name.to_string(),
            params: params
                .iter()
                .map(|(param, sequence)| ClrParam {
                    name: (*param).to_string(),
                    sequence: *sequence,
                })
                .collect(),
            signature: None,
            il: Vec::new(),
            rva: 0,
        }
    }

    fn clr_field(name: &str) -> ClrField {
        ClrField {
            name: name.to_string(),
            signature: None,
        }
    }

    fn il_section() -> goblin::pe::section_table::SectionTable {
        goblin::pe::section_table::SectionTable {
            name: *b".text\0\0\0",
            real_name: None,
            virtual_size: 0x200,
            virtual_address: 0x1000,
            size_of_raw_data: 0x200,
            pointer_to_raw_data: 0x400,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0x4000_0040,
        }
    }

    #[test]
    fn attach_il_resolves_methoddef_and_memberref_tokens() {
        // MethodDef rows in table order: Run (row 1), Jump (row 2), from two
        // TypeDefs. MemberRef row 1 is Add.
        let mut file = vec![0u8; 0x600];
        // RVA 0x1000: tiny body, codesize 6 — call MethodDef row 1, ret.
        file[0x400..0x407].copy_from_slice(&[0x1a, 0x28, 0x01, 0x00, 0x00, 0x06, 0x2a]);
        // RVA 0x1010: tiny body, codesize 10 — callvirt MemberRef row 1,
        // ldstr (stays hex).
        file[0x410..0x41b].copy_from_slice(&[
            0x2a, 0x6f, 0x01, 0x00, 0x00, 0x0a, 0x72, 0x01, 0x00, 0x00, 0x70,
        ]);
        // RVA 0x1020: tiny body, codesize 6 — call MethodDef row 2, ret.
        file[0x420..0x427].copy_from_slice(&[0x1a, 0x28, 0x02, 0x00, 0x00, 0x06, 0x2a]);
        let section = il_section();
        let mut header = ClrHeader {
            major_runtime: 2,
            minor_runtime: 5,
            metadata_rva: 0,
            metadata_size: 0,
            flags: 1,
            entry_point: 0,
            version: None,
            streams: Vec::new(),
            tables: Vec::new(),
            types: vec![
                ClrType {
                    table: "TypeDef".into(),
                    namespace: String::new(),
                    name: "A".into(),
                    fields: Vec::new(),
                    methods: vec![
                        ClrMethod {
                            name: "Run".into(),
                            params: Vec::new(),
                            signature: None,
                            il: Vec::new(),
                            rva: 0x1000,
                        },
                        ClrMethod {
                            name: "Unmapped".into(),
                            params: Vec::new(),
                            signature: None,
                            il: Vec::new(),
                            rva: 0,
                        },
                        ClrMethod {
                            name: "Offmap".into(),
                            params: Vec::new(),
                            signature: None,
                            il: Vec::new(),
                            rva: 0x9000,
                        },
                    ],
                    properties: Vec::new(),
                    events: Vec::new(),
                    interfaces: Vec::new(),
                },
                ClrType {
                    table: "TypeDef".into(),
                    namespace: String::new(),
                    name: "B".into(),
                    fields: Vec::new(),
                    methods: vec![ClrMethod {
                        name: "Jump".into(),
                        params: Vec::new(),
                        signature: None,
                        il: Vec::new(),
                        rva: 0x1020,
                    }],
                    properties: Vec::new(),
                    events: Vec::new(),
                    interfaces: Vec::new(),
                },
            ],
            member_refs: vec!["Add".to_string()],
            member_ref_signatures: Vec::new(),
            member_ref_parents: Vec::new(),
            typespec_signatures: Vec::new(),
            standalone_sigs: Vec::new(),
            assemblies: Vec::new(),
            assembly_refs: Vec::new(),
            module_refs: Vec::new(),
            constants: Vec::new(),
        };
        attach_il(&mut header, &file, &[section]);
        let types = &header.types;
        assert_eq!(
            types[0].methods[0].il,
            vec!["call 0x06000001 Run".to_string(), "ret".to_string()]
        );
        // RVA 0 and an RVA no section maps leave the listing empty.
        assert!(types[0].methods[1].il.is_empty());
        assert!(types[0].methods[2].il.is_empty());
        assert_eq!(
            types[1].methods[0].il,
            vec!["call 0x06000002 Unmapped".to_string(), "ret".to_string()]
        );
        // Jump is MethodDef row 3: the body-less `Unmapped` still occupies
        // its row in the flat list.
        assert_eq!(
            il_ops_resolved(
                &[0x16, 0x28, 0x03, 0x00, 0x00, 0x06],
                &[
                    "Run".to_string(),
                    "Unmapped".to_string(),
                    "Jump".to_string()
                ],
                &[]
            ),
            vec!["call 0x06000003 Jump".to_string()]
        );
    }

    #[test]
    fn clr_interfaces_resolve_typedef_and_typeref_rows() {
        // TypeRef 1 is Ns.IFace; TypeDef 1 is App, implementing TypeRef 1, TypeDef 1, and a TypeSpec.
        let mut tilde = tilde_header((1 << 1) | (1 << 2) | (1 << 9), &[1, 1, 3]);
        // TypeRef: scope, name, namespace.
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&7u16.to_le_bytes());
        // TypeDef: flags, name, namespace, extends, field list, method list.
        tilde.extend_from_slice(&0u32.to_le_bytes());
        tilde.extend_from_slice(&10u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        // InterfaceImpl rows: owner TypeDef 1, then a coded TypeDefOrRef.
        for coded in [(1u16 << 2) | 1u16, (1u16 << 2) | 0u16, (1u16 << 2) | 2u16] {
            tilde.extend_from_slice(&1u16.to_le_bytes());
            tilde.extend_from_slice(&coded.to_le_bytes());
        }
        let mut strings = vec![0u8];
        strings.extend_from_slice(b"IFace\0Ns\0App\0");
        let (file, streams) = with_strings(&tilde, &strings);
        let types = read_metadata_names(&file, Some(0), &streams).types;
        assert_eq!(types[1].name, "App");
        assert_eq!(
            types[1].interfaces,
            vec![
                "Ns.IFace".to_string(),
                "App".to_string(),
                "typespec-1".to_string()
            ]
        );
        assert!(types[0].interfaces.is_empty());
    }

    #[test]
    fn clr_member_refs_stay_aligned_past_interface_rows() {
        // Two InterfaceImpl rows in front of two MemberRef rows; the names still line up.
        let mut tilde = tilde_header((1 << 9) | (1 << 10), &[2, 2]);
        for coded in [(1u16 << 2) | 1u16, (2u16 << 2) | 1u16] {
            tilde.extend_from_slice(&1u16.to_le_bytes());
            tilde.extend_from_slice(&coded.to_le_bytes());
        }
        for name in [1u16, 7u16] {
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&name.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
        }
        let mut strings = vec![0u8];
        strings.extend_from_slice(b"Write\0Read\0");
        let (file, streams) = with_strings(&tilde, &strings);
        let meta = read_metadata_names(&file, Some(0), &streams);
        assert_eq!(
            meta.member_refs,
            vec!["Write".to_string(), "Read".to_string()]
        );
    }

    #[test]
    fn clr_property_and_event_signatures_come_from_the_blob() {
        // TypeDef App owns Property Text and Event Tick. Property rows carry a blob index; Event rows carry a TypeDefOrRef.
        let mut tilde = tilde_header(
            (1 << 1) | (1 << 2) | (1 << 18) | (1 << 20) | (1 << 21) | (1 << 23),
            &[1, 1, 1, 1, 1, 1],
        );
        // TypeRef 1: IFace.
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&7u16.to_le_bytes());
        // TypeDef App.
        tilde.extend_from_slice(&0u32.to_le_bytes());
        tilde.extend_from_slice(&10u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        // EventMap points at TypeDef 1; PropertyMap points at TypeDef 1.
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        // Event row: flags, name, TypeRef 1.
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&14u16.to_le_bytes());
        tilde.extend_from_slice(&((1u16 << 2) | 1u16).to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        // Property row: flags, name, blob index 1.
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&19u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        let mut strings = vec![0u8];
        strings.extend_from_slice(b"IFace\0Ns\0App\0Tick\0Text\0");
        let mut file = tilde.clone();
        let strings_at = file.len() as u32;
        file.extend_from_slice(&strings);
        let blob_at = file.len() as u32;
        // Entry 1: length 3, static property, count 0 index params, int32.
        file.extend_from_slice(&[0x00, 0x03, 0x08, 0x00, 0x08]);
        let streams = vec![
            ClrStream {
                name: "#~".into(),
                offset: 0,
                size: strings_at,
            },
            ClrStream {
                name: "#Strings".into(),
                offset: strings_at,
                size: strings.len() as u32,
            },
            ClrStream {
                name: "#Blob".into(),
                offset: blob_at,
                size: 5,
            },
        ];
        let types = read_metadata_names(&file, Some(0), &streams).types;
        assert_eq!(
            types[1].properties,
            vec![ClrProperty {
                name: "Text".into(),
                signature: Some("int32()".into()),
            }]
        );
        assert_eq!(
            types[1].events,
            vec![ClrEvent {
                name: "Tick".into(),
                signature: Some("Ns.IFace".into()),
            }]
        );
    }

    #[test]
    fn clr_module_refs_are_names() {
        let mut tilde = tilde_header(1 << 26, &[1]);
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&5u16.to_le_bytes());
        let mut strings = vec![0u8];
        strings.extend_from_slice(b"helper\0");
        let (file, streams) = with_strings(&tilde, &strings);
        let meta = read_metadata_names(&file, Some(0), &streams);
        assert_eq!(meta.module_refs, vec!["helper".to_string()]);
    }

    #[test]
    fn clr_field_signature_from_the_blob() {
        // Field rows: flags, name, signature blob index. Blob index 0 stays empty.
        let mut tilde = tilde_header((1 << 2) | (1 << 4), &[1, 2]);
        tilde.extend_from_slice(&0u32.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&5u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&9u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        let mut strings = vec![0u8];
        strings.extend_from_slice(b"App\0Fld\0Blank\0");
        let mut file = tilde.clone();
        let strings_at = file.len() as u32;
        file.extend_from_slice(&strings);
        let blob_at = file.len() as u32;
        // Entry 1: length 2, field calling convention, int32.
        file.extend_from_slice(&[0x00, 0x02, 0x06, 0x08]);
        let streams = vec![
            ClrStream {
                name: "#~".into(),
                offset: 0,
                size: strings_at,
            },
            ClrStream {
                name: "#Strings".into(),
                offset: strings_at,
                size: strings.len() as u32,
            },
            ClrStream {
                name: "#Blob".into(),
                offset: blob_at,
                size: 4,
            },
        ];
        let types = read_metadata_names(&file, Some(0), &streams).types;
        assert_eq!(types[0].name, "App");
        assert_eq!(
            types[0].fields,
            vec![
                ClrField {
                    name: "Fld".into(),
                    signature: Some("field int32".into()),
                },
                ClrField {
                    name: "Blank".into(),
                    signature: None,
                },
            ]
        );
    }

    #[test]
    fn coff_timestamp_is_a_utc_date() {
        assert_eq!(unix_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(unix_utc(86_400), "1970-01-02T00:00:00Z");
    }

    #[test]
    fn clr_signature_assembly_and_property_names() {
        let mut tilde = tilde_header((1 << 2) | (1 << 6), &[1, 1]);
        tilde.extend_from_slice(&0u32.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&0u32.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&1u16.to_le_bytes());
        tilde.extend_from_slice(&0u16.to_le_bytes());
        let mut strings = vec![0u8];
        strings.extend_from_slice(b"Run\0");
        let mut file = tilde.clone();
        let strings_at = file.len() as u32;
        file.extend_from_slice(&strings);
        let blob_at = file.len() as u32;
        file.extend_from_slice(&[0x00, 0x04, 0x00, 0x01, 0x01, 0x08]);
        let streams = vec![
            ClrStream {
                name: "#~".into(),
                offset: 0,
                size: strings_at,
            },
            ClrStream {
                name: "#Strings".into(),
                offset: strings_at,
                size: strings.len() as u32,
            },
            ClrStream {
                name: "#Blob".into(),
                offset: blob_at,
                size: 6,
            },
        ];
        let types = read_metadata_names(&file, Some(0), &streams).types;
        assert_eq!(types[0].name, "Run");
        assert_eq!(types[0].methods[0].signature.as_deref(), Some("void(int32)"));
        assert!(types[0].methods[0].il.is_empty());

        let mut assembly = tilde_header(1 << 32, &[1]);
        assembly.extend_from_slice(&[0u8; 16]);
        assembly.extend_from_slice(&0u16.to_le_bytes());
        assembly.extend_from_slice(&1u16.to_le_bytes());
        assembly.extend_from_slice(&0u16.to_le_bytes());
        let mut names = vec![0u8];
        names.extend_from_slice(b"Demo\0");
        let (file, streams) = with_strings(&assembly, &names);
        let meta = read_metadata_names(&file, Some(0), &streams);
        assert_eq!(
            meta.assemblies,
            vec![ClrAssembly {
                major_version: 0,
                minor_version: 0,
                build_number: 0,
                revision_number: 0,
                name: "Demo".into(),
                culture: String::new(),
                public_key: None,
                hash_alg_id: Some(0),
                flags: 0,
                hash_value: None,
            }]
        );

        let mut assembly_ref = tilde_header(1u64 << 35, &[1]);
        assembly_ref.extend_from_slice(&[0u8; 12]);
        assembly_ref.extend_from_slice(&0u16.to_le_bytes());
        assembly_ref.extend_from_slice(&1u16.to_le_bytes());
        assembly_ref.extend_from_slice(&0u16.to_le_bytes());
        assembly_ref.extend_from_slice(&0u16.to_le_bytes());
        let (file, streams) = with_strings(&assembly_ref, &names);
        let meta = read_metadata_names(&file, Some(0), &streams);
        assert_eq!(
            meta.assembly_refs,
            vec![ClrAssembly {
                major_version: 0,
                minor_version: 0,
                build_number: 0,
                revision_number: 0,
                name: "Demo".into(),
                culture: String::new(),
                public_key: None,
                hash_alg_id: None,
                flags: 0,
                hash_value: None,
            }]
        );

        let mut props = tilde_header((1 << 2) | (1 << 21) | (1 << 23), &[1, 1, 1]);
        props.extend_from_slice(&0u32.to_le_bytes());
        props.extend_from_slice(&1u16.to_le_bytes());
        props.extend_from_slice(&0u16.to_le_bytes());
        props.extend_from_slice(&0u16.to_le_bytes());
        props.extend_from_slice(&1u16.to_le_bytes());
        props.extend_from_slice(&1u16.to_le_bytes());
        props.extend_from_slice(&1u16.to_le_bytes());
        props.extend_from_slice(&1u16.to_le_bytes());
        props.extend_from_slice(&0u16.to_le_bytes());
        props.extend_from_slice(&5u16.to_le_bytes());
        props.extend_from_slice(&0u16.to_le_bytes());
        let mut names = vec![0u8];
        names.extend_from_slice(b"App\0Text\0");
        let (file, streams) = with_strings(&props, &names);
        let types = read_metadata_names(&file, Some(0), &streams).types;
        assert_eq!(types[0].name, "App");
        assert_eq!(
            types[0].properties,
            vec![ClrProperty {
                name: "Text".into(),
                signature: None,
            }]
        );

        let mut events = tilde_header((1 << 2) | (1 << 18) | (1 << 20), &[1, 1, 1]);
        events.extend_from_slice(&0u32.to_le_bytes());
        events.extend_from_slice(&1u16.to_le_bytes());
        events.extend_from_slice(&0u16.to_le_bytes());
        events.extend_from_slice(&0u16.to_le_bytes());
        events.extend_from_slice(&1u16.to_le_bytes());
        events.extend_from_slice(&1u16.to_le_bytes());
        events.extend_from_slice(&1u16.to_le_bytes());
        events.extend_from_slice(&1u16.to_le_bytes());
        events.extend_from_slice(&0u16.to_le_bytes());
        events.extend_from_slice(&5u16.to_le_bytes());
        events.extend_from_slice(&0u16.to_le_bytes());
        let (file, streams) = with_strings(&events, &names);
        let types = read_metadata_names(&file, Some(0), &streams).types;
        assert_eq!(
            types[0].events,
            vec![ClrEvent {
                name: "Text".into(),
                signature: None,
            }]
        );
    }

    #[test]
    fn clr_type_names_need_the_string_heap() {
        let tilde = tilde_header(1, &[1]);
        let streams = vec![ClrStream {
            name: "#~".into(),
            offset: 0,
            size: tilde.len() as u32,
        }];
        assert!(read_metadata_names(&tilde, Some(0), &streams).types.is_empty());
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

    #[test]
    fn clr_assembly_row_carries_version_culture_and_public_key() {
        // Hash-algorithm id, 1.2.3.4, flags, public-key blob index 1, name, culture.
        let mut assembly = tilde_header(1u64 << 32, &[1]);
        assembly.extend_from_slice(&0u32.to_le_bytes());
        assembly.extend_from_slice(&1u16.to_le_bytes());
        assembly.extend_from_slice(&2u16.to_le_bytes());
        assembly.extend_from_slice(&3u16.to_le_bytes());
        assembly.extend_from_slice(&4u16.to_le_bytes());
        assembly.extend_from_slice(&0u32.to_le_bytes());
        assembly.extend_from_slice(&1u16.to_le_bytes());
        assembly.extend_from_slice(&1u16.to_le_bytes());
        assembly.extend_from_slice(&6u16.to_le_bytes());
        let mut names = vec![0u8];
        names.extend_from_slice(b"Demo\0en-US\0");
        let mut blobs = vec![0u8];
        blobs.extend_from_slice(&[4, 0xde, 0xad, 0xbe, 0xef]);
        let (file, streams) = with_blobs(&assembly, &names, &blobs);
        let meta = read_metadata_names(&file, Some(0), &streams);
        assert_eq!(
            meta.assemblies,
            vec![ClrAssembly {
                major_version: 1,
                minor_version: 2,
                build_number: 3,
                revision_number: 4,
                name: "Demo".into(),
                culture: "en-US".into(),
                public_key: Some(ClrBlob {
                    len: 4,
                    hex: "deadbeef".into(),
                }),
                hash_alg_id: Some(0),
                flags: 0,
                hash_value: None,
            }]
        );
    }

    #[test]
    fn clr_assembly_ref_row_carries_token_and_versions() {
        let mut assembly_ref = tilde_header(1u64 << 35, &[1]);
        assembly_ref.extend_from_slice(&5u16.to_le_bytes());
        assembly_ref.extend_from_slice(&6u16.to_le_bytes());
        assembly_ref.extend_from_slice(&7u16.to_le_bytes());
        assembly_ref.extend_from_slice(&8u16.to_le_bytes());
        assembly_ref.extend_from_slice(&0u32.to_le_bytes());
        assembly_ref.extend_from_slice(&1u16.to_le_bytes());
        assembly_ref.extend_from_slice(&1u16.to_le_bytes());
        assembly_ref.extend_from_slice(&0u16.to_le_bytes());
        assembly_ref.extend_from_slice(&0u16.to_le_bytes());
        let mut names = vec![0u8];
        names.extend_from_slice(b"Demo\0");
        // 40-byte blob under the two-byte length form; hex caps at 32 bytes.
        let mut blobs = vec![0u8];
        blobs.push(0x80);
        blobs.push(40);
        blobs.extend(0u8..40);
        let (file, streams) = with_blobs(&assembly_ref, &names, &blobs);
        let meta = read_metadata_names(&file, Some(0), &streams);
        let reference = &meta.assembly_refs[0];
        assert_eq!(
            (
                reference.major_version,
                reference.minor_version,
                reference.build_number,
                reference.revision_number
            ),
            (5, 6, 7, 8)
        );
        assert_eq!(reference.name, "Demo");
        assert_eq!(reference.culture, "");
        let key = reference.public_key.as_ref().unwrap();
        assert_eq!(key.len, 40);
        assert_eq!(key.hex.len(), 64);
        assert!(key.hex.starts_with("0001020304"));
        assert!(key.hex.ends_with("1f"));
        assert_eq!(reference.flags, 0);
        assert_eq!(reference.hash_alg_id, None);
        assert_eq!(reference.hash_value, None);
    }

    #[test]
    fn clr_assembly_row_carries_hash_id_and_flags() {
        // Hash-algorithm id 0x2404, 1.2.3.4, flags 1, no public key, name, culture.
        let mut assembly = tilde_header(1u64 << 32, &[1]);
        assembly.extend_from_slice(&0x2404u32.to_le_bytes());
        assembly.extend_from_slice(&1u16.to_le_bytes());
        assembly.extend_from_slice(&2u16.to_le_bytes());
        assembly.extend_from_slice(&3u16.to_le_bytes());
        assembly.extend_from_slice(&4u16.to_le_bytes());
        assembly.extend_from_slice(&1u32.to_le_bytes());
        assembly.extend_from_slice(&0u16.to_le_bytes());
        assembly.extend_from_slice(&1u16.to_le_bytes());
        assembly.extend_from_slice(&0u16.to_le_bytes());
        let mut names = vec![0u8];
        names.extend_from_slice(b"Demo\0");
        let (file, streams) = with_strings(&assembly, &names);
        let meta = read_metadata_names(&file, Some(0), &streams);
        let row = &meta.assemblies[0];
        assert_eq!(row.hash_alg_id, Some(0x2404));
        assert_eq!(row.flags, 1);
        assert_eq!(row.public_key, None);
        assert_eq!(row.hash_value, None);
    }

    #[test]
    fn clr_assembly_ref_row_carries_flags_and_hash_value() {
        // Two AssemblyRef rows: flags 0x200, name, and a HashValue blob index 1 on the
        // first; a HashValue blob index 0 on the second.
        let mut assembly_ref = tilde_header(1u64 << 35, &[2]);
        for hash_index in [1u16, 0] {
            assembly_ref.extend_from_slice(&1u16.to_le_bytes());
            assembly_ref.extend_from_slice(&2u16.to_le_bytes());
            assembly_ref.extend_from_slice(&3u16.to_le_bytes());
            assembly_ref.extend_from_slice(&4u16.to_le_bytes());
            assembly_ref.extend_from_slice(&0x200u32.to_le_bytes());
            assembly_ref.extend_from_slice(&0u16.to_le_bytes());
            assembly_ref.extend_from_slice(&1u16.to_le_bytes());
            assembly_ref.extend_from_slice(&0u16.to_le_bytes());
            assembly_ref.extend_from_slice(&hash_index.to_le_bytes());
        }
        let mut names = vec![0u8];
        names.extend_from_slice(b"Demo\0");
        let mut blobs = vec![0u8];
        blobs.extend_from_slice(&[2, 0xAA, 0xBB]);
        let (file, streams) = with_blobs(&assembly_ref, &names, &blobs);
        let meta = read_metadata_names(&file, Some(0), &streams);
        assert_eq!(meta.assembly_refs.len(), 2);
        let first = &meta.assembly_refs[0];
        assert_eq!(first.flags, 0x200);
        assert_eq!(first.hash_alg_id, None);
        assert_eq!(
            first.hash_value,
            Some(ClrBlob {
                len: 2,
                hex: "aabb".into(),
            })
        );
        assert_eq!(meta.assembly_refs[1].hash_value, None);
        assert_eq!(meta.assembly_refs[1].name, "Demo");
    }

    #[test]
    fn clr_four_byte_blob_length_counts_the_first_byte() {
        // ECMA-335 II.24.2.4: a first byte >= 0xC0 starts a four-byte
        // little-endian... big-endian length covering the first byte, masked
        // to 29 bits. [00, C0, 00, 00, 01, AA] at index 1 is a length of 1
        // with payload AA; skipping the first byte would read 0x1AA and
        // drop the blob.
        let mut assembly = tilde_header(1u64 << 32, &[1]);
        assembly.extend_from_slice(&0u32.to_le_bytes());
        assembly.extend_from_slice(&1u16.to_le_bytes());
        assembly.extend_from_slice(&2u16.to_le_bytes());
        assembly.extend_from_slice(&3u16.to_le_bytes());
        assembly.extend_from_slice(&4u16.to_le_bytes());
        assembly.extend_from_slice(&0u32.to_le_bytes());
        assembly.extend_from_slice(&1u16.to_le_bytes());
        assembly.extend_from_slice(&1u16.to_le_bytes());
        assembly.extend_from_slice(&0u16.to_le_bytes());
        let mut names = vec![0u8];
        names.extend_from_slice(b"Demo\0");
        let mut blobs = vec![0u8];
        blobs.extend_from_slice(&[0xC0, 0x00, 0x00, 0x01, 0xAA]);
        let (file, streams) = with_blobs(&assembly, &names, &blobs);
        let meta = read_metadata_names(&file, Some(0), &streams);
        assert_eq!(
            meta.assemblies[0].public_key,
            Some(ClrBlob {
                len: 1,
                hex: "aa".into(),
            })
        );
    }

    #[test]
    fn clr_four_byte_blob_length_reads_a_16384_byte_blob() {
        // The only legal encoding of a 16384-byte blob is C0 00 40 00 plus
        // the payload; the old skip-first-byte decode inflated the length
        // and returned None.
        let mut assembly = tilde_header(1u64 << 32, &[1]);
        assembly.extend_from_slice(&0u32.to_le_bytes());
        assembly.extend_from_slice(&1u16.to_le_bytes());
        assembly.extend_from_slice(&2u16.to_le_bytes());
        assembly.extend_from_slice(&3u16.to_le_bytes());
        assembly.extend_from_slice(&4u16.to_le_bytes());
        assembly.extend_from_slice(&0u32.to_le_bytes());
        assembly.extend_from_slice(&1u16.to_le_bytes());
        assembly.extend_from_slice(&1u16.to_le_bytes());
        assembly.extend_from_slice(&0u16.to_le_bytes());
        let mut names = vec![0u8];
        names.extend_from_slice(b"Demo\0");
        let mut blobs = vec![0u8];
        blobs.extend_from_slice(&[0xC0, 0x00, 0x40, 0x00]);
        blobs.extend_from_slice(&vec![0x77u8; 16384]);
        let (file, streams) = with_blobs(&assembly, &names, &blobs);
        let meta = read_metadata_names(&file, Some(0), &streams);
        let key = meta.assemblies[0].public_key.as_ref().unwrap();
        assert_eq!(key.len, 16384);
        assert_eq!(key.hex, "77".repeat(32));
    }

    #[test]
    fn clr_blob_index_zero_or_past_the_heap_stays_empty() {
        // Two Assembly rows: blob index 0, then an index past the heap. Names still read.
        let mut assembly = tilde_header(1u64 << 32, &[2]);
        assembly.extend_from_slice(&[0u8; 16]);
        assembly.extend_from_slice(&0u16.to_le_bytes());
        assembly.extend_from_slice(&1u16.to_le_bytes());
        assembly.extend_from_slice(&0u16.to_le_bytes());
        assembly.extend_from_slice(&[0u8; 16]);
        assembly.extend_from_slice(&9u16.to_le_bytes());
        assembly.extend_from_slice(&1u16.to_le_bytes());
        assembly.extend_from_slice(&0u16.to_le_bytes());
        let mut names = vec![0u8];
        names.extend_from_slice(b"Demo\0");
        // Blob at index 1 claims 4 bytes but carries 1.
        let mut blobs = vec![0u8];
        blobs.extend_from_slice(&[4, 0x01]);
        let (file, streams) = with_blobs(&assembly, &names, &blobs);
        let meta = read_metadata_names(&file, Some(0), &streams);
        assert_eq!(meta.assemblies.len(), 2);
        assert!(meta.assemblies[0].public_key.is_none());
        assert!(meta.assemblies[1].public_key.is_none());
        assert_eq!(meta.assemblies[0].name, "Demo");
        assert_eq!(meta.assemblies[1].name, "Demo");
    }

}