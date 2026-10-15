//! PE data directories, CLR runtime header, CodeView PDB path, and resource type, name, and language ids.

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
    /// Resource directory through the language id. Integer ids are decimal strings. Named entries are UTF-16. Resource bytes are not read.
    pub resources: Vec<PeResource>,
    /// First CodeView PDB 7.0 or 2.0 record in the debug directory. Other debug types are skipped. `None` when the directory is absent, unmapped, or has no CodeView path.
    pub pdb: Option<PePdb>,
}

/// One resource type, the names under it, and the language id under each name.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PeResource {
    /// Integer type id as a decimal string, or the UTF-16 name when the root entry is named.
    pub ty: String,
    /// Name level. Integer ids are decimal strings. Named entries are UTF-16.
    pub names: Vec<PeResourceName>,
}

/// One resource name and the language ids under it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PeResourceName {
    /// Integer id as a decimal string, or the UTF-16 name.
    pub name: String,
    /// Language ids. The data entry under each id is not read.
    pub languages: Vec<String>,
}

/// A CodeView PDB filename from the debug directory.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PePdb {
    pub path: String,
    /// PDB 7.0 GUID, `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`. PDB 2.0 has none.
    pub guid: Option<String>,
    pub age: u32,
}

/// Leading `IMAGE_COR20_HEADER` fields, the BSJB version string, metadata stream headers, table row counts, and type, field, method, parameter, and member-ref names.
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
    /// Names from `Module`, `TypeRef`, and `TypeDef`, with `Field` and `MethodDef` names on each `TypeDef` and `Param` names on each method. Empty when the string heap or those rows are missing. Other table rows and IL are not read.
    pub types: Vec<ClrType>,
    /// `MemberRef` names, in table order. Empty when that table or the string heap is missing. Parent indexes and signatures are not read.
    pub member_refs: Vec<String>,
}

/// A type or module name from the metadata tables.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ClrType {
    /// `Module`, `TypeRef`, or `TypeDef`.
    pub table: String,
    pub namespace: String,
    pub name: String,
    /// `Field` names owned by a `TypeDef`, in table order. Empty for `Module` and `TypeRef`. Signatures are not read.
    pub fields: Vec<String>,
    /// `MethodDef` rows owned by a `TypeDef`, in table order. Empty for `Module` and `TypeRef`. Signatures and IL are not read.
    pub methods: Vec<ClrMethod>,
}

/// A method name and the `Param` names it owns.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ClrMethod {
    pub name: String,
    /// `Param` names in table order. Sequence numbers and the signature are not read.
    pub params: Vec<String>,
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
/// A language-level offset is not followed, so a further directory and the resource bytes stay unread. A short directory or a short name is an error.
pub(crate) fn resource_tree(dir: &[u8]) -> Result<Vec<PeResource>> {
    let mut out = Vec::new();
    for entry in directory_entries(dir, 0)? {
        out.push(PeResource {
            ty: entry_label(dir, entry.name_or_id)?,
            names: named_children(dir, entry.offset)?,
        });
    }
    Ok(out)
}

fn named_children(dir: &[u8], offset: u32) -> Result<Vec<PeResourceName>> {
    if offset & 0x8000_0000 == 0 {
        return Ok(Vec::new());
    }
    let sub = (offset & 0x7fff_ffff) as usize;
    let mut names = Vec::new();
    for child in directory_entries(dir, sub)? {
        names.push(PeResourceName {
            name: entry_label(dir, child.name_or_id)?,
            languages: directory_labels(dir, child.offset)?,
        });
    }
    Ok(names)
}

/// Labels in the directory `offset` points at. Each entry's own offset is ignored.
fn directory_labels(dir: &[u8], offset: u32) -> Result<Vec<String>> {
    if offset & 0x8000_0000 == 0 {
        return Ok(Vec::new());
    }
    let sub = (offset & 0x7fff_ffff) as usize;
    let mut labels = Vec::new();
    for child in directory_entries(dir, sub)? {
        labels.push(entry_label(dir, child.name_or_id)?);
    }
    Ok(labels)
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
    let (types, member_refs) = read_metadata_names(file, metadata_off, &streams);
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
        types,
        member_refs,
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

fn metadata_type_names(
    file: &[u8],
    metadata_off: Option<usize>,
    streams: &[ClrStream],
) -> Vec<ClrType> {
    read_metadata_names(file, metadata_off, streams).0
}

/// `Module`, `TypeRef`, and `TypeDef` names, plus `Field` and `MethodDef` names on each `TypeDef`, `Param` names on each method, and `MemberRef` names.
///
/// `FieldPtr`, `MethodPtr`, `ParamPtr`, and `InterfaceImpl` are skipped by row size. The pointer tables are not applied. String, blob, and coded-index widths follow the `#~` heap-size byte and the row counts. A row that does not fit ends the list and keeps the names already read. Signatures, RVAs, parameter sequence numbers, and IL are not read.
fn read_metadata_names(
    file: &[u8],
    metadata_off: Option<usize>,
    streams: &[ClrStream],
) -> (Vec<ClrType>, Vec<String>) {
    let Some(root) = metadata_off else {
        return (Vec::new(), Vec::new());
    };
    let Some(blob) = stream_bytes(file, root, streams, "#~")
        .or_else(|| stream_bytes(file, root, streams, "#-"))
    else {
        return (Vec::new(), Vec::new());
    };
    let Some(strings) = stream_bytes(file, root, streams, "#Strings") else {
        return (Vec::new(), Vec::new());
    };
    if blob.len() < 24 {
        return (Vec::new(), Vec::new());
    }
    let valid = u64::from_le_bytes(blob[8..16].try_into().unwrap());
    let count = valid.count_ones() as usize;
    let Some(header_end) = count.checked_mul(4).and_then(|n| n.checked_add(24)) else {
        return (Vec::new(), Vec::new());
    };
    if blob.len() < header_end {
        return (Vec::new(), Vec::new());
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
    let extends_w = coded_width(typedef_rows.max(typeref_rows).max(rows_at(blob, valid, 27)), 2);
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
    let interface_size = index_width(typedef_rows) + extends_w;
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
    // Index into `out`, then the 1-based FieldList and MethodList for each TypeDef.
    let mut typedefs: Vec<(usize, u32, u32)> = Vec::new();
    // Method name and its 1-based ParamList, in MethodDef order.
    let mut method_recs: Vec<(String, u32)> = Vec::new();
    let mut params_attached = false;
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
                        return (out, member_refs);
                    };
                    if end > blob.len() {
                        return (out, member_refs);
                    }
                    let row = &blob[cursor..end];
                    let (namespace, name) = match bit {
                        0 => (String::new(), heap_string(strings, read_index(row, 2, str_w))),
                        1 => (
                            heap_string(strings, read_index(row, scope_w + str_w, str_w)),
                            heap_string(strings, read_index(row, scope_w, str_w)),
                        ),
                        _ => (
                            heap_string(strings, read_index(row, 4 + str_w, str_w)),
                            heap_string(strings, read_index(row, 4, str_w)),
                        ),
                    };
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
                    });
                    cursor = end;
                }
            }
            3 | 5 => {
                let (rows, size) = if bit == 3 {
                    (rows_at(blob, valid, 3), field_w)
                } else {
                    (rows_at(blob, valid, 5), method_w)
                };
                if !skip_rows(blob, &mut cursor, rows, size) {
                    return (out, member_refs);
                }
            }
            4 => {
                let mut names = Vec::new();
                for _ in 0..field_rows {
                    let Some(end) = cursor.checked_add(field_size) else {
                        attach_field_names(&mut out, &typedefs, &names);
                        return (out, member_refs);
                    };
                    if end > blob.len() {
                        attach_field_names(&mut out, &typedefs, &names);
                        return (out, member_refs);
                    }
                    let row = &blob[cursor..end];
                    names.push(heap_string(strings, read_index(row, 2, str_w)));
                    cursor = end;
                }
                attach_field_names(&mut out, &typedefs, &names);
            }
            6 => {
                for _ in 0..method_rows {
                    let Some(end) = cursor.checked_add(method_size) else {
                        attach_methods(&mut out, &typedefs, &method_recs, &[]);
                        return (out, member_refs);
                    };
                    if end > blob.len() {
                        attach_methods(&mut out, &typedefs, &method_recs, &[]);
                        return (out, member_refs);
                    }
                    let row = &blob[cursor..end];
                    method_recs.push((
                        heap_string(strings, read_index(row, 8, str_w)),
                        read_index(row, param_list_at, param_w),
                    ));
                    cursor = end;
                }
            }
            7 => {
                let rows = rows_at(blob, valid, 7);
                if !skip_rows(blob, &mut cursor, rows, param_w) {
                    attach_methods(&mut out, &typedefs, &method_recs, &[]);
                    return (out, member_refs);
                }
            }
            8 => {
                let mut names = Vec::new();
                for _ in 0..param_rows {
                    let Some(end) = cursor.checked_add(param_size) else {
                        attach_methods(&mut out, &typedefs, &method_recs, &names);
                        return (out, member_refs);
                    };
                    if end > blob.len() {
                        attach_methods(&mut out, &typedefs, &method_recs, &names);
                        return (out, member_refs);
                    }
                    let row = &blob[cursor..end];
                    names.push(heap_string(strings, read_index(row, 4, str_w)));
                    cursor = end;
                }
                attach_methods(&mut out, &typedefs, &method_recs, &names);
                params_attached = true;
            }
            9 => {
                let rows = rows_at(blob, valid, 9);
                if !skip_rows(blob, &mut cursor, rows, interface_size) {
                    if !params_attached {
                        attach_methods(&mut out, &typedefs, &method_recs, &[]);
                    }
                    return (out, member_refs);
                }
            }
            _ => {
                let rows = rows_at(blob, valid, 10);
                for _ in 0..rows {
                    let Some(end) = cursor.checked_add(member_size) else {
                        if !params_attached {
                            attach_methods(&mut out, &typedefs, &method_recs, &[]);
                        }
                        return (out, member_refs);
                    };
                    if end > blob.len() {
                        if !params_attached {
                            attach_methods(&mut out, &typedefs, &method_recs, &[]);
                        }
                        return (out, member_refs);
                    }
                    let row = &blob[cursor..end];
                    member_refs.push(heap_string(
                        strings,
                        read_index(row, member_parent_w, str_w),
                    ));
                    cursor = end;
                }
            }
        }
    }
    if !params_attached {
        attach_methods(&mut out, &typedefs, &method_recs, &[]);
    }
    (out, member_refs)
}

/// `FieldList` is 1-based. Each TypeDef owns names up to the next list, or the end of `Field`.
fn attach_field_names(out: &mut [ClrType], typedefs: &[(usize, u32, u32)], names: &[String]) {
    let lists: Vec<u32> = typedefs.iter().map(|row| row.1).collect();
    for (index, &(at, _, _)) in typedefs.iter().enumerate() {
        let (start, end) = list_span(&lists, index, names.len());
        out[at].fields = names[start..end].to_vec();
    }
}

/// `MethodList` and `ParamList` are 1-based. Each method owns parameter names up to the next list.
fn attach_methods(
    out: &mut [ClrType],
    typedefs: &[(usize, u32, u32)],
    recs: &[(String, u32)],
    param_names: &[String],
) {
    let param_lists: Vec<u32> = recs.iter().map(|rec| rec.1).collect();
    let methods: Vec<ClrMethod> = recs
        .iter()
        .enumerate()
        .map(|(index, (name, _))| {
            let (start, end) = list_span(&param_lists, index, param_names.len());
            ClrMethod {
                name: name.clone(),
                params: param_names[start..end].to_vec(),
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

fn skip_rows(blob: &[u8], cursor: &mut usize, rows: u32, size: usize) -> bool {
    let Some(total) = usize::try_from(rows).ok().and_then(|rows| rows.checked_mul(size)) else {
        return false;
    };
    let Some(end) = cursor.checked_add(total) else {
        return false;
    };
    if end > blob.len() {
        return false;
    }
    *cursor = end;
    true
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

pub fn facts(bytes: &[u8]) -> Result<PeFacts> {
    let pe = goblin::pe::PE::parse(bytes).map_err(|e| Error::Parse(format!("pe: {e}")))?;
    let Some(optional) = pe.header.optional_header else {
        return Ok(PeFacts {
            directories: Vec::new(),
            has_clr: false,
            clr: None,
            resource_type_ids: Vec::new(),
            resources: Vec::new(),
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
            (resource_type_ids(blob)?, resource_tree(blob)?)
        } else {
            (Vec::new(), Vec::new())
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
        resources,
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
    fn resource_languages_stop_before_the_data() {
        let tree = resource_tree(&resource_name_fixture()).unwrap();
        assert_eq!(
            tree,
            vec![
                PeResource {
                    ty: "VER".into(),
                    names: vec![res_name("2", &[])],
                },
                PeResource {
                    ty: "16".into(),
                    names: vec![res_name("App", &[]), res_name("1", &["1033"])],
                },
            ]
        );
        assert_eq!(resource_type_ids(&resource_name_fixture()).unwrap(), vec![16]);
    }

    fn res_name(name: &str, languages: &[&str]) -> PeResourceName {
        PeResourceName {
            name: name.into(),
            languages: languages.iter().map(|lang| (*lang).to_string()).collect(),
        }
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
    /// `1` has language id 1033. That entry points at a directory whose id is 9999, which must stay unread.
    fn resource_name_fixture() -> Vec<u8> {
        let mut dir = vec![0u8; 164];
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
        dir[104 + 14] = 1;
        write_res_entry(&mut dir, 120, 1033, 0x8000_0000 | 140);
        dir[140 + 14] = 1;
        write_res_entry(&mut dir, 156, 9999, 0);
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
        let types = metadata_type_names(&file, Some(0), &streams);
        assert_eq!(
            types,
            vec![
                ClrType {
                    table: "Module".into(),
                    namespace: "".into(),
                    name: "Hello".into(),
                    fields: vec![],
                    methods: vec![],
                },
                ClrType {
                    table: "TypeDef".into(),
                    namespace: "World".into(),
                    name: "App".into(),
                    fields: vec![],
                    methods: vec![],
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
        let types = metadata_type_names(&file, Some(0), &streams);
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
        let types = metadata_type_names(&file, Some(0), &streams);
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
        assert_eq!(types[1].fields, vec!["Fld".to_string()]);
    }

    #[test]
    fn clr_typedef_fields_follow_the_field_list() {
        // FieldPtr sits between TypeDef and Field. Its one index is skipped, not applied.
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
        let types = metadata_type_names(&file, Some(0), &streams);
        assert_eq!(types[0].name, "App");
        assert_eq!(types[0].namespace, "Ns");
        assert_eq!(types[0].fields, vec!["Fld".to_string()]);
        assert_eq!(types[0].methods, vec![clr_method("Run", &[])]);
        assert_eq!(types[1].name, "Other");
        assert_eq!(types[1].fields, vec!["More".to_string()]);
        assert_eq!(types[1].methods, vec![clr_method("Done", &[])]);
    }

    #[test]
    fn clr_method_params_skip_the_param_ptr_row() {
        // ParamPtr sits between MethodDef and Param. Its one index is skipped, not applied.
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
        for name in [17u16, 19u16, 21u16] {
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&0u16.to_le_bytes());
            tilde.extend_from_slice(&name.to_le_bytes());
        }
        let mut strings = vec![0u8];
        strings.extend_from_slice(b"App\0Ns\0Run\0Stop\0a\0b\0c\0");
        let (file, streams) = with_strings(&tilde, &strings);
        let types = metadata_type_names(&file, Some(0), &streams);
        assert_eq!(types[0].name, "App");
        assert_eq!(types[0].namespace, "Ns");
        assert_eq!(
            types[0].methods,
            vec![
                clr_method("Run", &["a", "b"]),
                clr_method("Stop", &["c"])
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
        let (types, refs) = read_metadata_names(&file, Some(0), &streams);
        assert!(types.is_empty());
        assert_eq!(refs, vec!["Write".to_string(), "Read".to_string()]);
    }

    fn clr_method(name: &str, params: &[&str]) -> ClrMethod {
        ClrMethod {
            name: name.to_string(),
            params: params.iter().map(|param| (*param).to_string()).collect(),
        }
    }

    #[test]
    fn clr_type_names_need_the_string_heap() {
        let tilde = tilde_header(1, &[1]);
        let streams = vec![ClrStream {
            name: "#~".into(),
            offset: 0,
            size: tilde.len() as u32,
        }];
        assert!(metadata_type_names(&tilde, Some(0), &streams).is_empty());
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
