//! PE data directories, CLR header presence, and root resource type ids.

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
    /// Root resource-directory type ids (the low 16 bits) when the entry is an integer id. Named entries are skipped. Empty if there is no resource directory.
    pub resource_type_ids: Vec<u32>,
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

pub fn facts(bytes: &[u8]) -> Result<PeFacts> {
    let pe = goblin::pe::PE::parse(bytes).map_err(|e| Error::Parse(format!("pe: {e}")))?;
    let Some(optional) = pe.header.optional_header else {
        return Ok(PeFacts {
            directories: Vec::new(),
            has_clr: false,
            resource_type_ids: Vec::new(),
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
    let has_clr = optional
        .data_directories
        .get_clr_runtime_header()
        .is_some_and(|dir| dir.size != 0 || dir.virtual_address != 0);
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

    Ok(PeFacts {
        directories,
        has_clr,
        resource_type_ids,
    })
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
}
