//! Load-command facts for one Mach-O slice, plus fat-archive architecture headers.

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MachoFacts {
    pub dylibs: Vec<String>,
    pub uuid: Option<String>,     // lowercase hex, 32 chars, no dashes
    pub platform: Option<String>, // "macos", "ios", "tvos", "watchos", "bridgeos", or "platform-{n}"
    pub minos: Option<String>,    // "x.y.z" from LC_BUILD_VERSION
    pub sdk: Option<String>,
    pub has_code_signature: bool,
    /// Code-directory identifier, hash type, and team id. `None` when the load command is absent or the code directory does not fit. The CMS blob and the hash slots are not read.
    pub signature: Option<MachoSignature>,
}

/// The Mach-O code directory inside `LC_CODE_SIGNATURE`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MachoSignature {
    /// Identifier string from the code directory.
    pub identifier: String,
    /// `sha1`, `sha256`, `sha256-truncated`, `sha384`, `none`, or `hash-{n}`.
    pub hash_type: String,
    /// Team id when the code directory version is at least `0x20200` and `teamOffset` is set.
    pub team_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MachoArch {
    pub cpu: String, // "arm64", "x86_64", "arm", "x86", or "cpu-{n}"
    pub offset: u64,
    pub size: u64,
}

/// Parse one Mach-O slice (not a fat archive). Fat input returns Error::Parse.
pub fn facts(bytes: &[u8]) -> Result<MachoFacts> {
    let mo =
        goblin::mach::MachO::parse(bytes, 0).map_err(|e| Error::Parse(format!("mach-o: {e}")))?;
    let uuid = mo.load_commands.iter().find_map(|cmd| match &cmd.command {
        goblin::mach::load_command::CommandVariant::Uuid(uuid_cmd) => {
            Some(uuid_cmd.uuid.iter().map(|b| format!("{b:02x}")).collect())
        }
        _ => None,
    });
    let build = mo.load_commands.iter().find_map(|cmd| match &cmd.command {
        goblin::mach::load_command::CommandVariant::BuildVersion(cmd) => Some(*cmd),
        _ => None,
    });
    let (platform, minos, sdk) = match build {
        Some(cmd) => (
            Some(platform_name(cmd.platform)),
            Some(version_xyz(cmd.minos)),
            Some(version_xyz(cmd.sdk)),
        ),
        None => (None, None, None),
    };
    let has_code_signature = mo.load_commands.iter().any(|cmd| {
        matches!(
            &cmd.command,
            goblin::mach::load_command::CommandVariant::CodeSignature(_)
        )
    });
    let signature = mo.load_commands.iter().find_map(|cmd| match &cmd.command {
        goblin::mach::load_command::CommandVariant::CodeSignature(linkedit) => {
            code_directory(bytes, linkedit.dataoff, linkedit.datasize)
        }
        _ => None,
    });
    Ok(MachoFacts {
        dylibs: mo.libs.iter().map(|lib| (*lib).to_string()).collect(),
        uuid,
        platform,
        minos,
        sdk,
        has_code_signature,
        signature,
    })
}

const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CSSLOT_CODEDIRECTORY: u32 = 0;
const CODE_DIRECTORY_BASE: usize = 44;
const TEAM_OFFSET_FIELD: usize = 48;

/// Identifier, hash type, and team id from the first code directory.
///
/// A missing blob, a bad magic, or a short directory is `None` and does not fail the Mach-O parse. Slot `0x10000` and the hash slots are not read.
fn code_directory(bytes: &[u8], dataoff: u32, datasize: u32) -> Option<MachoSignature> {
    let start = dataoff as usize;
    let end = start.checked_add(datasize as usize)?;
    let blob = bytes.get(start..end)?;
    let length = be_u32(blob, 4)? as usize;
    if be_u32(blob, 0)? != CSMAGIC_EMBEDDED_SIGNATURE || length > blob.len() || length < 12 {
        return None;
    }
    let count = be_u32(blob, 8)? as usize;
    let index_end = 12usize.checked_add(count.checked_mul(8)?)?;
    if index_end > length {
        return None;
    }
    let cd_off = (0..count).find_map(|i| {
        let at = 12 + i * 8;
        let ty = be_u32(blob, at)?;
        let off = be_u32(blob, at + 4)? as usize;
        (ty == CSSLOT_CODEDIRECTORY).then_some(off)
    })?;
    if cd_off.checked_add(CODE_DIRECTORY_BASE)? > length {
        return None;
    }
    let cd = &blob[cd_off..length];
    if be_u32(cd, 0)? != CSMAGIC_CODEDIRECTORY {
        return None;
    }
    let cd_len = be_u32(cd, 4)? as usize;
    if cd_len < CODE_DIRECTORY_BASE || cd_len > cd.len() {
        return None;
    }
    let version = be_u32(cd, 8)?;
    let ident_off = be_u32(cd, 20)? as usize;
    let identifier = cstr_at(cd, cd_len, ident_off)?;
    let team_id = if version >= 0x20200 && cd_len >= TEAM_OFFSET_FIELD + 4 {
        let team_off = be_u32(cd, TEAM_OFFSET_FIELD)? as usize;
        if team_off == 0 {
            None
        } else {
            cstr_at(cd, cd_len, team_off)
        }
    } else {
        None
    };
    Some(MachoSignature {
        identifier,
        hash_type: hash_name(cd[37]),
        team_id,
    })
}

fn be_u32(buf: &[u8], at: usize) -> Option<u32> {
    let raw = buf.get(at..at + 4)?;
    Some(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn cstr_at(buf: &[u8], limit: usize, off: usize) -> Option<String> {
    if off >= limit || off > buf.len() {
        return None;
    }
    let end = buf[off..limit]
        .iter()
        .position(|b| *b == 0)
        .map(|i| off + i)
        .unwrap_or(limit);
    if end - off > 256 {
        return None;
    }
    std::str::from_utf8(&buf[off..end])
        .ok()
        .map(str::to_string)
}

fn hash_name(hash_type: u8) -> String {
    match hash_type {
        0 => "none".to_string(),
        1 => "sha1".to_string(),
        2 => "sha256".to_string(),
        3 => "sha256-truncated".to_string(),
        4 => "sha384".to_string(),
        n => format!("hash-{n}"),
    }
}

/// Architecture headers from the original file, which may be a fat archive.
/// Fat slices themselves are not parsed.
pub fn architectures(bytes: &[u8]) -> Result<Vec<MachoArch>> {
    match goblin::mach::Mach::parse(bytes).map_err(|e| Error::Parse(format!("mach-o: {e}")))? {
        goblin::mach::Mach::Fat(multi) => {
            let arches = multi
                .arches()
                .map_err(|e| Error::Parse(format!("mach-o: {e}")))?;
            Ok(arches
                .into_iter()
                .map(|arch| {
                    let goblin::mach::fat::FatArch {
                        cputype,
                        offset,
                        size,
                        ..
                    } = arch;
                    MachoArch {
                        cpu: cpu_name(cputype),
                        offset: u64::from(offset),
                        size: u64::from(size),
                    }
                })
                .collect())
        }
        goblin::mach::Mach::Binary(mo) => Ok(vec![MachoArch {
            cpu: cpu_name(mo.header.cputype()),
            offset: 0,
            size: bytes.len() as u64,
        }]),
    }
}

fn platform_name(platform: u32) -> String {
    match platform {
        1 => "macos".to_string(),
        2 => "ios".to_string(),
        3 => "tvos".to_string(),
        4 => "watchos".to_string(),
        5 => "bridgeos".to_string(),
        n => format!("platform-{n}"),
    }
}

/// `xxxx.yy.zz` packed as `(major << 16) | (minor << 8) | patch`.
fn version_xyz(value: u32) -> String {
    let major = value >> 16;
    let minor = (value >> 8) & 0xff;
    let patch = value & 0xff;
    format!("{major}.{minor}.{patch}")
}

fn cpu_name(cputype: u32) -> String {
    match cputype {
        0x0100_000c => "arm64".to_string(),
        0x0100_0007 => "x86_64".to_string(),
        12 => "arm".to_string(),
        7 => "x86".to_string(),
        n => format!("cpu-{n}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_macho() {
        assert!(facts(b"not a macho").is_err());
    }

    #[test]
    fn rejects_fat_archive() {
        let err = facts(&[0xca, 0xfe, 0xba, 0xbe]).unwrap_err();
        assert!(matches!(err, Error::Parse(_)));
    }

    #[test]
    fn reads_fat_arch_header_without_slice_bytes() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xcafe_babe_u32.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&0x0100_000c_u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&0x4000u32.to_be_bytes());
        bytes.extend_from_slice(&0x100u32.to_be_bytes());
        bytes.extend_from_slice(&14u32.to_be_bytes());
        assert_eq!(
            architectures(&bytes).unwrap(),
            vec![MachoArch {
                cpu: "arm64".into(),
                offset: 0x4000,
                size: 0x100,
            }]
        );
    }

    #[test]
    fn architectures_rejects_non_macho() {
        assert!(architectures(b"nope").is_err());
    }

    #[test]
    fn reads_build_version_and_code_signature() {
        let bytes = thin_macho(0x0100_000c, true);
        let got = facts(&bytes).unwrap();
        assert_eq!(got.platform.as_deref(), Some("ios"));
        assert_eq!(got.minos.as_deref(), Some("15.4.1"));
        assert_eq!(got.sdk.as_deref(), Some("16.0.0"));
        assert!(got.has_code_signature);
        assert_eq!(got.signature, None);
        assert_eq!(got.uuid, None);
        assert_eq!(
            architectures(&bytes).unwrap(),
            vec![MachoArch {
                cpu: "arm64".into(),
                offset: 0,
                size: bytes.len() as u64,
            }]
        );
    }

    #[test]
    fn omits_version_without_build_command() {
        let bytes = thin_macho(7, false);
        let got = facts(&bytes).unwrap();
        assert_eq!(got.platform, None);
        assert_eq!(got.minos, None);
        assert_eq!(got.sdk, None);
        assert!(!got.has_code_signature);
        assert_eq!(got.signature, None);
        assert_eq!(architectures(&bytes).unwrap()[0].cpu, "x86");
    }

    #[test]
    fn reads_code_directory_and_skips_the_cms_blob() {
        let bytes = signed_macho();
        let got = facts(&bytes).unwrap();
        assert!(got.has_code_signature);
        assert_eq!(
            got.signature,
            Some(MachoSignature {
                identifier: "com.example.app".into(),
                hash_type: "sha256".into(),
                team_id: Some("TEAM123456".into()),
            })
        );
        assert!(!format!("{got:?}").contains("CMS-BLOB"));

        let cms_only = signed_macho_without_code_directory();
        let got = facts(&cms_only).unwrap();
        assert!(got.has_code_signature);
        assert_eq!(got.signature, None);
    }

    /// Little-endian 64-bit Mach-O. `with_meta` adds `LC_BUILD_VERSION` (iOS 15.4.1,
    /// SDK 16.0.0) and `LC_CODE_SIGNATURE`.
    fn thin_macho(cputype: u32, with_meta: bool) -> Vec<u8> {
        let ncmds: u32 = if with_meta { 2 } else { 0 };
        let sizeofcmds: u32 = if with_meta { 24 + 16 } else { 0 };
        let mut buf = Vec::new();
        let mut push = |v: u32| buf.extend_from_slice(&v.to_le_bytes());
        push(0xfeed_facf);
        push(cputype);
        push(0);
        push(1); // MH_OBJECT
        push(ncmds);
        push(sizeofcmds);
        push(0);
        push(0);
        if with_meta {
            push(0x32); // LC_BUILD_VERSION
            push(24);
            push(2); // PLATFORM_IOS
            push((15 << 16) | (4 << 8) | 1);
            push(16 << 16);
            push(0);
            push(0x1d); // LC_CODE_SIGNATURE
            push(16);
            push(0);
            push(0);
        }
        buf
    }

    /// One `LC_CODE_SIGNATURE`. The index lists the CMS slot first. The code directory is version `0x20200`, hash type sha256.
    fn signed_macho() -> Vec<u8> {
        let mut cd = vec![0u8; 79];
        write_be(&mut cd, 0, 0xfade_0c02);
        write_be(&mut cd, 4, 79);
        write_be(&mut cd, 8, 0x20200);
        write_be(&mut cd, 20, 52);
        cd[37] = 2;
        write_be(&mut cd, 48, 68);
        cd[52..68].copy_from_slice(b"com.example.app\0");
        cd[68..79].copy_from_slice(b"TEAM123456\0");

        let mut blob = vec![0u8; 115];
        write_be(&mut blob, 0, 0xfade_0cc0);
        write_be(&mut blob, 4, 115);
        write_be(&mut blob, 8, 2);
        write_be(&mut blob, 12, 0x10000);
        write_be(&mut blob, 16, 107);
        write_be(&mut blob, 20, 0);
        write_be(&mut blob, 24, 28);
        blob[28..107].copy_from_slice(&cd);
        blob[107..115].copy_from_slice(b"CMS-BLOB");

        let mut file = Vec::new();
        let mut push = |v: u32| file.extend_from_slice(&v.to_le_bytes());
        push(0xfeed_facf);
        push(0x0100_000c);
        push(0);
        push(1);
        push(1);
        push(16);
        push(0);
        push(0);
        push(0x1d);
        push(16);
        push(48);
        push(blob.len() as u32);
        file.extend_from_slice(&blob);
        file
    }

    fn signed_macho_without_code_directory() -> Vec<u8> {
        let mut blob = vec![0u8; 20];
        write_be(&mut blob, 0, 0xfade_0cc0);
        write_be(&mut blob, 4, 20);
        write_be(&mut blob, 8, 1);
        write_be(&mut blob, 12, 0x10000);
        write_be(&mut blob, 16, 0);
        let mut file = Vec::new();
        let mut push = |v: u32| file.extend_from_slice(&v.to_le_bytes());
        push(0xfeed_facf);
        push(0x0100_000c);
        push(0);
        push(1);
        push(1);
        push(16);
        push(0);
        push(0);
        push(0x1d);
        push(16);
        push(48);
        push(blob.len() as u32);
        file.extend_from_slice(&blob);
        file
    }

    fn write_be(buf: &mut [u8], at: usize, value: u32) {
        buf[at..at + 4].copy_from_slice(&value.to_be_bytes());
    }
}
