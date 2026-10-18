//! Load-command facts for one Mach-O slice, plus each fat slice's uuid, dylibs, rpaths, build version, and code directory.

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MachoFacts {
    pub dylibs: Vec<String>,
    pub uuid: Option<String>,     // lowercase hex, 32 chars, no dashes
    pub platform: Option<String>, // "macos", "ios", "tvos", "watchos", "bridgeos", or "platform-{n}"
    pub minos: Option<String>,    // "x.y.z" from LC_BUILD_VERSION
    pub sdk: Option<String>,
    /// `LC_RPATH` paths. The directories are not searched.
    pub rpaths: Vec<String>,
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
    /// UUID of this slice. `None` when the slice bytes are absent or unreadable.
    pub uuid: Option<String>,
    /// Dylibs of this slice. Empty when the slice bytes are absent or unreadable.
    pub dylibs: Vec<String>,
    /// `LC_RPATH` paths of this slice. The directories are not searched.
    pub rpaths: Vec<String>,
    pub platform: Option<String>,
    pub minos: Option<String>,
    pub sdk: Option<String>,
    /// Code directory of this slice. `None` when the slice bytes are absent or the directory does not fit.
    pub signature: Option<MachoSignature>,
}

/// Parse one Mach-O slice (not a fat archive). Fat input returns Error::Parse.
pub fn facts(bytes: &[u8]) -> Result<MachoFacts> {
    let mo =
        goblin::mach::MachO::parse(bytes, 0).map_err(|e| Error::Parse(format!("mach-o: {e}")))?;
    let body = slice_body(&mo, bytes);
    Ok(MachoFacts {
        dylibs: body.dylibs,
        uuid: body.uuid,
        platform: body.platform,
        minos: body.minos,
        sdk: body.sdk,
        rpaths: body.rpaths,
        has_code_signature: body.has_code_signature,
        signature: body.signature,
    })
}

struct SliceBody {
    dylibs: Vec<String>,
    rpaths: Vec<String>,
    uuid: Option<String>,
    platform: Option<String>,
    minos: Option<String>,
    sdk: Option<String>,
    has_code_signature: bool,
    signature: Option<MachoSignature>,
}

fn slice_body(mo: &goblin::mach::MachO, bytes: &[u8]) -> SliceBody {
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
    SliceBody {
        dylibs: mo.libs.iter().map(|lib| (*lib).to_string()).collect(),
        rpaths: mo.rpaths.iter().map(|path| (*path).to_string()).collect(),
        uuid,
        platform,
        minos,
        sdk,
        has_code_signature,
        signature,
    }
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
///
/// Each slice that is present contributes its uuid, dylibs, rpaths, build version, and code directory. A missing or unreadable slice leaves those fields empty and does not fail the parse. The CMS blob and the hash slots are not read.
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
                    arch_of(cpu_name(cputype), u64::from(offset), u64::from(size), arch.slice(bytes))
                })
                .collect())
        }
        goblin::mach::Mach::Binary(mo) => {
            Ok(vec![arch_of(cpu_name(mo.header.cputype()), 0, bytes.len() as u64, bytes)])
        }
    }
}

fn arch_of(cpu: String, offset: u64, size: u64, slice: &[u8]) -> MachoArch {
    let body = slice_facts(slice);
    MachoArch {
        cpu,
        offset,
        size,
        uuid: body.uuid,
        dylibs: body.dylibs,
        rpaths: body.rpaths,
        platform: body.platform,
        minos: body.minos,
        sdk: body.sdk,
        signature: body.signature,
    }
}

/// Identity of one slice. An empty or unreadable slice is empty and does not fail the caller.
fn slice_facts(slice: &[u8]) -> SliceBody {
    if slice.is_empty() {
        return empty_slice();
    }
    match goblin::mach::MachO::parse(slice, 0) {
        Ok(mo) => slice_body(&mo, slice),
        Err(_) => empty_slice(),
    }
}

fn empty_slice() -> SliceBody {
    SliceBody {
        dylibs: Vec::new(),
        rpaths: Vec::new(),
        uuid: None,
        platform: None,
        minos: None,
        sdk: None,
        has_code_signature: false,
        signature: None,
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
                uuid: None,
                dylibs: Vec::new(),
                rpaths: Vec::new(),
                platform: None,
                minos: None,
                sdk: None,
                signature: None,
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
                uuid: None,
                dylibs: vec!["self".into()],
                rpaths: Vec::new(),
                platform: Some("ios".into()),
                minos: Some("15.4.1".into()),
                sdk: Some("16.0.0".into()),
                signature: None,
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

        let arches = architectures(&bytes).unwrap();
        assert_eq!(arches[0].signature, Some(got_signature()));
        assert!(!format!("{arches:?}").contains("CMS-BLOB"));
        assert_eq!(architectures(&cms_only).unwrap()[0].signature, None);
    }

    #[test]
    fn fat_slices_keep_their_own_code_directories() {
        let arm = signed_macho();
        let intel = retarget(signed_macho(), b"com.example.cmd\0", b"TEAM654321\0");
        let bytes = fat_two(&arm, &intel);
        let arches = architectures(&bytes).unwrap();
        assert!(facts(&bytes).is_err());
        assert_eq!(arches[0].cpu, "arm64");
        assert_eq!(arches[0].signature, Some(got_signature()));
        assert_eq!(arches[1].cpu, "x86_64");
        assert_eq!(
            arches[1].signature,
            Some(MachoSignature {
                identifier: "com.example.cmd".into(),
                hash_type: "sha256".into(),
                team_id: Some("TEAM654321".into()),
            })
        );
        assert!(!format!("{arches:?}").contains("CMS-BLOB"));
    }

    #[test]
    fn fat_slices_keep_their_own_identity() {
        let arm_uuid = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let intel_uuid = [0xaa; 16];
        let arm = identity_macho(
            0x0100_000c,
            arm_uuid,
            "libarm.dylib",
            "/opt/arm",
            Some((1, 12 << 16, (13 << 16) | (1 << 8))),
        );
        let intel = identity_macho(0x0100_0007, intel_uuid, "libx86.dylib", "/opt/x86", None);
        let thin = facts(&arm).unwrap();
        assert_eq!(thin.uuid.as_deref(), Some("0102030405060708090a0b0c0d0e0f10"));
        assert_eq!(thin.dylibs, vec!["self".to_string(), "libarm.dylib".to_string()]);
        assert_eq!(thin.rpaths, vec!["/opt/arm".to_string()]);
        assert_eq!(thin.platform.as_deref(), Some("macos"));
        assert_eq!(thin.minos.as_deref(), Some("12.0.0"));
        assert_eq!(thin.sdk.as_deref(), Some("13.1.0"));

        let bytes = fat_two(&arm, &intel);
        let arches = architectures(&bytes).unwrap();
        assert_eq!(arches[0].uuid.as_deref(), Some("0102030405060708090a0b0c0d0e0f10"));
        assert_eq!(arches[0].dylibs, vec!["self".to_string(), "libarm.dylib".to_string()]);
        assert_eq!(arches[0].rpaths, vec!["/opt/arm".to_string()]);
        assert_eq!(arches[0].platform.as_deref(), Some("macos"));
        assert_eq!(arches[1].uuid.as_deref(), Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert_eq!(arches[1].dylibs, vec!["self".to_string(), "libx86.dylib".to_string()]);
        assert_eq!(arches[1].rpaths, vec!["/opt/x86".to_string()]);
        assert_eq!(arches[1].platform, None);
        assert!(facts(&bytes).is_err());
    }

    #[test]
    fn unreadable_fat_slice_leaves_the_code_directory_empty() {
        let bytes = fat_two(&signed_macho(), b"not-a-slice");
        let arches = architectures(&bytes).unwrap();
        assert_eq!(
            arches[0].signature.as_ref().map(|sig| sig.identifier.as_str()),
            Some("com.example.app")
        );
        assert_eq!(arches[1].cpu, "x86_64");
        assert_eq!(arches[1].signature, None);
        assert_eq!(arches[1].uuid, None);
        assert!(arches[1].dylibs.is_empty());
        assert!(arches[1].rpaths.is_empty());
    }

    fn identity_macho(
        cputype: u32,
        uuid: [u8; 16],
        dylib: &str,
        rpath: &str,
        build: Option<(u32, u32, u32)>,
    ) -> Vec<u8> {
        let mut commands = vec![uuid_cmd(uuid), load_dylib(dylib), rpath_cmd(rpath)];
        if let Some((platform, minos, sdk)) = build {
            commands.push(build_version(platform, minos, sdk));
        }
        macho_object(cputype, &commands)
    }

    fn macho_object(cputype: u32, commands: &[Vec<u8>]) -> Vec<u8> {
        let sizeofcmds: u32 = commands.iter().map(|cmd| cmd.len() as u32).sum();
        let mut buf = Vec::new();
        let mut push = |v: u32| buf.extend_from_slice(&v.to_le_bytes());
        push(0xfeed_facf);
        push(cputype);
        push(0);
        push(1);
        push(commands.len() as u32);
        push(sizeofcmds);
        push(0);
        push(0);
        for cmd in commands {
            buf.extend_from_slice(cmd);
        }
        buf
    }

    fn uuid_cmd(uuid: [u8; 16]) -> Vec<u8> {
        let mut cmd = vec![0u8; 24];
        cmd[0..4].copy_from_slice(&0x1bu32.to_le_bytes());
        cmd[4..8].copy_from_slice(&24u32.to_le_bytes());
        cmd[8..24].copy_from_slice(&uuid);
        cmd
    }

    fn load_dylib(name: &str) -> Vec<u8> {
        cstring_cmd(0xc, 24, 24, name)
    }

    fn rpath_cmd(path: &str) -> Vec<u8> {
        cstring_cmd(0x8000_001c, 12, 12, path)
    }

    fn cstring_cmd(cmd: u32, header: usize, string_off: u32, value: &str) -> Vec<u8> {
        let bytes = value.as_bytes();
        let mut size = header + bytes.len() + 1;
        size = size.div_ceil(8) * 8;
        let mut out = vec![0u8; size];
        out[0..4].copy_from_slice(&cmd.to_le_bytes());
        out[4..8].copy_from_slice(&(size as u32).to_le_bytes());
        out[8..12].copy_from_slice(&string_off.to_le_bytes());
        let at = string_off as usize;
        out[at..at + bytes.len()].copy_from_slice(bytes);
        out
    }

    fn build_version(platform: u32, minos: u32, sdk: u32) -> Vec<u8> {
        let mut cmd = vec![0u8; 24];
        let mut push = |at: usize, v: u32| cmd[at..at + 4].copy_from_slice(&v.to_le_bytes());
        push(0, 0x32);
        push(4, 24);
        push(8, platform);
        push(12, minos);
        push(16, sdk);
        cmd
    }

    fn got_signature() -> MachoSignature {
        MachoSignature {
            identifier: "com.example.app".into(),
            hash_type: "sha256".into(),
            team_id: Some("TEAM123456".into()),
        }
    }

    fn retarget(mut bytes: Vec<u8>, ident: &[u8], team: &[u8]) -> Vec<u8> {
        let ident_at = bytes
            .windows(ident.len())
            .position(|window| window == b"com.example.app\0")
            .expect("identifier");
        let team_at = bytes
            .windows(team.len())
            .position(|window| window == b"TEAM123456\0")
            .expect("team id");
        bytes[ident_at..ident_at + ident.len()].copy_from_slice(ident);
        bytes[team_at..team_at + team.len()].copy_from_slice(team);
        bytes
    }

    fn fat_two(first: &[u8], second: &[u8]) -> Vec<u8> {
        let off1 = 64u32;
        let off2 = off1 + first.len() as u32;
        let mut out = vec![0u8; off2 as usize + second.len()];
        write_be(&mut out, 0, 0xcafe_babe);
        write_be(&mut out, 4, 2);
        write_be(&mut out, 8, 0x0100_000c);
        write_be(&mut out, 16, off1);
        write_be(&mut out, 20, first.len() as u32);
        write_be(&mut out, 28, 0x0100_0007);
        write_be(&mut out, 36, off2);
        write_be(&mut out, 40, second.len() as u32);
        out[off1 as usize..off1 as usize + first.len()].copy_from_slice(first);
        out[off2 as usize..off2 as usize + second.len()].copy_from_slice(second);
        out
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
