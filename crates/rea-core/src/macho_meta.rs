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
    Ok(MachoFacts {
        dylibs: mo.libs.iter().map(|lib| (*lib).to_string()).collect(),
        uuid,
        platform,
        minos,
        sdk,
        has_code_signature,
    })
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
        assert_eq!(architectures(&bytes).unwrap()[0].cpu, "x86");
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
}
