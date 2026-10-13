//! Dylibs and UUID from a single Mach-O slice.

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MachoFacts {
    pub dylibs: Vec<String>,
    pub uuid: Option<String>, // lowercase hex, 32 chars, no dashes
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
    Ok(MachoFacts {
        dylibs: mo.libs.iter().map(|lib| (*lib).to_string()).collect(),
        uuid,
    })
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
}
