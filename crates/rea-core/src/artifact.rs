//! Static kind of an app bundle, a compiled nib, or an asset catalog.
//!
//! This does not reconstruct the nib or the catalog. An unrecognized path is
//! `Ok(None)`.

use crate::{Error, Result};
use std::path::Path;

/// `app-bundle`, `nib`, or `asset-catalog` when the path matches that kind.
pub fn identify(path: &Path) -> Result<Option<String>> {
    if path.is_dir() {
        let ios = path.join("Info.plist");
        let mac = path.join("Contents").join("Info.plist");
        if ios.is_file() || mac.is_file() {
            return Ok(Some("app-bundle".to_string()));
        }
        return Ok(None);
    }
    if !path.exists() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "artifact path is missing",
        )));
    }
    let bytes = std::fs::read(path).map_err(Error::Io)?;
    Ok(sniff(&bytes))
}

/// Magic-only sniff. `NIBArchive` is a compiled nib. `BOMStore` is an asset catalog.
pub fn sniff(bytes: &[u8]) -> Option<String> {
    if bytes.starts_with(b"NIBArchive") {
        Some("nib".to_string())
    } else if bytes.starts_with(b"BOMStore") {
        Some("asset-catalog".to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{identify, sniff};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn magic_distinguishes_nib_and_asset_catalog() {
        assert_eq!(sniff(b"NIBArchive\0more").as_deref(), Some("nib"));
        assert_eq!(sniff(b"BOMStore\0more").as_deref(), Some("asset-catalog"));
        assert_eq!(sniff(b"short"), None);
    }

    #[test]
    fn directory_with_info_plist_is_an_app_bundle() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("rea-artifact-{stamp}"));
        let app = root.join("Example.app");
        let mac = root.join("Mac.app").join("Contents");
        fs::create_dir_all(&app).unwrap();
        fs::create_dir_all(&mac).unwrap();
        fs::write(app.join("Info.plist"), b"<plist></plist>").unwrap();
        fs::write(mac.join("Info.plist"), b"<plist></plist>").unwrap();
        fs::write(root.join("Widget.nib"), b"NIBArchive").unwrap();
        fs::write(root.join("Assets.car"), b"BOMStore").unwrap();
        assert_eq!(identify(&app).unwrap().as_deref(), Some("app-bundle"));
        assert_eq!(
            identify(&root.join("Mac.app")).unwrap().as_deref(),
            Some("app-bundle")
        );
        assert_eq!(identify(&root.join("Widget.nib")).unwrap().as_deref(), Some("nib"));
        assert_eq!(
            identify(&root.join("Assets.car")).unwrap().as_deref(),
            Some("asset-catalog")
        );
        assert_eq!(identify(&root).unwrap(), None);
        let _ = fs::remove_dir_all(&root);
    }
}
