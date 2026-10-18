//! Identifying fields from an XML Info.plist. A binary plist, or a text
//! plist with none of these keys, is `None` and does not fail the caller.

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PlistInfo {
    pub bundle_id: Option<String>,
    pub bundle_name: Option<String>,
    pub bundle_version: Option<String>,
}

/// `CFBundleIdentifier`, `CFBundleName`, and `CFBundleVersion` from an XML plist.
pub fn identify(bytes: &[u8]) -> Option<PlistInfo> {
    let text = std::str::from_utf8(bytes).ok()?;
    if !text.contains("<plist") && !text.contains("<key>") {
        return None;
    }
    let info = PlistInfo {
        bundle_id: string_after_key(text, "CFBundleIdentifier"),
        bundle_name: string_after_key(text, "CFBundleName"),
        bundle_version: string_after_key(text, "CFBundleVersion"),
    };
    if info.bundle_id.is_none() && info.bundle_name.is_none() && info.bundle_version.is_none() {
        None
    } else {
        Some(info)
    }
}

fn string_after_key(text: &str, key: &str) -> Option<String> {
    let needle = format!("<key>{key}</key>");
    let at = text.find(&needle)?;
    let rest = text.get(at + needle.len()..)?;
    let start = rest.find("<string>")? + "<string>".len();
    let tail = rest.get(start..)?;
    let end = tail.find("</string>")?;
    let value = tail[..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::identify;

    fn sample() -> String {
        "<?xml version=\"1.0\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\"><dict>\n\
         <key>CFBundleIdentifier</key><string>com.example.app</string>\n\
         <key>CFBundleName</key><string>Example</string>\n\
         <key>CFBundleVersion</key><string>1.2.3</string>\n\
         </dict></plist>\n"
            .to_string()
    }

    #[test]
    fn reads_identifying_plist_fields() {
        let got = identify(sample().as_bytes()).unwrap();
        assert_eq!(got.bundle_id.as_deref(), Some("com.example.app"));
        assert_eq!(got.bundle_name.as_deref(), Some("Example"));
        assert_eq!(got.bundle_version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn truncated_plist_does_not_invent_fields() {
        assert!(identify(b"<plist><dict><key>CFBundleName</key>").is_none());
        assert!(identify(b"not a plist").is_none());
    }
}
