//! Identifying lines from a text crash report. A report with none of these
//! lines is `None`.

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CrashReport {
    pub process: Option<String>,
    pub identifier: Option<String>,
    pub version: Option<String>,
}

/// `Process`, `Identifier`, and `Version` from a classic crash-report header.
///
/// The process value drops a trailing `[pid]`. A truncated file with no such
/// line is `None`.
pub fn identify(bytes: &[u8]) -> Option<CrashReport> {
    let text = String::from_utf8_lossy(bytes);
    let mut process = None;
    let mut identifier = None;
    let mut version = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key.trim() {
            "Process" => process = Some(strip_pid(value)),
            "Identifier" => identifier = Some(value.to_string()),
            "Version" => version = Some(value.to_string()),
            _ => {}
        }
    }
    if process.is_none() && identifier.is_none() && version.is_none() {
        None
    } else {
        Some(CrashReport {
            process,
            identifier,
            version,
        })
    }
}

fn strip_pid(value: &str) -> String {
    value.split('[').next().unwrap_or(value).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::identify;

    #[test]
    fn reads_process_identifier_and_version() {
        let text = "\
Process:               Example [123]\n\
Path:                  /tmp/Example\n\
Identifier:            com.example.app\n\
Version:               1.2.3 (1.2.3)\n\
";
        let got = identify(text.as_bytes()).unwrap();
        assert_eq!(got.process.as_deref(), Some("Example"));
        assert_eq!(got.identifier.as_deref(), Some("com.example.app"));
        assert_eq!(got.version.as_deref(), Some("1.2.3 (1.2.3)"));
    }

    #[test]
    fn truncated_report_has_no_identity() {
        assert!(identify(b"Process:\n").is_none());
        assert!(identify(b"not a crash").is_none());
    }
}
