//! In-process bridge for external reverse-engineering tools.
//!
//! `status` reports whether a known binary is on `PATH`. `parse` reads an export
//! from Hopper, Ghidra, IDA, JEB, Frida, a CDP event, or adb. This does not
//! launch those programs.

use crate::{Error, Result};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ProviderStatus {
    pub provider: String,
    pub installed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Finding {
    pub provider: String,
    pub kind: String,
    pub name: String,
    pub addr: Option<u64>,
    pub detail: String,
}

const PROVIDERS: &[(&str, &[&str])] = &[
    ("hopper", &["hopper", "Hopper"]),
    ("ghidra", &["analyzeHeadless"]),
    ("ida", &["ida64", "ida"]),
    ("jeb", &["jeb", "jeb_linux.sh"]),
    ("frida", &["frida", "frida-ps"]),
    ("cdp", &[]),
    ("adb", &["adb"]),
];

pub fn status() -> Vec<ProviderStatus> {
    PROVIDERS
        .iter()
        .map(|(name, bins)| ProviderStatus {
            provider: (*name).to_string(),
            installed: bins.is_empty() || bins.iter().any(|bin| on_path(bin)),
        })
        .collect()
}

/// Parse one export. A provider that is not in the table is an error.
/// A line that does not match that provider's grammar is skipped.
pub fn parse(provider: &str, text: &str) -> Result<Vec<Finding>> {
    if !PROVIDERS.iter().any(|(name, _)| *name == provider) {
        return Err(Error::Parse(format!("bridge: unknown provider {provider}")));
    }
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(found) = parse_line(provider, line) {
            out.push(found);
        }
    }
    Ok(out)
}

fn parse_line(provider: &str, line: &str) -> Option<Finding> {
    match provider {
        "ghidra" => parse_hex_name(provider, line, &["FUNCTION", "function"]),
        "hopper" => parse_hex_name(provider, line, &["procedure"]),
        "jeb" => parse_hex_name(provider, line, &["method"]),
        "ida" => parse_ida(line),
        "frida" => parse_frida(line),
        "cdp" => parse_cdp(line),
        "adb" => parse_adb(line),
        _ => None,
    }
}

fn parse_hex_name(provider: &str, line: &str, heads: &[&str]) -> Option<Finding> {
    let mut parts = line.split_whitespace();
    let head = parts.next()?;
    if !heads.iter().any(|h| *h == head) {
        return None;
    }
    let addr = parse_addr(parts.next()?)?;
    let name = parts.next()?.to_string();
    Some(Finding {
        provider: provider.to_string(),
        kind: "function".into(),
        name,
        addr: Some(addr),
        detail: String::new(),
    })
}

fn parse_ida(line: &str) -> Option<Finding> {
    let rest = line.strip_prefix("MakeName(")?.strip_suffix(");")?;
    let (addr, name) = rest.split_once(',')?;
    let name = name.trim().trim_matches('"').to_string();
    Some(Finding {
        provider: "ida".into(),
        kind: "name".into(),
        name,
        addr: Some(parse_addr(addr.trim())?),
        detail: String::new(),
    })
}

fn parse_frida(line: &str) -> Option<Finding> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let kind = value.get("type")?.as_str()?.to_string();
    let payload = value.get("payload")?;
    let detail = match payload {
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    Some(Finding {
        provider: "frida".into(),
        kind,
        name: String::new(),
        addr: None,
        detail,
    })
}

fn parse_cdp(line: &str) -> Option<Finding> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let method = value.get("method")?.as_str()?.to_string();
    let info = value.pointer("/params/targetInfo")?;
    let url = info.get("url").and_then(|v| v.as_str()).unwrap_or("");
    let title = info.get("title").and_then(|v| v.as_str()).unwrap_or("");
    Some(Finding {
        provider: "cdp".into(),
        kind: method,
        name: title.to_string(),
        addr: None,
        detail: url.to_string(),
    })
}

fn parse_adb(line: &str) -> Option<Finding> {
    let mut parts = line.split_whitespace();
    let serial = parts.next()?.to_string();
    let state = parts.next()?;
    if state != "device" && state != "offline" && state != "unauthorized" {
        return None;
    }
    Some(Finding {
        provider: "adb".into(),
        kind: state.to_string(),
        name: serial,
        addr: None,
        detail: parts.collect::<Vec<_>>().join(" "),
    })
}

fn parse_addr(text: &str) -> Option<u64> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if text.chars().all(|c| c.is_ascii_hexdigit()) && text.chars().any(|c| c.is_ascii_alphabetic())
    {
        u64::from_str_radix(text, 16).ok()
    } else {
        text.parse().ok()
    }
}

fn on_path(name: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| Path::new(&dir).join(name).is_file())
}

#[cfg(test)]
mod tests {
    use super::{parse, status};

    #[test]
    fn exports_become_findings() {
        let ghidra = parse("ghidra", "FUNCTION 0x1000 main\nnope\n").unwrap();
        assert_eq!(ghidra.len(), 1);
        assert_eq!(ghidra[0].name, "main");
        assert_eq!(ghidra[0].addr, Some(0x1000));

        let ida = parse("ida", "MakeName(0x2000, \"foo\");").unwrap();
        assert_eq!(ida[0].name, "foo");
        assert_eq!(ida[0].addr, Some(0x2000));

        let hopper = parse("hopper", "procedure 0x30 bar").unwrap();
        assert_eq!(hopper[0].name, "bar");

        let jeb = parse("jeb", "method 0x40 Baz").unwrap();
        assert_eq!(jeb[0].name, "Baz");

        let frida = parse("frida", r#"{"type":"send","payload":"hello"}"#).unwrap();
        assert_eq!(frida[0].kind, "send");
        assert_eq!(frida[0].detail, "hello");

        let cdp = parse(
            "cdp",
            r#"{"method":"Target.targetCreated","params":{"targetInfo":{"url":"https://example.test","title":"Example"}}}"#,
        )
        .unwrap();
        assert_eq!(cdp[0].name, "Example");
        assert_eq!(cdp[0].detail, "https://example.test");

        let adb = parse("adb", "emulator-5554 device product:sdk").unwrap();
        assert_eq!(adb[0].name, "emulator-5554");
        assert_eq!(adb[0].kind, "device");
        assert!(parse("nope", "FUNCTION 1 x").is_err());
    }

    #[test]
    fn status_lists_the_seven_providers() {
        let rows = status();
        assert_eq!(rows.len(), 7);
        assert!(rows.iter().any(|row| row.provider == "cdp" && row.installed));
    }
}
