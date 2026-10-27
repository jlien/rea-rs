//! Evidence sessions. Each session is a JSON file of tool records.
//!
//! `open` maps the named binary once through the loader and records its
//! identity summary (format, arch, bits, endianness, entry, section and symbol
//! counts). A path that does not load stays open with no summary. `record`
//! stores a summary, and with a `tool` name re-runs that named command against
//! the session's binary and embeds the output, capped. Each record also keeps
//! the unix-seconds time it was written and optional caller-supplied argument
//! text, capped. The file on disk stays the source of truth: nothing is held
//! mapped between calls. Comparing two
//! sessions lists identity evidence and records that appear on only one side.

use crate::{loader, Error, Result, Target};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Embedded tool output is capped at 16 KiB.
pub const EMBED_CAP: usize = 16 * 1024;

/// Caller-supplied argument text is capped at this many bytes.
pub const ARGUMENTS_CAP: usize = 1024;

const TRUNCATION_MARKER: &str = "\n[truncated]";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub id: String,
    pub path: String,
    /// Identity of the mapped binary, `None` when the path did not load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetSummary>,
    pub records: Vec<Record>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TargetSummary {
    pub format: String,
    pub arch: String,
    pub bits: u8,
    pub little_endian: bool,
    pub entry: u64,
    pub sections: usize,
    pub symbols: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Record {
    /// The rea command that produced the embedded output, empty for a plain summary.
    pub tool: String,
    pub summary: String,
    /// Output of the named command re-run against the session's binary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    /// Caller-supplied argument text, capped at [`ARGUMENTS_CAP`] bytes. Absent
    /// on records written before the field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
    /// Unix seconds, decimal, when the record was written. Absent on records
    /// written before the field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SessionDiff {
    pub only_left: Vec<String>,
    pub only_right: Vec<String>,
}

/// Create `dir/<id>.json`. The id is the next decimal counter in that directory.
/// A loadable `path` is mapped once for its identity summary.
pub fn open(dir: &Path, path: &str) -> Result<Session> {
    fs::create_dir_all(dir).map_err(Error::Io)?;
    let id = next_id(dir)?;
    let target = loader::load(path).ok().map(|t| summarize(&t));
    let session = Session {
        id,
        path: path.to_string(),
        target,
        records: Vec::new(),
    };
    save(dir, &session)?;
    Ok(session)
}

pub fn load(dir: &Path, id: &str) -> Result<Session> {
    let raw = fs::read(session_path(dir, id)).map_err(Error::Io)?;
    serde_json::from_slice(&raw).map_err(|e| Error::Parse(format!("session: {e}")))
}

/// Append a record. With a `tool`, the named command (`info`, `sections`,
/// `symbols`, `strings`, `funcs`, `disasm`) is re-run against the session's
/// binary and its output embedded, capped at [`EMBED_CAP`]. Optional
/// `arguments` text is stored as-is, capped at [`ARGUMENTS_CAP`] bytes. The
/// timestamp is unix seconds, decimal, from `SystemTime::now`.
pub fn record(
    dir: &Path,
    id: &str,
    tool: Option<&str>,
    summary: &str,
    arguments: Option<&str>,
) -> Result<Session> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::Parse(format!("session: {e}")))?
        .as_secs();
    record_at(dir, id, tool, summary, arguments, timestamp)
}

/// [`record`] with an explicit unix-seconds timestamp. Tests that need a fixed
/// value call this instead of reading the clock.
pub fn record_at(
    dir: &Path,
    id: &str,
    tool: Option<&str>,
    summary: &str,
    arguments: Option<&str>,
    timestamp: u64,
) -> Result<Session> {
    let mut session = load(dir, id)?;
    let output = match tool {
        None => None,
        Some(name) => {
            let target = loader::load(&session.path)?;
            Some(bounded_output(&target, name)?)
        }
    };
    session.records.push(Record {
        tool: tool.unwrap_or("").to_string(),
        summary: summary.to_string(),
        output,
        arguments: arguments.map(capped_arguments),
        timestamp: Some(timestamp),
    });
    save(dir, &session)?;
    Ok(session)
}

/// Truncate argument text at [`ARGUMENTS_CAP`] bytes, never mid-character.
fn capped_arguments(arguments: &str) -> String {
    if arguments.len() <= ARGUMENTS_CAP {
        return arguments.to_string();
    }
    let mut end = ARGUMENTS_CAP;
    while !arguments.is_char_boundary(end) {
        end -= 1;
    }
    arguments[..end].to_string()
}

/// Summaries of the form `tool: summary`, with embedded output in brackets,
/// plus one `target:` line per mapped identity. Compared as text.
pub fn diff(left: &Session, right: &Session) -> SessionDiff {
    let left_lines: Vec<String> = left
        .target
        .as_ref()
        .map(target_line)
        .into_iter()
        .chain(left.records.iter().map(line))
        .collect();
    let right_lines: Vec<String> = right
        .target
        .as_ref()
        .map(target_line)
        .into_iter()
        .chain(right.records.iter().map(line))
        .collect();
    SessionDiff {
        only_left: left_lines
            .iter()
            .filter(|line| !right_lines.contains(line))
            .cloned()
            .collect(),
        only_right: right_lines
            .iter()
            .filter(|line| !left_lines.contains(line))
            .cloned()
            .collect(),
    }
}

/// One upstream-morphic Evidence record, mapped from a native [`Record`].
/// Fields the native store does not capture — the session handle, a live
/// mapping — are explicit `null`s, never fabricated.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct EvidenceRecord {
    /// The session the record came from.
    pub session: String,
    /// The recorded rea command; empty for a plain summary record.
    pub tool: String,
    /// Upstream echoes the caller's arguments. The native store keeps the
    /// caller-supplied text, echoed as a JSON string; null when none was
    /// stored.
    pub arguments: Option<serde_json::Value>,
    pub summary: String,
    /// Embedded command output, capped at [`EMBED_CAP`]; the `[truncated]`
    /// marker is carried through verbatim. Null for a plain summary record.
    pub output: Option<String>,
    /// Unix seconds, decimal, as stored on the record; null when the record
    /// predates the field.
    pub timestamp: Option<u64>,
}

/// The upstream-morphic Evidence export of one session file.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct EvidenceExport {
    /// Binary path the session maps.
    pub path: String,
    /// Identity summary recorded at `open`; null when the path did not load.
    pub identity: Option<TargetSummary>,
    /// Upstream holds a live session handle; the native store does not.
    pub session_handle: Option<String>,
    /// Upstream holds a live memory mapping; nothing is mapped between calls.
    pub live_mapping: Option<String>,
    pub records: Vec<EvidenceRecord>,
}

/// Map a native session file to the upstream-morphic Evidence shape. The
/// native file stays the source of truth; nothing here writes back.
pub fn export_evidence(session: &Session) -> EvidenceExport {
    EvidenceExport {
        path: session.path.clone(),
        identity: session.target.clone(),
        session_handle: None,
        live_mapping: None,
        records: session
            .records
            .iter()
            .map(|record| EvidenceRecord {
                session: session.id.clone(),
                tool: record.tool.clone(),
                arguments: record
                    .arguments
                    .clone()
                    .map(serde_json::Value::String),
                summary: record.summary.clone(),
                output: record.output.clone(),
                timestamp: record.timestamp,
            })
            .collect(),
    }
}

fn summarize(target: &Target) -> TargetSummary {
    TargetSummary {
        format: target.format.as_str().to_string(),
        arch: target.arch.as_str().to_string(),
        bits: target.bits,
        little_endian: target.little_endian,
        entry: target.entry,
        sections: target.sections.len(),
        symbols: target.symbols.len(),
    }
}

/// Run one named rea command against a mapped binary. Unknown names error.
fn run_tool(target: &Target, tool: &str) -> Result<String> {
    let value = match tool {
        "info" => serde_json::json!({
            "path": target.path,
            "format": target.format.as_str(),
            "arch": target.arch.as_str(),
            "bits": target.bits,
            "little_endian": target.little_endian,
            "entry": target.entry,
            "sections": target.sections.len(),
            "symbols": target.symbols.len(),
        }),
        "sections" => serde_json::json!(target.sections),
        "symbols" => serde_json::json!({ "count": target.symbols.len(), "symbols": target.symbols }),
        "strings" => {
            let hits = crate::strings::extract(&target.bytes, 4);
            serde_json::json!({ "count": hits.len(), "strings": hits })
        }
        "funcs" => serde_json::json!(crate::analysis::discover_functions(target)),
        "disasm" => serde_json::json!({
            "address": target.entry,
            "count": 32,
            "instructions": crate::disasm::disassemble(target, target.entry, 32)
                .map_err(|e| Error::Parse(format!("session: {e}")))?,
        }),
        other => return Err(Error::Parse(format!("session: unknown tool {other}"))),
    };
    serde_json::to_string_pretty(&value).map_err(|e| Error::Parse(format!("session: {e}")))
}

fn bounded_output(target: &Target, tool: &str) -> Result<String> {
    let out = run_tool(target, tool)?;
    if out.len() <= EMBED_CAP {
        return Ok(out);
    }
    let keep = EMBED_CAP - TRUNCATION_MARKER.len();
    let mut end = keep;
    while !out.is_char_boundary(end) {
        end -= 1;
    }
    Ok(format!("{}{}", &out[..end], TRUNCATION_MARKER))
}

fn target_line(target: &TargetSummary) -> String {
    format!(
        "target: {} {} {}-bit {} entry {:#x} sections {} symbols {}",
        target.format,
        target.arch,
        target.bits,
        if target.little_endian { "little" } else { "big" },
        target.entry,
        target.sections,
        target.symbols,
    )
}

fn line(record: &Record) -> String {
    let head = if record.tool.is_empty() {
        record.summary.clone()
    } else {
        format!("{}: {}", record.tool, record.summary)
    };
    match &record.output {
        None => head,
        Some(out) => format!("{head} [{out}]"),
    }
}

fn save(dir: &Path, session: &Session) -> Result<()> {
    let raw = serde_json::to_vec_pretty(session)
        .map_err(|e| Error::Parse(format!("session: {e}")))?;
    fs::write(session_path(dir, &session.id), raw).map_err(Error::Io)
}

fn session_path(dir: &Path, id: &str) -> std::path::PathBuf {
    dir.join(format!("{id}.json"))
}

fn next_id(dir: &Path) -> Result<String> {
    let counter = dir.join("next");
    let current = fs::read_to_string(&counter)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let next = current + 1;
    fs::write(&counter, next.to_string()).map_err(Error::Io)?;
    Ok(next.to_string())
}

#[cfg(test)]
mod tests {
    use super::{bounded_output, diff, open, record, record_at, ARGUMENTS_CAP, EMBED_CAP};
    use crate::{Arch, Format, Target};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("rea-session-{stamp}-{n}"))
    }

    fn fixture_target() -> Target {
        Target {
            path: "fixture.elf".to_string(),
            format: Format::Elf,
            arch: Arch::X86_64,
            bits: 64,
            little_endian: true,
            entry: 0x1000,
            sections: Vec::new(),
            symbols: Vec::new(),
            bytes: vec![b'A'; EMBED_CAP * 2],
            page_map: None,
        }
    }

    /// A minimal two-section ELF the loader accepts, written to disk so the
    /// session records identity evidence from a real file.
    fn elf_fixture() -> Vec<u8> {
        let shstr = b"\0.text\0.shstrtab\0";
        let shstr_off = 64u64;
        let shoff = shstr_off + shstr.len() as u64;
        let mut file = vec![0u8; shoff as usize + 3 * 64];
        file[0..4].copy_from_slice(b"\x7fELF");
        file[4] = 2;
        file[5] = 1;
        file[6] = 1;
        file[16..18].copy_from_slice(&1u16.to_le_bytes());
        file[18..20].copy_from_slice(&62u16.to_le_bytes());
        file[20..24].copy_from_slice(&1u32.to_le_bytes());
        file[40..48].copy_from_slice(&shoff.to_le_bytes());
        file[52..54].copy_from_slice(&64u16.to_le_bytes());
        file[58..60].copy_from_slice(&64u16.to_le_bytes());
        file[60..62].copy_from_slice(&3u16.to_le_bytes());
        file[62..64].copy_from_slice(&2u16.to_le_bytes());
        file[shstr_off as usize..shstr_off as usize + shstr.len()].copy_from_slice(shstr);
        for (index, name, ty, flags, addr, off, size) in [
            (1usize, 1u32, 1u32, 6u64, 0x1000u64, 0u64, 0u64),
            (2, 7, 3, 0, 0, shstr_off, shstr.len() as u64),
        ] {
            let at = shoff as usize + index * 64;
            file[at..at + 4].copy_from_slice(&name.to_le_bytes());
            file[at + 4..at + 8].copy_from_slice(&ty.to_le_bytes());
            file[at + 8..at + 16].copy_from_slice(&flags.to_le_bytes());
            file[at + 16..at + 24].copy_from_slice(&addr.to_le_bytes());
            file[at + 24..at + 32].copy_from_slice(&off.to_le_bytes());
            file[at + 32..at + 40].copy_from_slice(&size.to_le_bytes());
            file[at + 48..at + 56].copy_from_slice(&1u64.to_le_bytes());
        }
        file
    }

    #[test]
    fn open_records_identity_for_a_loadable_binary() {
        let dir = scratch();
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("fixture.elf");
        std::fs::write(&bin, elf_fixture()).unwrap();
        let session = open(&dir, bin.to_str().unwrap()).unwrap();
        let target = session.target.as_ref().unwrap();
        assert_eq!(target.format, "elf");
        assert_eq!(target.arch, "x86_64");
        assert_eq!(target.bits, 64);
        assert!(target.little_endian);
        assert_eq!(target.sections, 3);
        assert_eq!(target.symbols, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_without_a_binary_keeps_the_path_optional() {
        let dir = scratch();
        let session = open(&dir, "missing.bin").unwrap();
        assert!(session.target.is_none());
        assert_eq!(session.path, "missing.bin");
        let session = record(&dir, &session.id, None, "noted", None).unwrap();
        assert_eq!(session.records.len(), 1);
        assert!(session.records[0].output.is_none());
        assert_eq!(session.records[0].tool, "");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_embeds_a_named_command_output() {
        let dir = scratch();
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("fixture.elf");
        std::fs::write(&bin, elf_fixture()).unwrap();
        let session = open(&dir, bin.to_str().unwrap()).unwrap();
        let session = record(&dir, &session.id, Some("info"), "identity", None).unwrap();
        let output = session.records[0].output.as_ref().unwrap();
        assert!(output.contains("\"format\": \"elf\""));
        assert_eq!(session.records[0].tool, "info");
        // The record re-runs against the file; a missing binary errors.
        std::fs::remove_file(&bin).unwrap();
        assert!(record(&dir, &session.id, Some("strings"), "s", None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn embedded_output_is_capped_and_marked() {
        let target = fixture_target();
        let out = bounded_output(&target, "strings").unwrap();
        assert_eq!(out.len(), EMBED_CAP);
        assert!(out.ends_with("[truncated]"));
        assert!(out.contains("\"value\": \"AAA"));
        assert!(bounded_output(&target, "nope").is_err());
    }

    #[test]
    fn diff_compares_identity_evidence_and_tool_records() {
        let mapped = super::Session {
            id: "1".to_string(),
            path: "a.bin".to_string(),
            target: Some(super::TargetSummary {
                format: "elf".to_string(),
                arch: "x86_64".to_string(),
                bits: 64,
                little_endian: true,
                entry: 0x1000,
                sections: 3,
                symbols: 0,
            }),
            records: vec![super::Record {
                tool: "info".to_string(),
                summary: "identity".to_string(),
                output: Some("{\"format\": \"elf\"}".to_string()),
                arguments: None,
                timestamp: None,
            }],
        };
        let plain = super::Session {
            id: "2".to_string(),
            path: "b.bin".to_string(),
            target: None,
            records: vec![super::Record {
                tool: "".to_string(),
                summary: "mach-o".to_string(),
                output: None,
                arguments: None,
                timestamp: None,
            }],
        };
        let got = diff(&mapped, &plain);
        assert_eq!(
            got.only_left,
            vec![
                "target: elf x86_64 64-bit little entry 0x1000 sections 3 symbols 0".to_string(),
                "info: identity [{\"format\": \"elf\"}]".to_string(),
            ]
        );
        assert_eq!(got.only_right, vec!["mach-o".to_string()]);
        // Same identity on both sides does not show as a difference.
        let same = super::Session { id: "3".to_string(), ..mapped.clone() };
        let got = diff(&mapped, &same);
        assert!(got.only_left.is_empty());
        assert!(got.only_right.is_empty());
    }

    #[test]
    fn open_record_and_diff() {
        let dir = scratch();
        let left = open(&dir, "a.bin").unwrap();
        let right = open(&dir, "b.bin").unwrap();
        let left = record(&dir, &left.id, None, "mach-o", None).unwrap();
        let right = record(&dir, &right.id, None, "elf", None).unwrap();
        let got = diff(&left, &right);
        assert_eq!(got.only_left, vec!["mach-o".to_string()]);
        assert_eq!(got.only_right, vec!["elf".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evidence_export_maps_identity_and_records_with_nulls_for_unknown() {
        let dir = scratch();
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("fixture.elf");
        std::fs::write(&bin, elf_fixture()).unwrap();
        let session = open(&dir, bin.to_str().unwrap()).unwrap();
        let session = record(&dir, &session.id, Some("info"), "identity", None).unwrap();
        let session = record(&dir, &session.id, None, "noted", None).unwrap();
        let export = super::export_evidence(&session);
        assert_eq!(export.path, bin.to_str().unwrap().to_string());
        assert_eq!(export.identity.as_ref().unwrap().format, "elf");
        assert_eq!(export.session_handle, None);
        assert_eq!(export.live_mapping, None);
        assert_eq!(export.records.len(), 2);
        assert_eq!(export.records[0].session, session.id);
        assert_eq!(export.records[0].tool, "info");
        assert_eq!(export.records[0].arguments, None);
        // `record` stamps unix seconds from the clock; the export copies it.
        assert!(export.records[0].timestamp.is_some());
        assert_eq!(export.records[0].output.as_ref().unwrap(), session.records[0].output.as_ref().unwrap());
        assert_eq!(export.records[1].tool, "");
        assert_eq!(export.records[1].output, None);
        // Serialized shape carries the null fields explicitly.
        let value = serde_json::to_value(&export).unwrap();
        let record = &value["records"][0];
        assert_eq!(record["arguments"], serde_json::Value::Null);
        assert!(record["timestamp"].is_u64());
        assert_eq!(value["session_handle"], serde_json::Value::Null);
        assert_eq!(value["live_mapping"], serde_json::Value::Null);
        assert_eq!(record["session"], session.id);
        assert!(record["output"].as_str().unwrap().contains("\"format\": \"elf\""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evidence_export_carries_the_truncation_marker() {
        let dir = scratch();
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("fixture.elf");
        // The appended printable run makes the embedded `strings` output
        // exceed the cap, so the marker survives into the export.
        let mut bytes = elf_fixture();
        bytes.extend(std::iter::repeat(b'A').take(EMBED_CAP * 2));
        std::fs::write(&bin, bytes).unwrap();
        let session = open(&dir, bin.to_str().unwrap()).unwrap();
        let session = record(&dir, &session.id, Some("strings"), "big run", None).unwrap();
        assert!(session.records[0].output.as_ref().unwrap().ends_with("[truncated]"));
        let export = super::export_evidence(&session);
        let output = export.records[0].output.as_ref().unwrap();
        assert_eq!(output.len(), EMBED_CAP);
        assert!(output.ends_with("[truncated]"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_stores_a_fixed_timestamp_and_argument_text() {
        let dir = scratch();
        let session = open(&dir, "a.bin").unwrap();
        // The helper takes the timestamp as an explicit u64; the clock is not read.
        let session = record_at(&dir, &session.id, None, "noted", Some("--flag value"), 1_700_000_000)
            .unwrap();
        assert_eq!(session.records[0].timestamp, Some(1_700_000_000));
        assert_eq!(session.records[0].arguments.as_deref(), Some("--flag value"));
        // The export copies both as stored.
        let export = super::export_evidence(&session);
        assert_eq!(export.records[0].timestamp, Some(1_700_000_000));
        assert_eq!(
            export.records[0].arguments,
            Some(serde_json::Value::String("--flag value".to_string()))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_from_the_clock_stamps_unix_seconds() {
        let dir = scratch();
        let session = open(&dir, "a.bin").unwrap();
        let session = record(&dir, &session.id, None, "noted", None).unwrap();
        let stamp = session.records[0].timestamp.unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(now >= stamp && now - stamp < 60, "{stamp} vs {now}");
        assert!(session.records[0].arguments.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn argument_text_is_capped_at_1024_bytes() {
        let dir = scratch();
        let session = open(&dir, "a.bin").unwrap();
        // 700 two-byte characters: the cap falls back to a character boundary.
        let long = "é".repeat(700);
        let session = record_at(&dir, &session.id, None, "noted", Some(&long), 1)
            .unwrap();
        let stored = session.records[0].arguments.as_ref().unwrap();
        assert_eq!(stored.len(), ARGUMENTS_CAP);
        assert!(stored.chars().all(|c| c == 'é'));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_session_file_without_the_new_fields_still_loads() {
        let dir = scratch();
        std::fs::create_dir_all(&dir).unwrap();
        // A record written before the timestamp and arguments fields existed.
        let raw = br#"{
  "id": "1",
  "path": "a.bin",
  "records": [
    { "tool": "", "summary": "mach-o" }
  ]
}"#;
        std::fs::write(dir.join("1.json"), raw).unwrap();
        let session = super::load(&dir, "1").unwrap();
        assert_eq!(session.records[0].summary, "mach-o");
        assert_eq!(session.records[0].timestamp, None);
        assert_eq!(session.records[0].arguments, None);
        // The export leaves both fields null rather than fabricating them.
        let export = super::export_evidence(&session);
        assert_eq!(export.records[0].timestamp, None);
        assert_eq!(export.records[0].arguments, None);
        let value = serde_json::to_value(&export).unwrap();
        assert_eq!(value["records"][0]["timestamp"], serde_json::Value::Null);
        assert_eq!(value["records"][0]["arguments"], serde_json::Value::Null);
        let _ = std::fs::remove_dir_all(&dir);
    }
}


