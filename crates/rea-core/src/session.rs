//! Evidence sessions. Each session is a JSON file of tool records.
//!
//! Opening a session does not keep the binary mapped. A later record stores the
//! tool name and a summary string. Comparing two sessions lists summaries that
//! appear on only one side.

use crate::{Error, Result};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub id: String,
    pub path: String,
    pub records: Vec<Record>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Record {
    pub tool: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SessionDiff {
    pub only_left: Vec<String>,
    pub only_right: Vec<String>,
}

/// Create `dir/<id>.json`. The id is the next decimal counter in that directory.
pub fn open(dir: &Path, path: &str) -> Result<Session> {
    fs::create_dir_all(dir).map_err(Error::Io)?;
    let id = next_id(dir)?;
    let session = Session {
        id,
        path: path.to_string(),
        records: Vec::new(),
    };
    save(dir, &session)?;
    Ok(session)
}

pub fn load(dir: &Path, id: &str) -> Result<Session> {
    let raw = fs::read(session_path(dir, id)).map_err(Error::Io)?;
    serde_json::from_slice(&raw).map_err(|e| Error::Parse(format!("session: {e}")))
}

pub fn record(dir: &Path, id: &str, tool: &str, summary: &str) -> Result<Session> {
    let mut session = load(dir, id)?;
    session.records.push(Record {
        tool: tool.to_string(),
        summary: summary.to_string(),
    });
    save(dir, &session)?;
    Ok(session)
}

/// Summaries of the form `tool: summary`, compared as text.
pub fn diff(left: &Session, right: &Session) -> SessionDiff {
    let left_lines: Vec<String> = left.records.iter().map(line).collect();
    let right_lines: Vec<String> = right.records.iter().map(line).collect();
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

fn line(record: &Record) -> String {
    format!("{}: {}", record.tool, record.summary)
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
    use super::{diff, open, record};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn open_record_and_diff() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rea-session-{stamp}"));
        let left = open(&dir, "a.bin").unwrap();
        let right = open(&dir, "b.bin").unwrap();
        let left = record(&dir, &left.id, "rea_info", "mach-o").unwrap();
        let right = record(&dir, &right.id, "rea_info", "elf").unwrap();
        let got = diff(&left, &right);
        assert_eq!(got.only_left, vec!["rea_info: mach-o".to_string()]);
        assert_eq!(got.only_right, vec!["rea_info: elf".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
