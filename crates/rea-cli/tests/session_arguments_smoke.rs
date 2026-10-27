//! `rea session record` stores an optional arguments string capped at 1024
//! bytes and a unix-seconds timestamp; `rea session export --format evidence`
//! copies both, and omitted arguments stay null.

use std::process::Command;

fn rea(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_rea"))
        .args(args)
        .output()
        .expect("rea binary runs");
    assert!(out.status.success(), "exit {:?}", out.status);
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn record_stores_arguments_and_the_export_echoes_them() {
    let dir = std::env::temp_dir().join(format!("rea-session-args-smoke-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    rea(&["session", "--dir", dir.to_str().unwrap(), "open", "missing.bin"]);
    // A value starting with `--` needs the `--arguments=<text>` form.
    let out = rea(&[
        "session",
        "--dir",
        dir.to_str().unwrap(),
        "record",
        "1",
        "--arguments=--flag value",
        "noted",
    ]);
    assert!(out.contains("\"arguments\": \"--flag value\""), "{out}");
    assert!(out.contains("\"timestamp\""), "{out}");

    // A record without --arguments keeps the field unset in the native file
    // (null in the evidence export below).
    let out = rea(&[
        "session",
        "--dir",
        dir.to_str().unwrap(),
        "record",
        "1",
        "plain",
    ]);
    let value: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(value["records"][1].get("arguments").is_none(), "{out}");

    let out = rea(&[
        "session",
        "--dir",
        dir.to_str().unwrap(),
        "export",
        "1",
        "--format",
        "evidence",
    ]);
    let value: serde_json::Value = serde_json::from_str(&out).expect("evidence export is JSON");
    let records = value["records"].as_array().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["arguments"], "--flag value");
    assert!(records[0]["timestamp"].is_u64());
    assert_eq!(records[1]["arguments"], serde_json::Value::Null);
    assert!(records[1]["timestamp"].is_u64());
    assert_eq!(value["session_handle"], serde_json::Value::Null);
    assert_eq!(value["live_mapping"], serde_json::Value::Null);

    // A 1024-byte cap applies to the stored text.
    let long = "x".repeat(2000);
    let out = rea(&[
        "session",
        "--dir",
        dir.to_str().unwrap(),
        "record",
        "1",
        "--arguments",
        &long,
        "long",
    ]);
    let value: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        value["records"][2]["arguments"].as_str().unwrap().len(),
        1024
    );

    let _ = std::fs::remove_dir_all(&dir);
}
