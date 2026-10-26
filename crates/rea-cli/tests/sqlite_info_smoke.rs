//! A database loads through the loader: `rea info` reports format `sqlite`
//! with the application id and the `sqlite_schema` object count, while
//! `rea funcs` still errors.

use std::process::Command;

/// One 512-byte page: application id `0x01020304`, and a leaf schema b-tree
/// with one row — table `notes`, root page 2, NULL SQL.
fn sqlite_db() -> Vec<u8> {
    let mut db = vec![0u8; 512];
    db[..16].copy_from_slice(b"SQLite format 3\0");
    db[16..18].copy_from_slice(&512u16.to_be_bytes());
    db[18] = 1;
    db[19] = 1;
    db[21] = 64;
    db[22] = 32;
    db[23] = 32;
    db[28..32].copy_from_slice(&1u32.to_be_bytes());
    db[44..48].copy_from_slice(&4u32.to_be_bytes());
    db[56..60].copy_from_slice(&1u32.to_be_bytes());
    db[68..72].copy_from_slice(&0x0102_0304u32.to_be_bytes());
    let mut payload: Vec<u8> = vec![6, 23, 23, 23, 1, 0];
    payload.extend_from_slice(b"tablenotesnotes");
    payload.push(2);
    let mut cell = vec![payload.len() as u8, 1];
    cell.extend_from_slice(&payload);
    let at = 512 - cell.len();
    db[at..at + cell.len()].copy_from_slice(&cell);
    db[100] = 0x0d;
    db[103..105].copy_from_slice(&1u16.to_be_bytes());
    db[105..107].copy_from_slice(&(at as u16).to_be_bytes());
    db[108..110].copy_from_slice(&(at as u16).to_be_bytes());
    db
}

#[test]
fn rea_info_reports_sqlite_identity_and_funcs_still_errors() {
    let path = std::env::temp_dir().join(format!("rea-sqlite-info-smoke-{}.db", std::process::id()));
    std::fs::write(&path, sqlite_db()).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_rea"))
        .args(["info", path.to_str().unwrap()])
        .output()
        .expect("rea binary runs");
    assert!(out.status.success(), "exit {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"format\": \"sqlite\""), "{stdout}");
    assert!(stdout.contains("\"arch\": \"unknown\""), "{stdout}");
    assert!(stdout.contains("\"application_id\": 16909060"), "{stdout}");
    assert!(stdout.contains("\"schema_objects\": 1"), "{stdout}");

    let out = Command::new(env!("CARGO_BIN_EXE_rea"))
        .args(["funcs", path.to_str().unwrap()])
        .output()
        .expect("rea binary runs");
    assert!(!out.status.success(), "funcs must still error");
    let _ = std::fs::remove_file(&path);
}
