//! A WASM module loads through the loader: `rea info` reports format `wasm`
//! and the counts `wasm::inspect` computes, while `rea funcs` still errors.

use std::process::Command;

/// Type, function, export, and code sections: one defined function with body
/// `end`, exported as `f` func 0.
fn wasm_module() -> Vec<u8> {
    let mut bytes = b"\0asm\x01\x00\x00\x00".to_vec();
    bytes.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);
    bytes.extend_from_slice(&[3, 2, 1, 0]);
    bytes.extend_from_slice(&[7, 5, 1, 1, b'f', 0, 0]);
    bytes.extend_from_slice(&[10, 4, 1, 2, 0, 0x0b]);
    bytes
}

#[test]
fn rea_info_reports_wasm_identity_and_funcs_still_errors() {
    let path = std::env::temp_dir().join("rea-wasm-info-smoke.wasm");
    std::fs::write(&path, wasm_module()).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_rea"))
        .args(["info", path.to_str().unwrap()])
        .output()
        .expect("rea binary runs");
    assert!(out.status.success(), "exit {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"format\": \"wasm\""), "{stdout}");
    assert!(stdout.contains("\"arch\": \"unknown\""), "{stdout}");
    assert!(stdout.contains("\"functions\": 1"), "{stdout}");
    assert!(stdout.contains("\"exports\": 1"), "{stdout}");
    assert!(stdout.contains("\"sections\": 4"), "{stdout}");

    let out = Command::new(env!("CARGO_BIN_EXE_rea"))
        .args(["funcs", path.to_str().unwrap()])
        .output()
        .expect("rea binary runs");
    assert!(!out.status.success(), "funcs must still error");
    let _ = std::fs::remove_file(&path);
}
