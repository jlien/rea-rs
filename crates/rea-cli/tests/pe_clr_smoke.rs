//! A synthetic .NET PE runs through `rea pe` end to end: the CLI reads the
//! file, parses the PE, follows the CLR runtime directory into the metadata,
//! and reports the Assembly row.

use std::process::Command;

fn le16(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}

fn le32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

fn le64(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

/// `#~` stream: valid bit 32 (Assembly), one row — hash id 0, version
/// 1.2.3.4, flags 0, public-key blob index 1, name index 1, culture index 6.
fn assembly_table() -> Vec<u8> {
    let mut tilde = vec![0u8; 24];
    tilde[4] = 2;
    tilde[7] = 1;
    let valid: u64 = 1 << 32;
    tilde[8..16].copy_from_slice(&valid.to_le_bytes());
    tilde.extend_from_slice(&1u32.to_le_bytes()); // one Assembly row
    tilde.extend_from_slice(&0u32.to_le_bytes());
    tilde.extend_from_slice(&1u16.to_le_bytes());
    tilde.extend_from_slice(&2u16.to_le_bytes());
    tilde.extend_from_slice(&3u16.to_le_bytes());
    tilde.extend_from_slice(&4u16.to_le_bytes());
    tilde.extend_from_slice(&0u32.to_le_bytes());
    tilde.extend_from_slice(&1u16.to_le_bytes());
    tilde.extend_from_slice(&1u16.to_le_bytes());
    tilde.extend_from_slice(&6u16.to_le_bytes());
    tilde
}

/// Metadata BSJB root plus `#~`, `#Strings`, and `#Blob` streams. The heaps
/// hold one Assembly row: name `Demo`, culture `en-US`, public key
/// `deadbeef` under the one-byte length form.
fn bsjb() -> Vec<u8> {
    let version = b"v4.0.30319\0\0";
    let mut meta = Vec::new();
    meta.extend_from_slice(&0x424A_5342u32.to_le_bytes());
    meta.extend_from_slice(&1u16.to_le_bytes());
    meta.extend_from_slice(&1u16.to_le_bytes());
    meta.extend_from_slice(&0u32.to_le_bytes());
    meta.extend_from_slice(&(version.len() as u32).to_le_bytes());
    meta.extend_from_slice(version);
    meta.extend_from_slice(&0u16.to_le_bytes());
    meta.extend_from_slice(&3u16.to_le_bytes());
    let tilde = assembly_table();
    let mut strings = vec![0u8];
    strings.extend_from_slice(b"Demo\0en-US\0");
    let blobs: Vec<u8> = vec![0, 4, 0xde, 0xad, 0xbe, 0xef];
    // Stream headers: offset, size, NUL name, NUL padding to a 4-byte bound.
    // Offsets are relative to the metadata root. Data begins after all the
    // headers: "#~" is 12 bytes, "#Strings" 20, "#Blob" 16.
    let names = ["#~", "#Strings", "#Blob"];
    let data_at = meta.len() as u32
        + names
            .iter()
            .map(|n| (8 + n.len() as u32 + 1).div_ceil(4) * 4)
            .sum::<u32>();
    let mut at = data_at;
    for (name, data) in [
        ("#~", tilde.as_slice()),
        ("#Strings", strings.as_slice()),
        ("#Blob", blobs.as_slice()),
    ] {
        meta.extend_from_slice(&at.to_le_bytes());
        meta.extend_from_slice(&(data.len() as u32).to_le_bytes());
        meta.extend_from_slice(name.as_bytes());
        meta.push(0);
        while meta.len() % 4 != 0 {
            meta.push(0);
        }
        at += data.len() as u32;
    }
    meta.extend_from_slice(&tilde);
    meta.extend_from_slice(&strings);
    meta.extend_from_slice(&blobs);
    meta
}

/// Minimal PE32+ with one section holding a 24-byte COR20 header at RVA
/// 0x1000 and the metadata at RVA 0x1100, reached through data directory 14.
fn pe_file() -> Vec<u8> {
    let metadata = bsjb();
    let mut pe: Vec<u8> = vec![0; 0x80];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3C..0x40].copy_from_slice(&le32(0x80));
    pe.extend_from_slice(b"PE\0\0");
    // COFF header.
    pe.extend_from_slice(&le16(0x8664));
    pe.extend_from_slice(&le16(1));
    pe.extend_from_slice(&le32(0x10203040));
    pe.extend_from_slice(&le32(0));
    pe.extend_from_slice(&le32(0));
    pe.extend_from_slice(&le16(240));
    pe.extend_from_slice(&le16(0x0022));
    // Optional header, PE32+ (240 bytes with 16 data directories).
    let mut opt = vec![0u8; 240];
    opt[0..2].copy_from_slice(&le16(0x020B));
    opt[24..32].copy_from_slice(&le64(0x400000));
    opt[32..36].copy_from_slice(&le32(0x1000));
    opt[36..40].copy_from_slice(&le32(0x200));
    opt[56..60].copy_from_slice(&le32(0x3000));
    opt[60..64].copy_from_slice(&le32(0x400));
    opt[68..70].copy_from_slice(&le16(3));
    opt[108..112].copy_from_slice(&le32(16));
    let clr_dir = 112 + 14 * 8;
    opt[clr_dir..clr_dir + 4].copy_from_slice(&le32(0x1000));
    opt[clr_dir + 4..clr_dir + 8].copy_from_slice(&le32(24));
    pe.extend_from_slice(&opt);
    // Section header.
    let mut sec = [0u8; 40];
    sec[0..6].copy_from_slice(b".text\0");
    sec[8..12].copy_from_slice(&le32(0x2000));
    sec[12..16].copy_from_slice(&le32(0x1000));
    sec[16..20].copy_from_slice(&le32(0x800));
    sec[20..24].copy_from_slice(&le32(0x400));
    sec[36..40].copy_from_slice(&le32(0x6000_0020));
    pe.extend_from_slice(&sec);
    pe.resize(0x400, 0);
    // COR20 header at file 0x400 (RVA 0x1000); metadata at file 0x500
    // (RVA 0x1100).
    let mut cor20 = [0u8; 24];
    cor20[0..4].copy_from_slice(&le32(72));
    cor20[4..6].copy_from_slice(&le16(2));
    cor20[6..8].copy_from_slice(&le16(5));
    cor20[8..12].copy_from_slice(&le32(0x1100));
    cor20[12..16].copy_from_slice(&(metadata.len() as u32).to_le_bytes());
    pe.extend_from_slice(&cor20);
    pe.resize(0x500, 0);
    pe.extend_from_slice(&metadata);
    pe.resize(0x400 + 0x800, 0);
    pe
}

#[test]
fn rea_pe_reports_the_assembly_row_of_a_synthetic_dotnet_pe() {
    let path = std::env::temp_dir().join("rea-pe-clr-smoke.exe");
    std::fs::write(&path, pe_file()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_rea"))
        .args(["pe", path.to_str().unwrap()])
        .output()
        .expect("rea binary runs");
    let _ = std::fs::remove_file(&path);
    assert!(out.status.success(), "exit {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Demo"), "assembly name missing: {stdout}");
    assert!(stdout.contains("en-US"), "culture missing: {stdout}");
    assert!(stdout.contains("deadbeef"), "public key missing: {stdout}");
}
