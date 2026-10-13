//! SQLite database header. This does not read schema or pages.

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SqliteHeader {
    pub page_size: u32,
    /// Database size in pages, from the header. Zero means the file has not been written yet.
    pub page_count: u32,
    /// 1 is the legacy rollback journal. 2 is WAL.
    pub write_version: u8,
    pub read_version: u8,
    /// `utf8`, `utf16le`, `utf16be`, or `encoding-{n}`.
    pub text_encoding: String,
    pub schema_format: u32,
    pub user_version: u32,
    pub change_counter: u32,
}

/// Read the 100-byte database header. A file that does not start with
/// `SQLite format 3\0` is `Error::Parse`.
pub fn header(bytes: &[u8]) -> Result<SqliteHeader> {
    const MAGIC: &[u8] = b"SQLite format 3\0";
    if bytes.len() < 100 || !bytes.starts_with(MAGIC) {
        return Err(Error::Parse("sqlite: not a database header".into()));
    }
    let page_raw = u16::from_be_bytes([bytes[16], bytes[17]]);
    let page_size = if page_raw == 1 { 65536 } else { u32::from(page_raw) };
    if page_size < 512 || !page_size.is_power_of_two() {
        return Err(Error::Parse(format!("sqlite: bad page size {page_size}")));
    }
    let text_encoding = match u32::from_be_bytes([bytes[56], bytes[57], bytes[58], bytes[59]]) {
        1 => "utf8".to_string(),
        2 => "utf16le".to_string(),
        3 => "utf16be".to_string(),
        n => format!("encoding-{n}"),
    };
    Ok(SqliteHeader {
        page_size,
        page_count: u32::from_be_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]),
        write_version: bytes[18],
        read_version: bytes[19],
        text_encoding,
        schema_format: u32::from_be_bytes([bytes[44], bytes[45], bytes[46], bytes[47]]),
        user_version: u32::from_be_bytes([bytes[60], bytes[61], bytes[62], bytes[63]]),
        change_counter: u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        let mut bytes = vec![0u8; 100];
        bytes[..16].copy_from_slice(b"SQLite format 3\0");
        bytes[16..18].copy_from_slice(&4096u16.to_be_bytes());
        bytes[18] = 2;
        bytes[19] = 2;
        bytes[24..28].copy_from_slice(&7u32.to_be_bytes());
        bytes[28..32].copy_from_slice(&3u32.to_be_bytes());
        bytes[44..48].copy_from_slice(&4u32.to_be_bytes());
        bytes[56..60].copy_from_slice(&1u32.to_be_bytes());
        bytes[60..64].copy_from_slice(&9u32.to_be_bytes());
        bytes
    }

    #[test]
    fn reads_header_fields() {
        let got = header(&sample()).unwrap();
        assert_eq!(got.page_size, 4096);
        assert_eq!(got.page_count, 3);
        assert_eq!(got.write_version, 2);
        assert_eq!(got.read_version, 2);
        assert_eq!(got.text_encoding, "utf8");
        assert_eq!(got.schema_format, 4);
        assert_eq!(got.user_version, 9);
        assert_eq!(got.change_counter, 7);
    }

    #[test]
    fn page_size_one_means_64k() {
        let mut bytes = sample();
        bytes[16..18].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(header(&bytes).unwrap().page_size, 65536);
    }

    #[test]
    fn rejects_a_short_or_foreign_file() {
        assert!(header(b"SQLite format 3").is_err());
        assert!(header(b"not a database").is_err());
    }
}
