//! Go toolchain build info (`debug/buildinfo`).
//!
//! The linker plants a 32-byte header on a 16-byte boundary. Bit 1 of the
//! flags byte means the version and module strings follow the header as
//! uvarint-prefixed blobs. The pre-1.18 form stores two file offsets. A null
//! or out-of-range offset is reported and is not treated as a host pointer.

use crate::{Error, Result};

const MAGIC: &[u8] = b"\xff Go buildinf:";
const HEADER_SIZE: usize = 32;
const ALIGN: usize = 16;
/// `encoding/binary.MaxVarintLen64`.
const MAX_UVARINT_LEN: usize = 10;
/// Flags bit 1: version and module strings are inline after the header.
const FLAG_INLINE: u8 = 0x2;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GoBuildInfo {
    pub version: String,
    /// Module info text with the 16-byte sentinels stripped, if that framing is present.
    pub modules: String,
}

/// `Ok(None)` when the magic is absent. `Err` when the magic is present but the
/// blob is truncated or the varints are invalid.
pub fn find_build_info(bytes: &[u8]) -> Result<Option<GoBuildInfo>> {
    let mut off = 0;
    while off + MAGIC.len() <= bytes.len() {
        if bytes[off..].starts_with(MAGIC) {
            return read_inline(bytes, off).map(Some);
        }
        off += ALIGN;
    }
    Ok(None)
}

fn read_inline(bytes: &[u8], off: usize) -> Result<GoBuildInfo> {
    if bytes.len() - off < HEADER_SIZE {
        return Err(Error::Parse("go buildinfo: truncated header".into()));
    }
    let flags = bytes[off + 15];
    if flags & FLAG_INLINE == 0 {
        return read_pointer(bytes, off);
    }

    let mut pos = off + HEADER_SIZE;
    let version = read_blob(bytes, &mut pos)?;
    let modules = read_blob(bytes, &mut pos)?;
    finish(version, modules)
}

const POINTER_ERROR: &str = "go buildinfo is pointer-based (pre-1.18); not resolved";

/// Pre-1.18 header: ptrSize at byte 14, then two little-endian file offsets at byte 16.
/// Each offset names a Go string header (data pointer, then length), also as file offsets.
fn read_pointer(bytes: &[u8], off: usize) -> Result<GoBuildInfo> {
    let unresolved = || Error::Parse(POINTER_ERROR.into());
    let ptr_size = bytes[off + 14] as usize;
    if ptr_size != 4 && ptr_size != 8 {
        return Err(unresolved());
    }
    let base = off + 16;
    if bytes.len() < base + ptr_size * 2 {
        return Err(unresolved());
    }
    let vers = read_go_string(bytes, read_ptr(bytes, base, ptr_size), ptr_size).ok_or_else(unresolved)?;
    let modules = read_go_string(bytes, read_ptr(bytes, base + ptr_size, ptr_size), ptr_size)
        .ok_or_else(unresolved)?;
    finish(vers, modules)
}

fn read_ptr(bytes: &[u8], at: usize, ptr_size: usize) -> u64 {
    if ptr_size == 4 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as u64
    } else {
        u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
    }
}

fn read_go_string(bytes: &[u8], addr: u64, ptr_size: usize) -> Option<Vec<u8>> {
    if addr == 0 {
        return None;
    }
    let at = usize::try_from(addr).ok()?;
    let header = at.checked_add(ptr_size.checked_mul(2)?)?;
    if header > bytes.len() {
        return None;
    }
    let data = read_ptr(bytes, at, ptr_size);
    let len = read_ptr(bytes, at + ptr_size, ptr_size);
    if data == 0 || len > (1 << 20) {
        return None;
    }
    let start = usize::try_from(data).ok()?;
    let n = usize::try_from(len).ok()?;
    bytes.get(start..start.checked_add(n)?).map(|raw| raw.to_vec())
}

fn finish(version: Vec<u8>, mut modules: Vec<u8>) -> Result<GoBuildInfo> {
    // cmd/go infoStart / infoEnd: 16 bytes on each side. The byte just
    // before the end sentinel is the module text's trailing newline.
    // Sentinels are arbitrary bytes, so strip before the UTF-8 check.
    if modules.len() >= 33 && modules[modules.len() - 17] == b'\n' {
        let end = modules.len() - 16;
        modules = modules[16..end].to_vec();
    }
    Ok(GoBuildInfo {
        version: bytes_to_string(version)?,
        modules: bytes_to_string(modules)?,
    })
}

/// Go `encoding/binary.Uvarint`. `n <= 0` (truncated or overflow) is an error.
fn uvarint(buf: &[u8]) -> Result<(u64, usize)> {
    let mut x: u64 = 0;
    let mut s: u32 = 0;
    for (i, &b) in buf.iter().take(MAX_UVARINT_LEN + 1).enumerate() {
        if i == MAX_UVARINT_LEN {
            return Err(Error::Parse("go buildinfo: bad uvarint".into()));
        }
        if b < 0x80 {
            if i == MAX_UVARINT_LEN - 1 && b > 1 {
                return Err(Error::Parse("go buildinfo: bad uvarint".into()));
            }
            return Ok((x | (u64::from(b) << s), i + 1));
        }
        x |= u64::from(b & 0x7f) << s;
        s += 7;
    }
    Err(Error::Parse("go buildinfo: bad uvarint".into()))
}

fn read_blob(bytes: &[u8], pos: &mut usize) -> Result<Vec<u8>> {
    let (len, n) = uvarint(&bytes[*pos..])?;
    *pos += n;
    let avail = (bytes.len() - *pos) as u64;
    if len > avail {
        return Err(Error::Parse("go buildinfo: truncated string".into()));
    }
    let len = len as usize;
    let end = *pos + len;
    let raw = bytes[*pos..end].to_vec();
    *pos = end;
    Ok(raw)
}

fn bytes_to_string(raw: Vec<u8>) -> Result<String> {
    String::from_utf8(raw).map_err(|_| Error::Parse("go buildinfo: string is not utf-8".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_uvarint(buf: &mut Vec<u8>, mut x: u64) {
        while x >= 0x80 {
            buf.push((x as u8) | 0x80);
            x >>= 7;
        }
        buf.push(x as u8);
    }

    /// 32-byte header at `off`, then inline version and module blobs.
    fn inline_blob(off: usize, flags: u8, version: &str, modules: &str) -> Vec<u8> {
        let mut buf = vec![0u8; off];
        buf.extend_from_slice(MAGIC);
        buf.push(8);
        buf.push(flags);
        buf.extend(std::iter::repeat(0).take(HEADER_SIZE - MAGIC.len() - 2));
        push_uvarint(&mut buf, version.len() as u64);
        buf.extend_from_slice(version.as_bytes());
        push_uvarint(&mut buf, modules.len() as u64);
        buf.extend_from_slice(modules.as_bytes());
        buf
    }

    #[test]
    fn reads_inline_buildinfo_and_strips_sentinels() {
        let mut framed = vec![0xABu8; 16];
        framed.extend_from_slice(b"path\texample.com/mod\n");
        framed.extend(std::iter::repeat(0xCD).take(16));
        assert!(framed.len() >= 33);
        assert_eq!(framed[framed.len() - 17], b'\n');

        let mut buf = vec![0u8; 16];
        buf.extend_from_slice(MAGIC);
        buf.push(8);
        buf.push(FLAG_INLINE);
        buf.extend(std::iter::repeat(0).take(HEADER_SIZE - MAGIC.len() - 2));
        push_uvarint(&mut buf, b"go1.22.0".len() as u64);
        buf.extend_from_slice(b"go1.22.0");
        push_uvarint(&mut buf, framed.len() as u64);
        buf.extend_from_slice(&framed);

        let info = find_build_info(&buf).unwrap().unwrap();
        assert_eq!(info.version, "go1.22.0");
        assert_eq!(info.modules, "path\texample.com/mod\n");
    }

    #[test]
    fn absent_magic_is_none() {
        assert_eq!(
            find_build_info(b"not a go binary, just text").unwrap(),
            None
        );
        assert_eq!(find_build_info(&[]).unwrap(), None);
    }

    #[test]
    fn pointer_form_is_an_error() {
        let buf = inline_blob(0, 0x00, "go1.17", "mod");
        let err = find_build_info(&buf).unwrap_err();
        assert!(
            matches!(err, Error::Parse(ref msg) if msg == "go buildinfo is pointer-based (pre-1.18); not resolved"),
            "{err:?}"
        );
    }

    #[test]
    fn pointer_offsets_resolve_inside_the_file() {
        let mut buf = vec![0u8; 115];
        buf[..MAGIC.len()].copy_from_slice(MAGIC);
        buf[14] = 4;
        buf[16..20].copy_from_slice(&64u32.to_le_bytes());
        buf[20..24].copy_from_slice(&80u32.to_le_bytes());
        buf[64..68].copy_from_slice(&96u32.to_le_bytes());
        buf[68..72].copy_from_slice(&8u32.to_le_bytes());
        buf[80..84].copy_from_slice(&112u32.to_le_bytes());
        buf[84..88].copy_from_slice(&3u32.to_le_bytes());
        buf[96..104].copy_from_slice(b"go1.17.0");
        buf[112..115].copy_from_slice(b"mod");
        let info = find_build_info(&buf).unwrap().unwrap();
        assert_eq!(info.version, "go1.17.0");
        assert_eq!(info.modules, "mod");

        buf[16..20].copy_from_slice(&10_000u32.to_le_bytes());
        let err = find_build_info(&buf).unwrap_err();
        assert!(
            matches!(err, Error::Parse(ref msg) if msg == POINTER_ERROR),
            "{err:?}"
        );
    }
}
