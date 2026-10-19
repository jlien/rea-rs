//! SQLite database header, `sqlite_schema`, one named table's rows, and WAL replay.
//!
//! Row reads are capped by the caller. WAL replay keeps frames through the last
//! valid commit and stops on a salt or checksum mismatch. It does not run SQL.

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
    /// Application id at header offset 68. Zero when the file does not set one.
    pub application_id: u32,
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
        application_id: u32::from_be_bytes([bytes[68], bytes[69], bytes[70], bytes[71]]),
        change_counter: u32::from_be_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]),
    })
}

/// One row of `sqlite_schema` (`sqlite_master`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SqliteObject {
    pub kind: String,
    pub name: String,
    pub table_name: String,
    pub root_page: i64,
    /// `None` when the SQL column is NULL.
    pub sql: Option<String>,
}

/// Read schema objects from the table b-tree rooted at page 1.
///
/// Follows interior pages and cell overflow chains.
pub fn schema(bytes: &[u8]) -> Result<Vec<SqliteObject>> {
    let hdr = header(bytes)?;
    let reserved = u32::from(bytes[20]);
    let usable = hdr
        .page_size
        .checked_sub(reserved)
        .ok_or_else(|| Error::Parse("sqlite: reserved space exceeds the page size".into()))?;
    if usable < 480 {
        return Err(Error::Parse("sqlite: usable page is below 480".into()));
    }
    if (bytes.len() as u64) < u64::from(hdr.page_size) {
        if hdr.page_count == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::Parse("sqlite: file is shorter than one page".into()));
    }
    let enc = match u32::from_be_bytes([bytes[56], bytes[57], bytes[58], bytes[59]]) {
        1 => TextEnc::Utf8,
        2 => TextEnc::Utf16Le,
        3 => TextEnc::Utf16Be,
        n => {
            return Err(Error::Parse(format!(
                "sqlite: unknown text encoding {n}"
            )))
        }
    };
    let file_pages = (bytes.len() as u32) / hdr.page_size;
    let mut seen = vec![false; file_pages as usize + 1];
    let mut out = Vec::new();
    walk_table(
        bytes,
        1,
        hdr.page_size,
        usable,
        enc,
        0,
        &mut seen,
        &mut out,
    )?;
    Ok(out)
}

/// Column strings from one table, at most `limit` rows. `limit` of 0 returns none.
/// A missing table is an error. A root page of 0 or less returns none.
pub fn table_rows(bytes: &[u8], name: &str, limit: usize) -> Result<Vec<Vec<String>>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let limit = limit.min(1024);
    let table = schema(bytes)?
        .into_iter()
        .find(|object| object.kind == "table" && object.name == name)
        .ok_or_else(|| Error::Parse(format!("sqlite: table {name} is missing")))?;
    if table.root_page <= 0 {
        return Ok(Vec::new());
    }
    let root = u32::try_from(table.root_page)
        .map_err(|_| Error::Parse("sqlite: table root page does not fit".into()))?;
    let hdr = header(bytes)?;
    let reserved = u32::from(bytes[20]);
    let usable = hdr
        .page_size
        .checked_sub(reserved)
        .ok_or_else(|| Error::Parse("sqlite: reserved space exceeds the page size".into()))?;
    let enc = match u32::from_be_bytes([bytes[56], bytes[57], bytes[58], bytes[59]]) {
        1 => TextEnc::Utf8,
        2 => TextEnc::Utf16Le,
        3 => TextEnc::Utf16Be,
        n => return Err(Error::Parse(format!("sqlite: unknown text encoding {n}"))),
    };
    let file_pages = (bytes.len() as u32) / hdr.page_size;
    let mut seen = vec![false; file_pages as usize + 1];
    let mut out = Vec::new();
    walk_rows(
        bytes,
        root,
        hdr.page_size,
        usable,
        enc,
        0,
        limit,
        &mut seen,
        &mut out,
    )?;
    Ok(out)
}

/// Overlay committed WAL frames onto a copy of `db`.
///
/// Magic `0x377f0682` checksums big-endian words. Magic `0x377f0683` checksums
/// little-endian words. A bad magic, version, page size, or header checksum is
/// an error. A later frame with the wrong salt or checksum ends the valid prefix.
pub fn apply_wal(db: &[u8], wal: &[u8]) -> Result<Vec<u8>> {
    if wal.len() < 32 {
        return Err(Error::Parse("sqlite: wal header is truncated".into()));
    }
    let magic = be_u32_at(wal, 0);
    let big = match magic {
        0x377f_0682 => true,
        0x377f_0683 => false,
        _ => return Err(Error::Parse("sqlite: bad wal magic".into())),
    };
    if be_u32_at(wal, 4) != 3_007_000 {
        return Err(Error::Parse("sqlite: bad wal version".into()));
    }
    let page_size = be_u32_at(wal, 8);
    if page_size < 8 || page_size % 8 != 0 {
        return Err(Error::Parse("sqlite: wal page size is not a multiple of 8".into()));
    }
    let salt1 = be_u32_at(wal, 16);
    let salt2 = be_u32_at(wal, 20);
    let (sum1, sum2) = wal_checksum(big, &wal[..24], 0, 0);
    if sum1 != be_u32_at(wal, 24) || sum2 != be_u32_at(wal, 28) {
        return Err(Error::Parse("sqlite: wal header checksum failed".into()));
    }
    let frame_len = 24 + page_size as usize;
    let mut committed: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut pending: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut at = 32usize;
    while at + frame_len <= wal.len() {
        let hdr = &wal[at..at + 24];
        let page_no = be_u32_at(hdr, 0);
        let db_size = be_u32_at(hdr, 4);
        if be_u32_at(hdr, 8) != salt1 || be_u32_at(hdr, 12) != salt2 {
            break;
        }
        let page = &wal[at + 24..at + frame_len];
        let (s0, s1) = wal_checksum(big, &hdr[..8], salt1, salt2);
        let (s0, s1) = wal_checksum(big, page, s0, s1);
        if s0 != be_u32_at(hdr, 16) || s1 != be_u32_at(hdr, 20) {
            break;
        }
        if (1..=1_048_576).contains(&page_no) {
            pending.push((page_no, page.to_vec()));
        }
        if db_size != 0 {
            committed.append(&mut pending);
        }
        at += frame_len;
    }
    let mut out = db.to_vec();
    for (page_no, page) in committed {
        let start = (page_no as usize - 1).saturating_mul(page_size as usize);
        let end = start + page_size as usize;
        if end > out.len().saturating_add(wal.len()) {
            continue;
        }
        if out.len() < end {
            out.resize(end, 0);
        }
        out[start..end].copy_from_slice(&page);
    }
    Ok(out)
}

fn be_u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn wal_checksum(big: bool, data: &[u8], mut s0: u32, mut s1: u32) -> (u32, u32) {
    let mut i = 0;
    while i + 8 <= data.len() {
        let (x0, x1) = if big {
            (
                u32::from_be_bytes(data[i..i + 4].try_into().unwrap()),
                u32::from_be_bytes(data[i + 4..i + 8].try_into().unwrap()),
            )
        } else {
            (
                u32::from_le_bytes(data[i..i + 4].try_into().unwrap()),
                u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap()),
            )
        };
        s0 = s0.wrapping_add(x0).wrapping_add(s1);
        s1 = s1.wrapping_add(x1).wrapping_add(s0);
        i += 8;
    }
    (s0, s1)
}

fn walk_rows(
    bytes: &[u8],
    page_no: u32,
    page_size: u32,
    usable: u32,
    enc: TextEnc,
    depth: u32,
    limit: usize,
    seen: &mut [bool],
    out: &mut Vec<Vec<String>>,
) -> Result<()> {
    if out.len() >= limit {
        return Ok(());
    }
    if depth > 64 {
        return Err(Error::Parse("sqlite: table tree is too deep".into()));
    }
    if page_no == 0 || page_no as usize >= seen.len() {
        return Err(Error::Parse(format!("sqlite: bad page {page_no}")));
    }
    if seen[page_no as usize] {
        return Err(Error::Parse(format!("sqlite: page {page_no} repeats")));
    }
    seen[page_no as usize] = true;
    let page = page_bytes(bytes, page_size, page_no)?;
    let base = if page_no == 1 { 100 } else { 0 };
    if page.len() < base + 8 {
        return Err(Error::Parse(format!("sqlite: page {page_no} is truncated")));
    }
    let ncells = usize::from(u16::from_be_bytes([page[base + 3], page[base + 4]]));
    match page[base] {
        0x0d => {
            let ptrs = base + 8;
            for i in 0..ncells {
                if out.len() >= limit {
                    break;
                }
                let off = cell_offset(page, ptrs, i)?;
                out.push(leaf_row(bytes, page, off, page_size, usable, enc)?);
            }
        }
        0x05 => {
            if page.len() < base + 12 {
                return Err(Error::Parse(format!(
                    "sqlite: interior page {page_no} is truncated"
                )));
            }
            let ptrs = base + 12;
            for i in 0..ncells {
                if out.len() >= limit {
                    break;
                }
                let off = cell_offset(page, ptrs, i)?;
                let child = page.get(off..off + 4).ok_or_else(|| {
                    Error::Parse("sqlite: interior cell is truncated".into())
                })?;
                let child = u32::from_be_bytes(child.try_into().unwrap());
                walk_rows(
                    bytes,
                    child,
                    page_size,
                    usable,
                    enc,
                    depth + 1,
                    limit,
                    seen,
                    out,
                )?;
            }
            if out.len() < limit {
                let right = u32::from_be_bytes(page[base + 8..base + 12].try_into().unwrap());
                if right != 0 {
                    walk_rows(
                        bytes,
                        right,
                        page_size,
                        usable,
                        enc,
                        depth + 1,
                        limit,
                        seen,
                        out,
                    )?;
                }
            }
        }
        other => {
            return Err(Error::Parse(format!(
                "sqlite: page {page_no} is not a table b-tree ({other:#x})"
            )))
        }
    }
    Ok(())
}

fn leaf_row(
    file: &[u8],
    page: &[u8],
    cell: usize,
    page_size: u32,
    usable: u32,
    enc: TextEnc,
) -> Result<Vec<String>> {
    let (payload_size, n1) = varint(page, cell)?;
    let (_rowid, n2) = varint(page, cell + n1)?;
    let payload = assemble_payload(file, page, cell + n1 + n2, payload_size, page_size, usable)?;
    let cols = record_columns(&payload, enc)?;
    Ok((0..cols.len()).map(|index| column_text(&cols, index)).collect())
}

#[derive(Clone, Copy)]
enum TextEnc {
    Utf8,
    Utf16Le,
    Utf16Be,
}

fn walk_table(
    bytes: &[u8],
    page_no: u32,
    page_size: u32,
    usable: u32,
    enc: TextEnc,
    depth: u32,
    seen: &mut [bool],
    out: &mut Vec<SqliteObject>,
) -> Result<()> {
    if depth > 64 {
        return Err(Error::Parse("sqlite: schema tree is too deep".into()));
    }
    if page_no == 0 || page_no as usize >= seen.len() {
        return Err(Error::Parse(format!("sqlite: bad page {page_no}")));
    }
    if seen[page_no as usize] {
        return Err(Error::Parse(format!("sqlite: page {page_no} repeats")));
    }
    seen[page_no as usize] = true;
    let page = page_bytes(bytes, page_size, page_no)?;
    let base = if page_no == 1 { 100 } else { 0 };
    if page.len() < base + 8 {
        return Err(Error::Parse(format!("sqlite: page {page_no} is truncated")));
    }
    let ncells = usize::from(u16::from_be_bytes([page[base + 3], page[base + 4]]));
    match page[base] {
        0x0d => {
            let ptrs = base + 8;
            for i in 0..ncells {
                let off = cell_offset(page, ptrs, i)?;
                out.push(leaf_object(bytes, page, off, page_size, usable, enc)?);
            }
        }
        0x05 => {
            if page.len() < base + 12 {
                return Err(Error::Parse(format!(
                    "sqlite: interior page {page_no} is truncated"
                )));
            }
            let ptrs = base + 12;
            for i in 0..ncells {
                let off = cell_offset(page, ptrs, i)?;
                let child = page.get(off..off + 4).ok_or_else(|| {
                    Error::Parse("sqlite: interior cell is truncated".into())
                })?;
                let child = u32::from_be_bytes(child.try_into().unwrap());
                walk_table(bytes, child, page_size, usable, enc, depth + 1, seen, out)?;
            }
            let right = u32::from_be_bytes(page[base + 8..base + 12].try_into().unwrap());
            if right != 0 {
                walk_table(bytes, right, page_size, usable, enc, depth + 1, seen, out)?;
            }
        }
        other => {
            return Err(Error::Parse(format!(
                "sqlite: page {page_no} is not a table b-tree ({other:#x})"
            )))
        }
    }
    Ok(())
}

fn page_bytes(bytes: &[u8], page_size: u32, page_no: u32) -> Result<&[u8]> {
    let start = (page_no as usize - 1)
        .checked_mul(page_size as usize)
        .ok_or_else(|| Error::Parse(format!("sqlite: bad page {page_no}")))?;
    let end = start + page_size as usize;
    bytes.get(start..end).ok_or_else(|| {
        Error::Parse(format!(
            "sqlite: page {page_no} is past the end of the file"
        ))
    })
}

fn cell_offset(page: &[u8], ptrs: usize, index: usize) -> Result<usize> {
    let at = ptrs + index * 2;
    let raw = page
        .get(at..at + 2)
        .ok_or_else(|| Error::Parse("sqlite: cell pointer is past the page".into()))?;
    let off = usize::from(u16::from_be_bytes([raw[0], raw[1]]));
    if off == 0 || off >= page.len() {
        return Err(Error::Parse("sqlite: cell offset is outside the page".into()));
    }
    Ok(off)
}

fn leaf_object(
    file: &[u8],
    page: &[u8],
    cell: usize,
    page_size: u32,
    usable: u32,
    enc: TextEnc,
) -> Result<SqliteObject> {
    let (payload_size, n1) = varint(page, cell)?;
    let (_rowid, n2) = varint(page, cell + n1)?;
    let payload = assemble_payload(file, page, cell + n1 + n2, payload_size, page_size, usable)?;
    let cols = record_columns(&payload, enc)?;
    Ok(object_from_columns(&cols))
}

fn local_payload(usable: u32, payload: usize) -> usize {
    let u = usable as usize;
    let x = u - 35;
    if payload <= x {
        return payload;
    }
    let m = ((u - 12) * 32 / 255) - 23;
    let k = m + ((payload - m) % (u - 4));
    if k <= x {
        k
    } else {
        m
    }
}

fn assemble_payload(
    file: &[u8],
    page: &[u8],
    at: usize,
    payload_size: u64,
    page_size: u32,
    usable: u32,
) -> Result<Vec<u8>> {
    let total = usize::try_from(payload_size)
        .map_err(|_| Error::Parse("sqlite: payload does not fit".into()))?;
    let local = local_payload(usable, total);
    let local_bytes = page.get(at..at + local).ok_or_else(|| {
        Error::Parse("sqlite: local payload is past the page".into())
    })?;
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(local_bytes);
    if total == local {
        return Ok(buf);
    }
    let ptr = page.get(at + local..at + local + 4).ok_or_else(|| {
        Error::Parse("sqlite: overflow pointer is past the page".into())
    })?;
    let mut next = u32::from_be_bytes(ptr.try_into().unwrap());
    let max_hops = (file.len() as u32 / page_size).saturating_add(1);
    let mut guard = 0u32;
    while buf.len() < total {
        if next == 0 || guard > max_hops {
            return Err(Error::Parse("sqlite: overflow chain ended early".into()));
        }
        guard += 1;
        let ov = page_bytes(file, page_size, next)?;
        next = u32::from_be_bytes(ov[0..4].try_into().unwrap());
        let chunk = ov.get(4..usable as usize).ok_or_else(|| {
            Error::Parse("sqlite: overflow page is shorter than the usable size".into())
        })?;
        let need = total - buf.len();
        if chunk.len() >= need {
            buf.extend_from_slice(&chunk[..need]);
        } else {
            buf.extend_from_slice(chunk);
        }
    }
    Ok(buf)
}

fn varint(bytes: &[u8], at: usize) -> Result<(u64, usize)> {
    let mut value = 0u64;
    for i in 0..8 {
        let b = *bytes.get(at + i).ok_or_else(|| {
            Error::Parse("sqlite: truncated varint".into())
        })?;
        value = (value << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    let b = *bytes.get(at + 8).ok_or_else(|| {
        Error::Parse("sqlite: truncated varint".into())
    })?;
    Ok(((value << 8) | u64::from(b), 9))
}

enum Column {
    Null,
    Int(i64),
    Text(String),
    Blob(Vec<u8>),
}

fn record_columns(payload: &[u8], enc: TextEnc) -> Result<Vec<Column>> {
    let (header_size, size_len) = varint(payload, 0)?;
    let header_size = usize::try_from(header_size)
        .map_err(|_| Error::Parse("sqlite: record header does not fit".into()))?;
    if header_size < size_len || header_size > payload.len() {
        return Err(Error::Parse("sqlite: record header is truncated".into()));
    }
    let mut types = Vec::new();
    let mut at = size_len;
    while at < header_size {
        let (serial, n) = varint(payload, at)?;
        at += n;
        if at > header_size {
            return Err(Error::Parse("sqlite: serial type overruns the header".into()));
        }
        types.push(serial);
    }
    let mut body = header_size;
    let mut cols = Vec::with_capacity(types.len());
    for serial in types {
        let (col, n) = read_serial(payload, body, serial, enc)?;
        body += n;
        cols.push(col);
    }
    Ok(cols)
}

fn read_serial(payload: &[u8], at: usize, serial: u64, enc: TextEnc) -> Result<(Column, usize)> {
    let (col, n) = match serial {
        0 => (Column::Null, 0),
        1 => (Column::Int(read_be_int(need(payload, at, 1)?, 8)), 1),
        2 => (Column::Int(read_be_int(need(payload, at, 2)?, 16)), 2),
        3 => (Column::Int(read_be_int(need(payload, at, 3)?, 24)), 3),
        4 => (Column::Int(read_be_int(need(payload, at, 4)?, 32)), 4),
        5 => (Column::Int(read_be_int(need(payload, at, 6)?, 48)), 6),
        6 => (Column::Int(read_be_int(need(payload, at, 8)?, 64)), 8),
        7 => (Column::Null, 8),
        8 => (Column::Int(0), 0),
        9 => (Column::Int(1), 0),
        10 | 11 => {
            return Err(Error::Parse(
                "sqlite: reserved serial type in a schema record".into(),
            ))
        }
        n if n >= 12 && n % 2 == 0 => {
            let len = ((n - 12) / 2) as usize;
            (Column::Blob(need(payload, at, len)?.to_vec()), len)
        }
        n => {
            let len = ((n - 13) / 2) as usize;
            let raw = need(payload, at, len)?;
            (Column::Text(decode_text(raw, enc)), len)
        }
    };
    if at + n > payload.len() && !matches!(serial, 7) {
        return Err(Error::Parse("sqlite: record body is truncated".into()));
    }
    if serial == 7 && at + 8 > payload.len() {
        return Err(Error::Parse("sqlite: record body is truncated".into()));
    }
    Ok((col, n))
}

fn need(payload: &[u8], at: usize, len: usize) -> Result<&[u8]> {
    payload
        .get(at..at + len)
        .ok_or_else(|| Error::Parse("sqlite: record body is truncated".into()))
}

fn read_be_int(bytes: &[u8], bits: u32) -> i64 {
    let mut raw = 0u64;
    for b in bytes {
        raw = (raw << 8) | u64::from(*b);
    }
    let shift = 64 - bits;
    ((raw << shift) as i64) >> shift
}

fn decode_text(bytes: &[u8], enc: TextEnc) -> String {
    match enc {
        TextEnc::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
        TextEnc::Utf16Le => decode_utf16(bytes, false),
        TextEnc::Utf16Be => decode_utf16(bytes, true),
    }
}

fn decode_utf16(bytes: &[u8], big_endian: bool) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| {
            if big_endian {
                u16::from_be_bytes([c[0], c[1]])
            } else {
                u16::from_le_bytes([c[0], c[1]])
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

fn object_from_columns(cols: &[Column]) -> SqliteObject {
    SqliteObject {
        kind: column_text(cols, 0),
        name: column_text(cols, 1),
        table_name: column_text(cols, 2),
        root_page: column_int(cols, 3),
        sql: match cols.get(4) {
            Some(Column::Null) | None => None,
            _ => Some(column_text(cols, 4)),
        },
    }
}

fn column_text(cols: &[Column], index: usize) -> String {
    match cols.get(index) {
        Some(Column::Text(text)) => text.clone(),
        Some(Column::Blob(bytes)) => String::from_utf8_lossy(bytes).into_owned(),
        Some(Column::Int(n)) => n.to_string(),
        Some(Column::Null) | None => String::new(),
    }
}

fn column_int(cols: &[Column], index: usize) -> i64 {
    match cols.get(index) {
        Some(Column::Int(n)) => *n,
        _ => 0,
    }
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
        bytes[68..72].copy_from_slice(&0x0102_0304u32.to_be_bytes());
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
        assert_eq!(got.application_id, 0x0102_0304);
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

    fn put_varint(mut value: u64) -> Vec<u8> {
        if value == 0 {
            return vec![0];
        }
        let mut parts = Vec::new();
        while value > 0 {
            parts.push((value & 0x7f) as u8);
            value >>= 7;
        }
        parts.reverse();
        let last = parts.len() - 1;
        for (i, byte) in parts.iter_mut().enumerate() {
            if i != last {
                *byte |= 0x80;
            }
        }
        parts
    }

    fn text_serial(len: usize) -> u64 {
        (len as u64) * 2 + 13
    }

    fn schema_record(kind: &str, name: &str, table: &str, root: u8, sql: Option<&str>) -> Vec<u8> {
        let mut serials = vec![
            text_serial(kind.len()),
            text_serial(name.len()),
            text_serial(table.len()),
            1,
        ];
        let sql_bytes = sql.unwrap_or("");
        if sql.is_some() {
            serials.push(text_serial(sql_bytes.len()));
        } else {
            serials.push(0);
        }
        let mut header = Vec::new();
        for serial in &serials {
            header.extend(put_varint(*serial));
        }
        let mut size = put_varint((header.len() + 1) as u64);
        if size.len() != 1 {
            size = put_varint((header.len() + size.len()) as u64);
        }
        let mut rec = size;
        rec.extend(header);
        rec.extend_from_slice(kind.as_bytes());
        rec.extend_from_slice(name.as_bytes());
        rec.extend_from_slice(table.as_bytes());
        rec.push(root);
        if sql.is_some() {
            rec.extend_from_slice(sql_bytes.as_bytes());
        }
        rec
    }

    fn leaf_cell(rowid: u64, payload: &[u8]) -> Vec<u8> {
        let mut cell = put_varint(payload.len() as u64);
        cell.extend(put_varint(rowid));
        cell.extend_from_slice(payload);
        cell
    }

    fn blank_db(page_size: usize, pages: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; page_size * pages];
        bytes[..16].copy_from_slice(b"SQLite format 3\0");
        let stored = if page_size == 65536 {
            1u16
        } else {
            page_size as u16
        };
        bytes[16..18].copy_from_slice(&stored.to_be_bytes());
        bytes[18] = 1;
        bytes[19] = 1;
        bytes[21] = 64;
        bytes[22] = 32;
        bytes[23] = 32;
        bytes[28..32].copy_from_slice(&(pages as u32).to_be_bytes());
        bytes[44..48].copy_from_slice(&4u32.to_be_bytes());
        bytes[56..60].copy_from_slice(&1u32.to_be_bytes());
        bytes
    }

    fn write_leaf(page: &mut [u8], header_at: usize, cells: &[Vec<u8>]) {
        let mut cursor = page.len();
        let mut offsets = Vec::new();
        for cell in cells.iter().rev() {
            cursor -= cell.len();
            page[cursor..cursor + cell.len()].copy_from_slice(cell);
            offsets.push(cursor as u16);
        }
        offsets.reverse();
        page[header_at] = 0x0d;
        page[header_at + 3..header_at + 5].copy_from_slice(&(cells.len() as u16).to_be_bytes());
        page[header_at + 5..header_at + 7].copy_from_slice(&(cursor as u16).to_be_bytes());
        let mut at = header_at + 8;
        for off in offsets {
            page[at..at + 2].copy_from_slice(&off.to_be_bytes());
            at += 2;
        }
    }

    #[test]
    fn reads_a_leaf_schema_row_and_a_null_sql() {
        let mut db = blank_db(512, 1);
        let table = schema_record(
            "table",
            "notes",
            "notes",
            2,
            Some("CREATE TABLE notes(id INT)"),
        );
        let view = schema_record("view", "v", "v", 0, None);
        write_leaf(&mut db, 100, &[leaf_cell(1, &table), leaf_cell(2, &view)]);
        let got = schema(&db).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].kind, "table");
        assert_eq!(got[0].name, "notes");
        assert_eq!(got[0].table_name, "notes");
        assert_eq!(got[0].root_page, 2);
        assert_eq!(got[0].sql.as_deref(), Some("CREATE TABLE notes(id INT)"));
        assert_eq!(got[1].kind, "view");
        assert_eq!(got[1].sql, None);
        assert_eq!(got[1].root_page, 0);
    }

    #[test]
    fn follows_an_interior_page_to_the_leaf() {
        let mut db = blank_db(512, 2);
        db[100] = 0x05;
        db[108..112].copy_from_slice(&2u32.to_be_bytes());
        let table = schema_record("index", "notes_id", "notes", 3, Some("CREATE INDEX notes_id ON notes(id)"));
        write_leaf(&mut db[512..], 0, &[leaf_cell(1, &table)]);
        let got = schema(&db).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].kind, "index");
        assert_eq!(got[0].name, "notes_id");
        assert_eq!(got[0].root_page, 3);
    }

    #[test]
    fn decodes_utf16le_schema_text() {
        let kind = [b'h', 0, b'i', 0];
        let serials = [text_serial(kind.len()), text_serial(0), text_serial(0), 8, 0];
        let mut header = Vec::new();
        for serial in serials {
            header.extend(put_varint(serial));
        }
        let mut rec = put_varint((header.len() + 1) as u64);
        rec.extend(header);
        rec.extend_from_slice(&kind);
        let mut db = blank_db(512, 1);
        db[56..60].copy_from_slice(&2u32.to_be_bytes());
        write_leaf(&mut db, 100, &[leaf_cell(1, &rec)]);
        let got = schema(&db).unwrap();
        assert_eq!(got[0].kind, "hi");
        assert_eq!(got[0].name, "");
        assert_eq!(got[0].sql, None);
        assert_eq!(got[0].root_page, 0);
    }

    #[test]
    fn empty_file_with_no_pages_has_no_schema() {
        let mut bytes = sample();
        bytes[28..32].copy_from_slice(&0u32.to_be_bytes());
        assert!(schema(&bytes).unwrap().is_empty());
    }

    #[test]
    fn rejects_a_non_table_root() {
        let mut db = blank_db(512, 1);
        db[100] = 0x0a;
        assert!(schema(&db).is_err());
    }

    fn row_record(text: &str, n: u8) -> Vec<u8> {
        let serials = [text_serial(text.len()), 1u64];
        let mut header = Vec::new();
        for serial in serials {
            header.extend(put_varint(serial));
        }
        let mut rec = put_varint((header.len() + 1) as u64);
        rec.extend(header);
        rec.extend_from_slice(text.as_bytes());
        rec.push(n);
        rec
    }

    fn notes_db(body: &str) -> Vec<u8> {
        let mut db = blank_db(512, 2);
        let table = schema_record(
            "table",
            "notes",
            "notes",
            2,
            Some("CREATE TABLE notes(body TEXT, n INT)"),
        );
        write_leaf(&mut db[..512], 100, &[leaf_cell(1, &table)]);
        write_leaf(&mut db[512..], 0, &[leaf_cell(1, &row_record(body, 1))]);
        db
    }

    #[test]
    fn reads_rows_from_the_named_table() {
        let db = notes_db("hello");
        assert_eq!(
            table_rows(&db, "notes", 32).unwrap(),
            vec![vec!["hello".to_string(), "1".to_string()]]
        );
        assert!(table_rows(&db, "notes", 0).unwrap().is_empty());
        assert!(table_rows(&db, "missing", 4).is_err());
        let mut view = blank_db(512, 1);
        let empty = schema_record("table", "empty", "empty", 0, Some("CREATE TABLE empty(id INT)"));
        write_leaf(&mut view, 100, &[leaf_cell(1, &empty)]);
        assert!(table_rows(&view, "empty", 8).unwrap().is_empty());
    }

    fn wal_file(big: bool, page_size: u32, frames: &[(u32, u32, &[u8])]) -> Vec<u8> {
        let magic = if big { 0x377f_0682u32 } else { 0x377f_0683 };
        let salt1 = 0x1111_1111u32;
        let salt2 = 0x2222_2222u32;
        let mut header = vec![0u8; 32];
        header[0..4].copy_from_slice(&magic.to_be_bytes());
        header[4..8].copy_from_slice(&3_007_000u32.to_be_bytes());
        header[8..12].copy_from_slice(&page_size.to_be_bytes());
        header[16..20].copy_from_slice(&salt1.to_be_bytes());
        header[20..24].copy_from_slice(&salt2.to_be_bytes());
        let (c0, c1) = wal_checksum(big, &header[..24], 0, 0);
        header[24..28].copy_from_slice(&c0.to_be_bytes());
        header[28..32].copy_from_slice(&c1.to_be_bytes());
        let mut out = header;
        for (page_no, db_size, page) in frames {
            let mut frame = vec![0u8; 24 + page.len()];
            frame[0..4].copy_from_slice(&page_no.to_be_bytes());
            frame[4..8].copy_from_slice(&db_size.to_be_bytes());
            frame[8..12].copy_from_slice(&salt1.to_be_bytes());
            frame[12..16].copy_from_slice(&salt2.to_be_bytes());
            frame[24..].copy_from_slice(page);
            let (s0, s1) = wal_checksum(big, &frame[..8], salt1, salt2);
            let (s0, s1) = wal_checksum(big, &frame[24..], s0, s1);
            frame[16..20].copy_from_slice(&s0.to_be_bytes());
            frame[20..24].copy_from_slice(&s1.to_be_bytes());
            out.extend_from_slice(&frame);
        }
        out
    }

    #[test]
    fn wal_replay_keeps_the_last_committed_page() {
        let db = notes_db("old");
        let mut page = vec![0u8; 512];
        write_leaf(&mut page, 0, &[leaf_cell(1, &row_record("new", 2))]);
        let applied = apply_wal(&db, &wal_file(false, 512, &[(2, 2, &page)])).unwrap();
        assert_eq!(table_rows(&applied, "notes", 4).unwrap()[0][0], "new");

        let uncommitted = apply_wal(&db, &wal_file(false, 512, &[(2, 0, &page)])).unwrap();
        assert_eq!(table_rows(&uncommitted, "notes", 4).unwrap()[0][0], "old");

        let mut bad = wal_file(false, 512, &[(2, 2, &page)]);
        bad[32 + 24] ^= 0xff;
        let stopped = apply_wal(&db, &bad).unwrap();
        assert_eq!(table_rows(&stopped, "notes", 4).unwrap()[0][0], "old");

        let header_only = apply_wal(&db, &wal_file(true, 512, &[])).unwrap();
        assert_eq!(header_only, db);
        assert!(apply_wal(&db, &vec![0u8; 32]).is_err());
        let mut odd = wal_file(false, 512, &[]);
        odd[8..12].copy_from_slice(&4u32.to_be_bytes());
        assert!(apply_wal(&db, &odd).is_err());
    }
}
