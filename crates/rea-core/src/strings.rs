//! Printable-string extraction from raw bytes.

/// An extracted string with its file offset.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StringHit {
    pub offset: u64,
    pub value: String,
    /// `utf-16le` or `utf-16be` for UTF-16 runs; absent for ASCII.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<&'static str>,
}

/// Extract printable ASCII strings of at least `min_len` characters, plus
/// UTF-16LE and UTF-16BE runs whose code units sit in `0x20..=0x7E`, using
/// the same minimum length (counted in code units for UTF-16).
///
/// A BE-shaped byte pattern (`00 61 00 62`) also parses as a nested LE run one
/// unit shorter, and an LE pattern nests a BE run the same way. Where the two
/// passes overlap, only the longer (matching-endian) run is kept.
pub fn extract(bytes: &[u8], min_len: usize) -> Vec<StringHit> {
    fn run_end(h: &StringHit) -> u64 {
        h.offset + (h.value.len() as u64) * 2
    }
    fn overlaps(a: &StringHit, b: &StringHit) -> bool {
        a.offset < run_end(b) && b.offset < run_end(a)
    }
    let le = utf16_runs(bytes, min_len, true);
    let be = utf16_runs(bytes, min_len, false);
    let mut utf16: Vec<StringHit> = le
        .into_iter()
        .filter(|l| !be.iter().any(|b| overlaps(l, b) && b.value.len() >= l.value.len()))
        .collect();
    let mut keep_be = Vec::new();
    for b in be {
        if !utf16.iter().any(|l| overlaps(l, &b) && l.value.len() >= b.value.len()) {
            keep_be.push(b);
        }
    }
    utf16.extend(keep_be);

    let mut hits = ascii_runs(bytes, min_len);
    hits.extend(utf16);
    hits.sort_unstable_by_key(|h| h.offset);
    hits
}

fn ascii_runs(bytes: &[u8], min_len: usize) -> Vec<StringHit> {
    let mut hits = Vec::new();
    let mut start = None;

    for (i, &b) in bytes.iter().enumerate() {
        if (0x20..=0x7e).contains(&b) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            if i - s >= min_len {
                hits.push(StringHit {
                    offset: s as u64,
                    value: String::from_utf8_lossy(&bytes[s..i]).into_owned(),
                    encoding: None,
                });
            }
        }
    }
    let end = bytes.len();
    if let Some(s) = start {
        if end - s >= min_len {
            hits.push(StringHit {
                offset: s as u64,
                value: String::from_utf8_lossy(&bytes[s..end]).into_owned(),
                encoding: None,
            });
        }
    }
    hits
}

/// One pass over `bytes` pairing adjacent bytes into code units. `little`
/// selects UTF-16LE (`bytes[i]` low, `bytes[i + 1]` high); big endian is the
/// mirror. A code unit is printable when its high byte is `0x00` and its low
/// byte is `0x20..=0x7E`. Runs are maximal and counted in code units.
fn utf16_runs(bytes: &[u8], min_len: usize, little: bool) -> Vec<StringHit> {
    let unit_printable = |i: usize| -> bool {
        let (lo, hi) = if little {
            (bytes[i], bytes[i + 1])
        } else {
            (bytes[i + 1], bytes[i])
        };
        hi == 0 && (0x20..=0x7e).contains(&lo)
    };
    let encoding: &'static str = if little { "utf-16le" } else { "utf-16be" };
    let mut hits = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if unit_printable(i) {
            let start = i;
            let mut units = 0usize;
            let mut value = Vec::new();
            while i + 1 < bytes.len() && unit_printable(i) {
                let lo = if little { bytes[i] } else { bytes[i + 1] };
                value.push(lo as char);
                units += 1;
                i += 2;
            }
            if units >= min_len {
                hits.push(StringHit {
                    offset: start as u64,
                    value: String::from_iter(value),
                    encoding: Some(encoding),
                });
            }
        } else {
            i += 1;
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_printable_runs() {
        let data = b"abc\0hello world\x00xy";
        let hits = extract(data, 3);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].value, "abc");
        assert_eq!(hits[0].offset, 0);
        assert_eq!(hits[1].value, "hello world");
    }

    #[test]
    fn respects_min_len() {
        let hits = extract(b"ab\0abc", 3);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].value, "abc");
    }

    #[test]
    fn finds_utf16le_runs() {
        // Three LE code units, then a double NUL, then ASCII.
        let data = b"h\0i\0!\0\0tail";
        let hits = extract(data, 3);
        assert_eq!(hits.len(), 2);
        let le = hits.iter().find(|h| h.encoding == Some("utf-16le")).unwrap();
        assert_eq!(le.value, "hi!");
        assert_eq!(le.offset, 0);
        assert_eq!(hits[1].value, "tail");
        // serde shape: a UTF-16 hit adds the encoding key.
        let json = serde_json::to_value(&hits[0]).unwrap();
        assert_eq!(json["encoding"], "utf-16le");
    }

    #[test]
    fn finds_utf16be_runs() {
        let mut data = Vec::new();
        for &b in b"ok" {
            data.push(0);
            data.push(b);
        }
        let hits = extract(&data, 2);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].encoding, Some("utf-16be"));
        assert_eq!(hits[0].value, "ok");
        assert_eq!(hits[0].offset, 0);
    }

    #[test]
    fn utf16_uses_same_min_len_in_code_units() {
        // Two BE code units, min 3: not reported.
        let data = &[0u8, b'a', 0, b'b'];
        assert!(extract(data, 3).is_empty());
        // Three BE code units, min 3: reported once, as utf-16be.
        let data = &[0u8, b'a', 0, b'b', 0, b'c'];
        let hits = extract(data, 3);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].encoding, Some("utf-16be"));
        assert_eq!(hits[0].value, "abc");
    }

    #[test]
    fn ascii_hits_keep_their_shape_and_plain_ascii_is_not_utf16() {
        let hits = extract(b"abcdef", 3);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].encoding.is_none());
        // serde shape: no encoding key on ASCII hits.
        let json = serde_json::to_value(&hits[0]).unwrap();
        assert!(json.get("encoding").is_none());
        assert_eq!(json["value"], "abcdef");
    }

    #[test]
    fn a_run_that_is_neither_ascii_nor_utf16_stays_unread() {
        // UTF-32LE 'a' and non-ASCII UTF-8 stay unread.
        let mut data = vec![0x61, 0, 0, 0, 0xc3, 0xa9];
        data.extend_from_slice(b"xyz");
        let hits = extract(&data, 3);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].encoding.is_none());
        assert_eq!(hits[0].value, "xyz");
    }

    #[test]
    fn merged_hits_sort_by_offset() {
        // Four BE code units, then ASCII between NULs.
        let mut data = Vec::new();
        for _ in 0..4 {
            data.push(0);
            data.push(b'z');
        }
        data.extend_from_slice(b"\0ascii\0");
        let hits = extract(&data, 4);
        let offs: Vec<u64> = hits.iter().map(|h| h.offset).collect();
        assert!(offs.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].encoding, Some("utf-16be"));
        assert_eq!(hits[1].value, "ascii");
    }
}
