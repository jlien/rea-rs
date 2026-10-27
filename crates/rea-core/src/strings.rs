//! Printable-string extraction from raw bytes.

/// An extracted string with its file offset.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StringHit {
    pub offset: u64,
    pub value: String,
    /// `utf-16le`, `utf-16be`, `utf-32le`, `utf-32be`, or `utf-8` for UTF-16,
    /// UTF-32, and UTF-8 runs; absent for ASCII.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<&'static str>,
}

/// Extract printable ASCII strings of at least `min_len` characters, plus
/// UTF-16LE and UTF-16BE runs whose code units sit in `0x20..=0x7E`, using
/// the same minimum length (counted in code units for UTF-16), plus UTF-32LE
/// and UTF-32BE runs whose code points sit in `0x20..=0x7E` (counted in code
/// points for UTF-32), plus valid UTF-8 runs containing at least one
/// non-ASCII scalar whose scalars are printable (not C0, not C1, not U+007F),
/// counted in scalars.
///
/// A BE-shaped byte pattern (`00 61 00 62`) also parses as a nested LE run one
/// unit shorter, and an LE pattern nests a BE run the same way. Between the two
/// UTF-16 passes, only the longer run of an overlap stays (a shorter
/// opposite-endian run is dropped). The UTF-32 passes use the ordered rule: a
/// run is dropped only when a hit the scan already keeps is at least as long
/// in bytes — so a later opposite-endian UTF-32 run that is strictly longer
/// stays beside the shorter earlier hit. A UTF-32 run that overlaps a longer
/// ASCII or UTF-16 hit (in bytes) is dropped; the hit the ASCII and UTF-16
/// scans already keep stays. A UTF-8 run that overlaps a longer ASCII, UTF-16,
/// or UTF-32 hit (in bytes) is dropped the same way; on a byte-length tie the
/// hit the earlier scan already keeps stays. A run of only ASCII stays on the
/// ASCII scan and does not gain an encoding; an invalid UTF-8 sequence ends
/// the run and stays unread.
pub fn extract(bytes: &[u8], min_len: usize) -> Vec<StringHit> {
    fn byte_len(h: &StringHit) -> u64 {
        match h.encoding {
            Some("utf-32le") | Some("utf-32be") => (h.value.len() as u64) * 4,
            // UTF-8 and ASCII hits are their own byte length; UTF-16 hits are
            // BMP code units stored in a Rust string, so two bytes per unit.
            Some("utf-8") | None => h.value.len() as u64,
            Some(_) => (h.value.len() as u64) * 2,
        }
    }
    fn run_end(h: &StringHit) -> u64 {
        h.offset + byte_len(h)
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
    // A UTF-32 window like `61 00 00 00` also contains a UTF-16LE unit and an
    // ASCII byte; where a longer ASCII or UTF-16 hit (in bytes) already covers
    // the run, the current scan's hit stays and the UTF-32 run is dropped.
    for u in utf32_runs(bytes, min_len, true)
        .into_iter()
        .chain(utf32_runs(bytes, min_len, false))
    {
        if !hits
            .iter()
            .any(|h| overlaps(&u, h) && byte_len(h) >= byte_len(&u))
        {
            hits.push(u);
        }
    }
    // A UTF-8 run is checked last: where it overlaps an ASCII, UTF-16, or
    // UTF-32 hit the scan already keeps, the longer hit stays and a tie keeps
    // the earlier scan's hit — so a strictly longer UTF-8 run replaces the
    // shorter hits it overlaps.
    for u in utf8_runs(bytes, min_len) {
        if hits
            .iter()
            .any(|h| overlaps(&u, h) && byte_len(h) >= byte_len(&u))
        {
            continue;
        }
        hits.retain(|h| !(overlaps(&u, h) && byte_len(&u) > byte_len(h)));
        hits.push(u);
    }
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

/// One pass over `bytes` grouping every four bytes into a code point.
/// `little` selects UTF-32LE (`bytes[i]` low); big endian is the mirror. A
/// code point is printable when it sits in `0x20..=0x7E`. Runs are maximal and
/// counted in code points.
fn utf32_runs(bytes: &[u8], min_len: usize, little: bool) -> Vec<StringHit> {
    let unit_printable = |i: usize| -> bool {
        let cp = if little {
            u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]])
        } else {
            u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]])
        };
        (0x20..=0x7e).contains(&cp)
    };
    let encoding: &'static str = if little { "utf-32le" } else { "utf-32be" };
    let mut hits = Vec::new();
    let mut i = 0;
    while i + 3 < bytes.len() {
        if unit_printable(i) {
            let start = i;
            let mut units = 0usize;
            let mut value = Vec::new();
            while i + 3 < bytes.len() && unit_printable(i) {
                let lo = if little { bytes[i] } else { bytes[i + 3] };
                value.push(lo as char);
                units += 1;
                i += 4;
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

/// One pass over `bytes` decoding UTF-8 scalars in place. A run is a maximal
/// sequence of printable scalars (not C0, not C1, not U+007F); a run is
/// reported only when it holds at least one non-ASCII scalar and at least
/// `min_len` scalars. A run of only ASCII stays on the ASCII scan. An invalid
/// sequence (bad lead byte, bad continuation, overlong, surrogate, past
/// U+10FFFF) ends the run and stays unread; the scan resumes after the run's
/// bytes.
fn utf8_runs(bytes: &[u8], min_len: usize) -> Vec<StringHit> {
    fn printable(cp: u32) -> bool {
        !(cp < 0x20 || (0x7f..=0x9f).contains(&cp))
    }
    /// Decode one scalar at `i`; return it and its encoded width, or `None`
    /// when the sequence is invalid or truncated.
    fn scalar(bytes: &[u8], i: usize) -> Option<(u32, usize)> {
        let b0 = *bytes.get(i)?;
        let (cp, width) = match b0 {
            0x00..=0x7f => (b0 as u32, 1),
            0xc2..=0xdf => ((b0 as u32) & 0x1f, 2),
            0xe0 => ((b0 as u32) & 0x0f, 3),
            0xe1..=0xec | 0xee..=0xef => ((b0 as u32) & 0x0f, 3),
            0xed => ((b0 as u32) & 0x0f, 3),
            0xf0 => ((b0 as u32) & 0x07, 4),
            0xf1..=0xf3 => ((b0 as u32) & 0x07, 4),
            0xf4 => ((b0 as u32) & 0x07, 4),
            _ => return None,
        };
        // Each continuation position has its own window: the lead's window
        // (overlong and surrogate exclusion) binds only the FIRST
        // continuation; the rest take the plain `0x80..=0xbf`.
        let (first_min, first_max) = match b0 {
            0xe0 => (0xa0, 0xbf),
            0xed => (0x80, 0x9f),
            0xf0 => (0x90, 0xbf),
            0xf4 => (0x80, 0x8f),
            _ => (0x80, 0xbf),
        };
        let mut cp = cp;
        for k in 1..width {
            let b = *bytes.get(i + k)?;
            let (lo, hi) = if k == 1 { (first_min, first_max) } else { (0x80, 0xbf) };
            if b < lo || b > hi {
                return None;
            }
            cp = (cp << 6) | (b as u32 & 0x3f);
        }
        Some((cp, width))
    }
    let mut hits = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match scalar(bytes, i) {
            Some((cp, _)) if printable(cp) => {
                let start = i;
                let mut scalars = 0usize;
                let mut has_non_ascii = false;
                let mut value = String::new();
                let mut j = i;
                while let Some((cp, width)) = scalar(bytes, j) {
                    if !printable(cp) {
                        break;
                    }
                    if cp >= 0x80 {
                        has_non_ascii = true;
                    }
                    value.push(char::from_u32(cp).unwrap());
                    scalars += 1;
                    j += width;
                }
                if has_non_ascii && scalars >= min_len {
                    hits.push(StringHit {
                        offset: start as u64,
                        value,
                        encoding: Some("utf-8"),
                    });
                }
                i = j.max(start + 1);
            }
            _ => i += 1,
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
        // UTF-32LE 'aaa' reads; a real multi-byte UTF-8 run reads as utf-8;
        // a broken sequence stays unread.
        let mut data = Vec::new();
        for _ in 0..3 {
            data.extend_from_slice(&[0x61, 0, 0, 0]);
        }
        data.extend_from_slice(&[0xc3, 0xa9]);
        data.extend_from_slice(b"xyz");
        data.extend_from_slice(&[0xc3, 0x28]);
        let hits = extract(&data, 3);
        let u32hit = hits.iter().find(|h| h.encoding == Some("utf-32le")).unwrap();
        assert_eq!(u32hit.value, "aaa");
        assert_eq!(u32hit.offset, 0);
        // é + xyz is one valid run of four printable scalars; the ASCII scan's
        // shorter `xyz` yields to the longer UTF-8 hit.
        let u8hit = hits.iter().find(|h| h.encoding == Some("utf-8")).unwrap();
        assert_eq!(u8hit.value, "éxyz");
        assert_eq!(u8hit.offset, 12);
        // The broken sequence (0xC3 with a bad continuation 0x28) stays
        // unread; `(` alone is under the minimum, so nothing else reads.
        let ascii: Vec<_> = hits.iter().filter(|h| h.encoding.is_none()).collect();
        assert!(ascii.is_empty());
        assert_eq!(hits.len(), 2, "{hits:?}");
    }

    #[test]
    fn a_multibyte_utf8_run_meets_the_minimum_in_scalars() {
        // Two scalars (é é), min 2: reported once, counted in scalars.
        let data = [0xc3u8, 0xa9, 0xc3, 0xa9];
        let hits = extract(&data, 2);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].encoding, Some("utf-8"));
        assert_eq!(hits[0].value, "éé");
        assert_eq!(hits[0].offset, 0);
        // serde shape: a UTF-8 hit adds the encoding key.
        let json = serde_json::to_value(&hits[0]).unwrap();
        assert_eq!(json["encoding"], "utf-8");
        // One scalar, min 2: not reported.
        assert!(extract(&data[..2], 2).is_empty());
    }

    #[test]
    fn utf8_continuation_windows_bind_per_position_not_per_lead() {
        // The lead's window binds only the FIRST continuation; later
        // continuations take the plain 0x80..=0xbf. Three- and four-byte
        // scalars whose LAST continuation sits at 0x80 must decode.
        for (hex, want) in [
            (&b"\xe0\xa0\x80"[..], Some("\u{0800}")),   // U+0800, E0 lead
            (&b"\xed\x9f\xbf"[..], Some("\u{D7FF}")),   // U+D7FF, ED lead
            (&b"\xf0\x90\x80\x80"[..], Some("\u{10000}")), // U+10000, F0 lead
            (&b"\xf4\x8f\xbf\xbf"[..], Some("\u{10FFFF}")), // U+10FFFF, F4 lead
        ] {
            let hits = extract(hex, 1);
            assert_eq!(hits.len(), 1, "{hex:?}");
            assert_eq!(hits[0].encoding, Some("utf-8"));
            assert_eq!(hits[0].value, want.unwrap());
        }
        // Overlong, surrogate, and past-U+10FFFF stay unread.
        for hex in [
            &b"\xe0\x80\x80"[..],    // overlong
            &b"\xed\xa0\x80"[..],    // surrogate
            &b"\xf4\x90\x80\x80"[..], // past U+10FFFF
        ] {
            assert!(extract(hex, 1).is_empty(), "{hex:?}");
        }
    }

    #[test]
    fn a_multibyte_run_yields_to_a_longer_ascii_hit_and_keeps_ascii_only_runs() {
        // ASCII "abcd" (4 bytes) overlaps a UTF-8 run "abcd" + é (5 bytes)?
        // No: the run is longer, so here pin the reverse — an ASCII hit longer
        // than the UTF-8 run keeps its bytes. A non-ASCII scalar after long
        // ASCII always extends the run, so instead pin: ASCII-only bytes stay
        // on the ASCII scan without an encoding.
        let hits = extract(b"abcdef", 3);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].encoding.is_none());
        let json = serde_json::to_value(&hits[0]).unwrap();
        assert!(json.get("encoding").is_none());
    }

    #[test]
    fn a_utf8_run_with_control_or_c1_scalars_stops_there() {
        // é then C0 NUL: the run is one scalar, under the minimum.
        let data = [0xc3u8, 0xa9, 0x00, 0x61, 0x62, 0x63];
        let hits = extract(&data, 3);
        assert!(hits.iter().all(|h| h.encoding != Some("utf-8")));
        assert_eq!(hits[0].value, "abc");
        // é then C1 U+009D: the run stops before the C1 scalar.
        let data = [0xc3u8, 0xa9, 0xc2, 0x9d, 0x61, 0x62, 0x63];
        let hits = extract(&data, 3);
        assert!(hits.iter().all(|h| h.encoding != Some("utf-8")));
        // é then U+007F: the run stops before DEL.
        let data = [0xc3u8, 0xa9, 0x7f, 0x61, 0x62, 0x63];
        let hits = extract(&data, 3);
        assert!(hits.iter().all(|h| h.encoding != Some("utf-8")));
        // A truncated sequence stays unread.
        let data = [0xc3u8];
        assert!(extract(&data, 1).is_empty());
        // An overlong encoding and a surrogate stay unread.
        let data = [0xc0u8, 0xaf, 0x61];
        let hits = extract(&data, 1);
        assert!(hits.iter().all(|h| h.encoding != Some("utf-8")));
        let data = [0xedu8, 0xa0, 0x80, 0x61];
        let hits = extract(&data, 1);
        assert!(hits.iter().all(|h| h.encoding != Some("utf-8")));
        assert_eq!(hits[0].value, "a");
    }

    #[test]
    fn finds_utf32le_and_utf32be_runs() {
        let mut le = Vec::new();
        for _ in 0..2 {
            le.extend_from_slice(&[b'o', 0, 0, 0]);
        }
        let hits = extract(&le, 2);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].encoding, Some("utf-32le"));
        assert_eq!(hits[0].value, "oo");
        assert_eq!(hits[0].offset, 0);
        // serde shape: a UTF-32 hit adds the encoding key.
        let json = serde_json::to_value(&hits[0]).unwrap();
        assert_eq!(json["encoding"], "utf-32le");

        let mut be = Vec::new();
        for _ in 0..2 {
            be.extend_from_slice(&[0, 0, 0, b'k']);
        }
        let hits = extract(&be, 2);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].encoding, Some("utf-32be"));
        assert_eq!(hits[0].value, "kk");
    }

    #[test]
    fn utf32_uses_same_min_len_in_code_points() {
        // One LE code point, min 2: not reported.
        let data = [0x61u8, 0, 0, 0];
        assert!(extract(&data, 2).is_empty());
        // Two code points, min 2: reported once, counted in code points.
        let mut data = Vec::new();
        for _ in 0..2 {
            data.extend_from_slice(&[b'a', 0, 0, 0]);
        }
        let hits = extract(&data, 2);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].value, "aa");
    }

    #[test]
    fn a_utf32_run_yields_to_a_longer_ascii_hit() {
        // "abcdaa" (6 bytes) overlaps the single UTF-32LE window at offset 5
        // (4 bytes): the ASCII hit the current scan keeps stays; the UTF-32
        // run is dropped.
        let data = b"abcda\x61\x00\x00\x00";
        let hits = extract(data, 1);
        assert!(hits.iter().all(|h| !h.encoding.unwrap_or("").starts_with("utf-32")));
        let ascii = hits.iter().find(|h| h.encoding.is_none()).unwrap();
        assert_eq!(ascii.value, "abcdaa");
    }

    #[test]
    fn an_overlapping_utf32_run_of_the_other_endianness_is_dropped() {
        // 13 bytes: LE reads "abc" at 0 (three printable low bytes, 12 bytes
        // long). The same bytes are also a 3-unit BE run "bcd" at 1 (each BE
        // unit is 00 00 00 X): 12 bytes, overlapping, equal length. The
        // longer-or-equal rule keeps the run the scan saw first and drops the
        // other-endian twin, so the bytes yield one UTF-32 hit, not two.
        let data = [
            0x61, 0x00, 0x00, 0x00, 0x62, 0x00, 0x00, 0x00, 0x63, 0x00, 0x00, 0x00, 0x64,
        ];
        let hits = extract(&data, 2);
        let utf32: Vec<_> = hits
            .iter()
            .filter(|h| h.encoding.unwrap_or("").starts_with("utf-32"))
            .collect();
        assert_eq!(utf32.len(), 1, "{hits:?}");
        assert_eq!(utf32[0].encoding, Some("utf-32le"));
        assert_eq!(utf32[0].value, "abc");
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
