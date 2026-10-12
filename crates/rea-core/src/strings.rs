//! Printable-string extraction from raw bytes.

/// An extracted string with its file offset.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StringHit {
    pub offset: u64,
    pub value: String,
}

/// Extract printable ASCII strings of at least `min_len` characters.
pub fn extract(bytes: &[u8], min_len: usize) -> Vec<StringHit> {
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
                });
            }
        }
    }
    let end = bytes.len();
    if let Some(s) = start {
        if end - s >= min_len {
            hits.push(StringHit { offset: s as u64, value: String::from_utf8_lossy(&bytes[s..end]).into_owned() });
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
}
