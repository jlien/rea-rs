//! Identifying fields from an XML or binary (`bplist00`) Info.plist. A
//! plist with none of these keys is `None` and does not fail the caller.

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PlistInfo {
    pub bundle_id: Option<String>,
    pub bundle_name: Option<String>,
    pub bundle_version: Option<String>,
}

/// `CFBundleIdentifier`, `CFBundleName`, and `CFBundleVersion` from an XML
/// or binary plist.
pub fn identify(bytes: &[u8]) -> Option<PlistInfo> {
    if bytes.starts_with(b"bplist00") {
        return identify_binary(bytes);
    }
    let text = std::str::from_utf8(bytes).ok()?;
    if !text.contains("<plist") && !text.contains("<key>") {
        return None;
    }
    let info = PlistInfo {
        bundle_id: string_after_key(text, "CFBundleIdentifier"),
        bundle_name: string_after_key(text, "CFBundleName"),
        bundle_version: string_after_key(text, "CFBundleVersion"),
    };
    if info.bundle_id.is_none() && info.bundle_name.is_none() && info.bundle_version.is_none() {
        None
    } else {
        Some(info)
    }
}

fn string_after_key(text: &str, key: &str) -> Option<String> {
    let needle = format!("<key>{key}</key>");
    let at = text.find(&needle)?;
    let rest = text.get(at + needle.len()..)?;
    let start = rest.find("<string>")? + "<string>".len();
    let tail = rest.get(start..)?;
    let end = tail.find("</string>")?;
    let value = tail[..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// The object kinds the binary identity walk needs. Everything else is
/// `Skip`: UIDs, data, numbers, arrays, and keyed archives stay unread
/// and do not fail the parse. A date (`0x33`) carries its whole seconds
/// of the Apple absolute time.
enum Obj {
    Str(String),
    /// Whole seconds since 2001-01-01 from a `0x33` marker.
    Date(i64),
    Dict { keys: Vec<u64>, values: Vec<u64> },
    Skip,
}

fn identify_binary(bytes: &[u8]) -> Option<PlistInfo> {
    if bytes.len() < 8 + 32 {
        return None;
    }
    let t = bytes.len() - 32;
    if bytes[t + 5] != 0 {
        return None;
    }
    let offset_size = bytes[t + 6] as usize;
    let ref_size = bytes[t + 7] as usize;
    if !(1..=8).contains(&offset_size) || !(1..=8).contains(&ref_size) {
        return None;
    }
    let num_objects = be_uint(bytes, t + 8, 8)? as usize;
    let top = be_uint(bytes, t + 16, 8)? as usize;
    let table_at = be_uint(bytes, t + 24, 8)? as usize;
    if num_objects == 0 || top >= num_objects || table_at == 0 {
        return None;
    }
    let table_end = table_at.checked_add(num_objects.checked_mul(offset_size)?)?;
    if table_end > bytes.len() {
        return None;
    }
    let bp = BpList { bytes, table_at, num_objects, offset_size, ref_size };
    let Obj::Dict { keys, values } = bp.object(top as u64)? else {
        return None;
    };
    let mut info = PlistInfo { bundle_id: None, bundle_name: None, bundle_version: None };
    for (k, v) in keys.iter().zip(values.iter()) {
        let Some(Obj::Str(key)) = bp.object(*k) else {
            continue;
        };
        let field = match key.as_str() {
            "CFBundleIdentifier" => &mut info.bundle_id,
            "CFBundleName" => &mut info.bundle_name,
            "CFBundleVersion" => &mut info.bundle_version,
            _ => continue,
        };
        match bp.object(*v) {
            Some(Obj::Str(value)) if !value.is_empty() => *field = Some(value),
            Some(Obj::Date(secs)) => *field = Some(secs.to_string()),
            _ => continue,
        }
    }
    if info.bundle_id.is_none() && info.bundle_name.is_none() && info.bundle_version.is_none() {
        None
    } else {
        Some(info)
    }
}

struct BpList<'a> {
    bytes: &'a [u8],
    table_at: usize,
    num_objects: usize,
    offset_size: usize,
    ref_size: usize,
}

impl BpList<'_> {
    fn object(&self, index: u64) -> Option<Obj> {
        if index as usize >= self.num_objects {
            return None;
        }
        let at = self.table_at + index as usize * self.offset_size;
        let off = be_uint(self.bytes, at, self.offset_size)? as usize;
        let marker = *self.bytes.get(off)?;
        match marker >> 4 {
            0x5 => {
                let (len, at) = self.length(off)?;
                let end = at.checked_add(len)?;
                let s = std::str::from_utf8(self.bytes.get(at..end)?).ok()?;
                Some(Obj::Str(s.to_string()))
            }
            0x6 => {
                let (units, at) = self.length(off)?;
                let end = at.checked_add(units.checked_mul(2)?)?;
                let raw = self.bytes.get(at..end)?;
                let units: Vec<u16> =
                    raw.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
                Some(Obj::Str(String::from_utf16(&units).ok()?))
            }
            0x3 => {
                // Only the 8-byte date marker `0x33` decodes. A truncated
                // payload, a non-finite value, or a fraction that is not
                // zero returns `None`, which leaves the field unread and
                // does not fail the parse.
                if marker != 0x33 {
                    return Some(Obj::Skip);
                }
                let raw: [u8; 8] = self.bytes.get(off + 1..off + 9)?.try_into().ok()?;
                let secs = f64::from_be_bytes(raw);
                // Only a finite whole number inside `i64` range is the
                // seconds the payload holds. `as i64` saturates at the `i64`
                // ends, so anything above `i64::MAX` (including `2^63`
                // itself, the first f64 past it) or below `i64::MIN` (the
                // next f64 below `-2^63`) is not representable and stays
                // unread instead of becoming a different integer. `-2^63`
                // itself is representable and stores exactly.
                if !secs.is_finite()
                    || secs.fract() != 0.0
                    || secs < -9.223372036854776e18
                    || secs >= 9.223372036854776e18
                {
                    return None;
                }
                Some(Obj::Date(secs as i64))
            }
            0xD => {
                let (count, at) = self.length(off)?;
                let stride = self.ref_size;
                let keys_at = at;
                let values_at = at.checked_add(count.checked_mul(stride)?)?;
                if values_at.checked_add(count.checked_mul(stride)?)? > self.bytes.len() {
                    return None;
                }
                let mut keys = Vec::with_capacity(count);
                let mut values = Vec::with_capacity(count);
                for i in 0..count {
                    keys.push(be_uint(self.bytes, keys_at + i * stride, stride)?);
                    values.push(be_uint(self.bytes, values_at + i * stride, stride)?);
                }
                Some(Obj::Dict { keys, values })
            }
            _ => Some(Obj::Skip),
        }
    }

    /// The object length at `at`: the marker's low nibble, or an integer
    /// object following it when that nibble is `0xF`.
    fn length(&self, at: usize) -> Option<(usize, usize)> {
        let marker = *self.bytes.get(at)?;
        let info = (marker & 0x0f) as usize;
        if info < 0xF {
            return Some((info, at + 1));
        }
        let int_marker = *self.bytes.get(at + 1)?;
        if int_marker >> 4 != 0x1 {
            return None;
        }
        let size = 1usize << (int_marker & 0x0f);
        let len = be_uint(self.bytes, at + 2, size)? as usize;
        Some((len, at + 2 + size))
    }
}

fn be_uint(bytes: &[u8], at: usize, size: usize) -> Option<u64> {
    let raw = bytes.get(at..at.checked_add(size)?)?;
    let mut v = 0u64;
    for b in raw {
        v = (v << 8) | *b as u64;
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::identify;

    fn sample() -> String {
        "<?xml version=\"1.0\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\"><dict>\n\
         <key>CFBundleIdentifier</key><string>com.example.app</string>\n\
         <key>CFBundleName</key><string>Example</string>\n\
         <key>CFBundleVersion</key><string>1.2.3</string>\n\
         </dict></plist>\n"
            .to_string()
    }

    /// One ASCII string object. Lengths past 14 use the integer form.
    fn ascii_obj(s: &str) -> Vec<u8> {
        let raw = s.as_bytes();
        if raw.len() < 0xF {
            let mut obj = vec![0x50 | raw.len() as u8];
            obj.extend_from_slice(raw);
            obj
        } else {
            let mut obj = vec![0x5F, 0x10, raw.len() as u8];
            obj.extend_from_slice(raw);
            obj
        }
    }

    /// One UTF-16BE string object.
    fn utf16_obj(s: &str) -> Vec<u8> {
        let units: Vec<u16> = s.encode_utf16().collect();
        let mut obj = vec![0x60 | units.len() as u8];
        for u in units {
            obj.extend_from_slice(&u.to_be_bytes());
        }
        obj
    }

    /// One `0x33` date object: 8-byte big-endian IEEE-754 seconds since
    /// 2001-01-01.
    fn date_obj(secs: f64) -> Vec<u8> {
        let mut obj = vec![0x33];
        obj.extend_from_slice(&secs.to_be_bytes());
        obj
    }

    /// A minimal `bplist00` file: one dict of ASCII keys, offset size 1,
    /// ref size 1, and the 32-byte trailer.
    fn bplist(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        // The dict is object 0 (the top); its keys and values follow it.
        let n = entries.len();
        let mut dict = vec![0xD0 | n as u8];
        for i in 0..n {
            dict.push((1 + 2 * i) as u8);
        }
        for i in 0..n {
            dict.push((2 + 2 * i) as u8);
        }
        let mut objects = vec![dict];
        for (k, v) in entries {
            objects.push(ascii_obj(k));
            objects.push(v.clone());
        }
        let mut file = b"bplist00".to_vec();
        let mut offsets = Vec::new();
        for obj in &objects {
            offsets.push(file.len() as u8);
            file.extend_from_slice(obj);
        }
        let table_at = file.len() as u64;
        file.extend_from_slice(&offsets);
        file.extend_from_slice(&[0u8; 5]);
        file.push(0);
        file.push(1);
        file.push(1);
        file.extend_from_slice(&(objects.len() as u64).to_be_bytes());
        file.extend_from_slice(&0u64.to_be_bytes());
        file.extend_from_slice(&table_at.to_be_bytes());
        file
    }

    #[test]
    fn reads_identifying_plist_fields() {
        let got = identify(sample().as_bytes()).unwrap();
        assert_eq!(got.bundle_id.as_deref(), Some("com.example.app"));
        assert_eq!(got.bundle_name.as_deref(), Some("Example"));
        assert_eq!(got.bundle_version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn truncated_plist_does_not_invent_fields() {
        assert!(identify(b"<plist><dict><key>CFBundleName</key>").is_none());
        assert!(identify(b"not a plist").is_none());
    }

    #[test]
    fn reads_binary_plist_identity_keys() {
        let file = bplist(&[
            ("CFBundleIdentifier", ascii_obj("com.example.binary")),
            ("CFBundleName", ascii_obj("Example")),
            ("CFBundleVersion", ascii_obj("1.2.3")),
        ]);
        let got = identify(&file).unwrap();
        assert_eq!(got.bundle_id.as_deref(), Some("com.example.binary"));
        assert_eq!(got.bundle_name.as_deref(), Some("Example"));
        assert_eq!(got.bundle_version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn reads_binary_plist_utf16_values_and_long_ascii_lengths() {
        let long_id = "com.example.application.binary";
        let file = bplist(&[
            ("CFBundleIdentifier", ascii_obj(long_id)),
            ("CFBundleName", utf16_obj("Example")),
        ]);
        let got = identify(&file).unwrap();
        assert_eq!(got.bundle_id.as_deref(), Some(long_id));
        assert_eq!(got.bundle_name.as_deref(), Some("Example"));
        assert_eq!(got.bundle_version.as_deref(), None);
    }

    #[test]
    fn binary_plist_without_the_keys_is_none() {
        assert!(identify(&bplist(&[])).is_none());
        assert!(identify(&bplist(&[("Other", ascii_obj("x"))])).is_none());
        // An empty string value stays unread, like the XML path.
        assert!(identify(&bplist(&[("CFBundleName", ascii_obj(""))])).is_none());
    }

    #[test]
    fn binary_plist_that_does_not_parse_is_none() {
        assert!(identify(b"bplist00").is_none());
        assert!(identify(&bplist(&[("CFBundleName", ascii_obj("x"))])[..39]).is_none());
        // A non-dict top object.
        let file = bplist(&[("CFBundleName", ascii_obj("x"))]);
        let mut not_a_dict = file.clone();
        not_a_dict[8] = 0x50;
        assert!(identify(&not_a_dict).is_none());
        // An object-ref size of zero in the trailer.
        let mut bad_ref = bplist(&[("CFBundleName", ascii_obj("x"))]);
        let n = bad_ref.len();
        bad_ref[n - 32 + 7] = 0;
        assert!(identify(&bad_ref).is_none());
    }

    #[test]
    fn reads_binary_plist_date_values_as_whole_seconds() {
        // 700_000_000 seconds after 2001-01-01 is early 2023.
        let file = bplist(&[
            ("CFBundleIdentifier", date_obj(700_000_000.0)),
            ("CFBundleName", ascii_obj("Example")),
            ("CFBundleVersion", date_obj(-42.0)),
        ]);
        let got = identify(&file).unwrap();
        assert_eq!(got.bundle_id.as_deref(), Some("700000000"));
        assert_eq!(got.bundle_name.as_deref(), Some("Example"));
        assert_eq!(got.bundle_version.as_deref(), Some("-42"));
    }

    #[test]
    fn binary_plist_dates_that_do_not_decode_leave_the_field_unread() {
        // A fraction that is not zero.
        let file = bplist(&[("CFBundleName", date_obj(700_000_000.5))]);
        assert!(identify(&file).is_none());
        // A non-finite value.
        let file = bplist(&[("CFBundleName", date_obj(f64::NAN))]);
        assert!(identify(&file).is_none());
        let file = bplist(&[("CFBundleName", date_obj(f64::INFINITY))]);
        assert!(identify(&file).is_none());
        // A truncated payload: marker plus 6 of 8 bytes, with a valid
        // offset table and trailer after it.
        let mut file = b"bplist00".to_vec();
        let dict = vec![0xD1, 1, 2];
        let key = ascii_obj("CFBundleName");
        let mut date = vec![0x33];
        date.extend_from_slice(&700_000_000.0f64.to_be_bytes()[..6]);
        let objects = [dict, key, date];
        let mut offsets = Vec::new();
        for obj in &objects {
            offsets.push(file.len() as u8);
            file.extend_from_slice(obj);
        }
        let table_at = file.len() as u64;
        file.extend_from_slice(&offsets);
        file.extend_from_slice(&[0u8; 5]);
        file.push(0);
        file.push(1);
        file.push(1);
        file.extend_from_slice(&(objects.len() as u64).to_be_bytes());
        file.extend_from_slice(&0u64.to_be_bytes());
        file.extend_from_slice(&table_at.to_be_bytes());
        assert!(identify(&file).is_none());
        // A float marker (`0x30`) stays unread and does not fail the parse.
        let mut float_obj = vec![0x30];
        float_obj.extend_from_slice(&1.0f32.to_be_bytes());
        let file = bplist(&[("CFBundleName", float_obj), ("CFBundleVersion", ascii_obj("1"))]);
        let got = identify(&file).unwrap();
        assert_eq!(got.bundle_name, None);
        assert_eq!(got.bundle_version.as_deref(), Some("1"));
    }

    #[test]
    fn a_date_past_the_i64_range_is_not_a_saturated_integer() {
        // `2^63` passes a magnitude guard written as `9.3e18`, and `as i64`
        // saturates it to `i64::MAX`: the field would hold a different
        // integer than the payload. It must stay unread.
        let file = bplist(&[
            ("CFBundleVersion", date_obj(9223372036854775808.0)),
            ("CFBundleName", ascii_obj("Example")),
        ]);
        let got = identify(&file).unwrap();
        assert_eq!(got.bundle_version, None);
        assert_eq!(got.bundle_name.as_deref(), Some("Example"));
        // The next f64 below `-i64::MIN` also saturates (to `i64::MIN`).
        let file = bplist(&[("CFBundleVersion", date_obj(-9223372036854777856.0))]);
        assert!(identify(&file).is_none());
        // A magnitude just inside the range still decodes. The largest
        // whole f64 below `2^63` is `2^63 - 1024`.
        let file = bplist(&[("CFBundleVersion", date_obj(9223372036854774784.0))]);
        let got = identify(&file).unwrap();
        assert_eq!(got.bundle_version.as_deref(), Some("9223372036854774784"));
    }
}
