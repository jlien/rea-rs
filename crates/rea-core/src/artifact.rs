//! Static kind of an app bundle, a compiled nib, or an asset catalog.
//!
//! `reconstruct` reads a NIBArchive object list and a BOMStore block directory,
//! including a CARHEADER rendition count. Nib objects render their scalar
//! values beside their keys, capped at 128 objects. The RENDITIONS tree
//! reports a name, pixel dimensions, a pixel-format string, and the payload
//! length after the 184-byte header per rendition; pixel data itself is never
//! decoded. An unrecognized path is `Ok(None)`. A magic
//! that does not fit stays kind-only.

use crate::{Error, Result};
use std::path::Path;

/// `app-bundle`, `nib`, or `asset-catalog` when the path matches that kind.
pub fn identify(path: &Path) -> Result<Option<String>> {
    if path.is_dir() {
        let ios = path.join("Info.plist");
        let mac = path.join("Contents").join("Info.plist");
        if ios.is_file() || mac.is_file() {
            return Ok(Some("app-bundle".to_string()));
        }
        return Ok(None);
    }
    if !path.exists() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "artifact path is missing",
        )));
    }
    let bytes = std::fs::read(path).map_err(Error::Io)?;
    Ok(sniff(&bytes))
}

/// Magic-only sniff. `NIBArchive` is a compiled nib. `BOMStore` is an asset catalog.
pub fn sniff(bytes: &[u8]) -> Option<String> {
    if bytes.starts_with(b"NIBArchive") {
        Some("nib".to_string())
    } else if bytes.starts_with(b"BOMStore") {
        Some("asset-catalog".to_string())
    } else {
        None
    }
}

/// Keys and classes from a NIBArchive, or block names from a BOMStore.
/// A file that is only the magic returns `None`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Reconstruction {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub classes: Option<Vec<String>>,
    /// `"<class>.<key> = <value>"` per coder value, objects capped at 128.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocks: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rendition_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// `"<name> <width>x<height> <pixel-format> payload <n> bytes"` per
    /// rendition, capped at 128.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renditions: Option<Vec<String>>,
}

pub fn reconstruct(bytes: &[u8]) -> Option<Reconstruction> {
    if bytes.starts_with(b"NIBArchive") {
        parse_nib(bytes)
    } else if bytes.starts_with(b"BOMStore") {
        parse_bom(bytes)
    } else {
        None
    }
}

fn parse_nib(bytes: &[u8]) -> Option<Reconstruction> {
    if bytes.len() < 50 {
        return None;
    }
    let object_count = le_u32(bytes, 18)? as usize;
    let object_off = le_u32(bytes, 22)? as usize;
    let key_count = le_u32(bytes, 26)?;
    let key_off = le_u32(bytes, 30)? as usize;
    let value_count = le_u32(bytes, 34)?;
    let value_off = le_u32(bytes, 38)? as usize;
    let class_count = le_u32(bytes, 42)?;
    let class_off = le_u32(bytes, 46)? as usize;
    if key_count > 4096 || class_count > 4096 {
        return None;
    }
    let mut at = key_off;
    let mut keys = Vec::new();
    for _ in 0..key_count {
        let len = nib_varint(bytes, &mut at)?;
        if len > 1024 {
            return None;
        }
        let len = len as usize;
        let raw = bytes.get(at..at + len)?;
        at += len;
        keys.push(String::from_utf8(raw.to_vec()).ok()?);
    }
    at = class_off;
    let mut classes = Vec::new();
    for _ in 0..class_count {
        let name_len = nib_varint(bytes, &mut at)? as usize;
        let extra = nib_varint(bytes, &mut at)? as usize;
        if name_len > 256 || extra > 64 {
            return None;
        }
        at = at.checked_add(extra.checked_mul(4)?)?;
        let raw = bytes.get(at..at + name_len)?;
        at += name_len;
        let end = raw.iter().rposition(|b| *b != 0).map(|i| i + 1).unwrap_or(0);
        classes.push(String::from_utf8(raw[..end].to_vec()).ok()?);
    }
    // Objects: class index, first value index, value count. A truncated table
    // just stops the list instead of failing keys and classes above.
    let mut objects = Vec::new();
    let mut at = object_off;
    while objects.len() < object_count {
        let class_idx = match nib_varint(bytes, &mut at) {
            Some(v) => v as usize,
            None => break,
        };
        let start = match nib_varint(bytes, &mut at) {
            Some(v) => v as usize,
            None => break,
        };
        let count = match nib_varint(bytes, &mut at) {
            Some(v) => v as usize,
            None => break,
        };
        objects.push((class_idx, start, count));
    }
    // Coder values: key index, type tag, payload. A value whose type is not in
    // the table, or whose payload is cut short, renders as `type N`.
    let mut rendered = Vec::new();
    at = value_off;
    for _ in 0..value_count {
        let key_id = match nib_varint(bytes, &mut at) {
            Some(v) => v as usize,
            None => break,
        };
        let tag = match bytes.get(at) {
            Some(&b) => {
                at += 1;
                b
            }
            None => break,
        };
        let key = keys.get(key_id).map(String::as_str).unwrap_or("key?");
        let text = match tag {
            0 => fixed(bytes, &mut at, 1).map(|r| (r[0] as i8).to_string()),
            1 => fixed(bytes, &mut at, 2).map(|r| i16::from_le_bytes(r.try_into().unwrap()).to_string()),
            2 => fixed(bytes, &mut at, 4).map(|r| i32::from_le_bytes(r.try_into().unwrap()).to_string()),
            3 => fixed(bytes, &mut at, 8).map(|r| i64::from_le_bytes(r.try_into().unwrap()).to_string()),
            4 => Some("true".to_string()),
            5 => Some("false".to_string()),
            6 => fixed(bytes, &mut at, 4).map(|r| f32::from_le_bytes(r.try_into().unwrap()).to_string()),
            7 => fixed(bytes, &mut at, 8).map(|r| f64::from_le_bytes(r.try_into().unwrap()).to_string()),
            8 => {
                let mut probe = at;
                match nib_varint(bytes, &mut probe) {
                    Some(n) if probe + n as usize <= bytes.len() => {
                        at = probe + n as usize;
                        Some(format!("{n} bytes"))
                    }
                    _ => None,
                }
            }
            9 => Some("nil".to_string()),
            10 => fixed(bytes, &mut at, 4).map(|r| format!("object {}", u32::from_le_bytes(r.try_into().unwrap()))),
            _ => Some(format!("type {tag}")),
        };
        match text {
            Some(text) => rendered.push(format!("{key} = {text}")),
            None => {
                rendered.push(format!("{key} = type {tag}"));
                break;
            }
        }
    }
    let mut values = Vec::new();
    for (i, &(class_idx, start, count)) in objects.iter().enumerate() {
        if i == MAX_RENDERED_OBJECTS {
            break;
        }
        let class = classes.get(class_idx).map(String::as_str).unwrap_or("class?");
        for tail in rendered.get(start..start.saturating_add(count)).unwrap_or(&[]) {
            values.push(format!("{class}.{tail}"));
        }
    }
    if objects.len() > MAX_RENDERED_OBJECTS {
        values.push(format!(
            "... {} more objects",
            objects.len() - MAX_RENDERED_OBJECTS
        ));
    }
    Some(Reconstruction {
        kind: "nib".into(),
        object_count: Some(object_count as u32),
        keys: Some(keys),
        classes: Some(classes),
        values: Some(values),
        blocks: None,
        rendition_count: None,
        version: None,
        renditions: None,
    })
}

/// Objects rendered before the `... more objects` marker.
const MAX_RENDERED_OBJECTS: usize = 128;

/// Renditions reported before the `... more renditions` marker.
const MAX_RENDITIONS: usize = 128;

fn fixed<'a>(bytes: &'a [u8], at: &mut usize, n: usize) -> Option<&'a [u8]> {
    let raw = bytes.get(*at..*at + n)?;
    *at += n;
    Some(raw)
}

/// NIBArchive varint: 7-bit groups, low group first. The terminal byte has bit 7 set.
fn nib_varint(bytes: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        if shift > 56 {
            return None;
        }
        let byte = *bytes.get(*at)?;
        *at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 != 0 {
            return Some(value);
        }
        shift += 7;
    }
}

fn parse_bom(bytes: &[u8]) -> Option<Reconstruction> {
    if bytes.len() < 32 {
        return None;
    }
    let index_off = be_u32(bytes, 16)? as usize;
    let vars_off = be_u32(bytes, 24)? as usize;
    let count = be_u32(bytes, index_off)? as usize;
    if count > 4096 {
        return None;
    }
    let mut addresses = Vec::with_capacity(count);
    let mut cursor = index_off + 4;
    for _ in 0..count {
        let address = be_u32(bytes, cursor)? as usize;
        let length = be_u32(bytes, cursor + 4)? as usize;
        cursor += 8;
        addresses.push((address, length));
    }
    let var_count = be_u32(bytes, vars_off)? as usize;
    if var_count > 4096 {
        return None;
    }
    cursor = vars_off + 4;
    let mut blocks = Vec::new();
    let mut car: Option<(usize, usize)> = None;
    let mut renditions_id: Option<usize> = None;
    for _ in 0..var_count {
        let index = be_u32(bytes, cursor)? as usize;
        cursor += 4;
        let len = *bytes.get(cursor)? as usize;
        cursor += 1;
        let name = bytes.get(cursor..cursor + len)?;
        cursor += len;
        let name = std::str::from_utf8(name).ok()?.to_string();
        if name == "CARHEADER" {
            car = addresses.get(index).copied();
        } else if name == "RENDITIONS" {
            renditions_id = Some(index);
        }
        blocks.push(name);
    }
    let (rendition_count, version) = match car {
        Some((address, length)) => car_header(bytes, address, length),
        None => (None, None),
    };
    let renditions = renditions_id
        .and_then(|id| addresses.get(id))
        .and_then(|&(address, length)| rendition_facts(bytes, address, length, &addresses));
    Some(Reconstruction {
        kind: "asset-catalog".into(),
        object_count: None,
        keys: None,
        classes: None,
        values: None,
        blocks: Some(blocks),
        rendition_count,
        version,
        renditions,
    })
}

fn car_header(bytes: &[u8], address: usize, length: usize) -> (Option<u32>, Option<String>) {
    let block = match bytes.get(address..address + length) {
        Some(block) if block.len() >= 20 + 128 => block,
        _ => return (None, None),
    };
    let big = match &block[..4] {
        b"RATC" => true,
        b"CTAR" => false,
        _ => return (None, None),
    };
    let count = if big {
        be_u32(block, 16)
    } else {
        le_u32(block, 16)
    };
    let text = &block[20..20 + 128];
    let end = text.iter().position(|b| *b == 0).unwrap_or(text.len());
    let version = std::str::from_utf8(&text[..end]).ok().map(str::to_string);
    (count, version)
}

/// RENDITIONS block: a BOM tree ("tree" descriptor, big-endian like all BOM
/// block internals). Internal nodes point at child node blocks; leaves carry
/// `{ value block, key block }` pairs and chain through `forward`. The value
/// block of a rendition is a CSI header: name at 40, width at 12, height at
/// 16, pixel format at 24. Only those header fields are read, plus the
/// payload length after the 184-byte header; the payload bytes stay
/// untouched.
fn rendition_facts(
    bytes: &[u8],
    address: usize,
    length: usize,
    blocks: &[(usize, usize)],
) -> Option<Vec<String>> {
    let tree = bytes.get(address..address + length)?;
    if tree.len() < 21 {
        return None;
    }
    match tree.get(..4) {
        Some(b"tree") => {}
        _ => return None,
    }
    let total = be_u32(tree, 16)? as usize;
    let mut node = be_u32(tree, 8)? as usize;
    let mut seen = std::collections::HashSet::new();
    let mut facts: Vec<String> = Vec::new();
    loop {
        if !seen.insert(node) {
            break;
        }
        let (addr, len) = match blocks.get(node) {
            Some(&(0, 0)) | None => break,
            Some(&pair) => pair,
        };
        let block = match bytes.get(addr..addr + len) {
            Some(block) if block.len() >= 12 => block,
            _ => break,
        };
        let is_leaf = be_u16(block, 0)?;
        let count = be_u16(block, 2)? as usize;
        let forward = be_u32(block, 4)? as usize;
        if is_leaf != 1 {
            // Internal node: the first entry points at a child node block.
            if count == 0 {
                break;
            }
            node = be_u32(block, 12)? as usize;
            continue;
        }
        for entry in 0..count {
            let at = 12 + entry * 8;
            if at + 8 > block.len() {
                break;
            }
            let value_id = be_u32(block, at)? as usize;
            let line = match blocks.get(value_id) {
                Some(&(0, 0)) | None => None,
                Some(&(vaddr, vlen)) => csi_line(bytes, vaddr, vlen),
            };
            if let Some(line) = line {
                facts.push(line);
            }
            if facts.len() >= MAX_RENDITIONS {
                facts.push(format!("... {} more renditions", total.saturating_sub(facts.len())));
                return Some(facts);
            }
        }
        if forward == 0 {
            break;
        }
        node = forward;
    }
    if facts.is_empty() {
        None
    } else {
        Some(facts)
    }
}

/// Name, dimensions, and pixel format from one CSI header, plus the payload
/// after the 184-byte header: its length, the first 16 bytes as hex, and —
/// for an `SVG` rendition whose payload is valid UTF-8 — the text itself,
/// capped at 256 bytes (cut at a char boundary). No bitmap is expanded and
/// no JPEG is decoded; "Magic alone reconstructs to nothing" stays.
fn csi_line(bytes: &[u8], address: usize, length: usize) -> Option<String> {
    if length < 184 {
        return None;
    }
    match bytes.get(address..address + 4)? {
        b"ISTC" => {}
        _ => return None,
    }
    let width = le_u32(bytes, address + 12)?;
    let height = le_u32(bytes, address + 16)?;
    let raw = bytes.get(address + 24..address + 28)?;
    let name_raw = bytes.get(address + 40..address + 168)?;
    let end = name_raw.iter().position(|&b| b == 0).unwrap_or(name_raw.len());
    let name = String::from_utf8_lossy(&name_raw[..end]);
    let mut line = String::new();
    if !name.is_empty() {
        line.push_str(&name);
        line.push(' ');
    }
    line.push_str(&format!("{width}x{height}"));
    let format = pixel_format(raw);
    if let Some(format) = &format {
        line.push(' ');
        line.push_str(format);
    }
    let payload_len = length.saturating_sub(184);
    line.push_str(&format!(" payload {payload_len} bytes"));
    if payload_len > 0 {
        if let Some(payload) = bytes.get(address + 184..address + length) {
            let head = payload.len().min(16);
            let hex = payload[..head]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            line.push_str(&format!(" {hex}"));
            if format.as_deref() == Some("SVG") {
                if let Ok(text) = std::str::from_utf8(payload) {
                    let mut end = text.len().min(256);
                    while end > 0 && !text.is_char_boundary(end) {
                        end -= 1;
                    }
                    line.push_str(&format!(" text {}", &text[..end]));
                }
            }
        }
    }
    Some(line)
}

/// The pixel-format word is four ASCII bytes, e.g. `ARGB` on disk for BGRA.
/// Zero means the rendition carries no pixels (links, colors, stubs).
fn pixel_format(raw: &[u8]) -> Option<String> {
    if raw.iter().all(|&b| b == 0) {
        return None;
    }
    Some(match raw {
        b"ARGB" => "BGRA8".to_string(),
        b"GA8 " => "GA8".to_string(),
        b"WBGR" => "RGBA16F".to_string(),
        b"GA16" => "GA16".to_string(),
        b"SVG " => "SVG".to_string(),
        b"DATA" => "DATA".to_string(),
        b"GEPJ" => "JPEG".to_string(),
        _ => String::from_utf8_lossy(raw).trim_end().to_string(),
    })
}

fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let raw = bytes.get(at..at + 4)?;
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn be_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let raw = bytes.get(at..at + 4)?;
    Some(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn be_u16(bytes: &[u8], at: usize) -> Option<u16> {
    let raw = bytes.get(at..at + 2)?;
    Some(u16::from_be_bytes([raw[0], raw[1]]))
}

#[cfg(test)]
mod tests {
    use super::{identify, reconstruct, sniff};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn magic_distinguishes_nib_and_asset_catalog() {
        assert_eq!(sniff(b"NIBArchive\0more").as_deref(), Some("nib"));
        assert_eq!(sniff(b"BOMStore\0more").as_deref(), Some("asset-catalog"));
        assert_eq!(sniff(b"short"), None);
    }

    #[test]
    fn directory_with_info_plist_is_an_app_bundle() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("rea-artifact-{stamp}"));
        let app = root.join("Example.app");
        let mac = root.join("Mac.app").join("Contents");
        fs::create_dir_all(&app).unwrap();
        fs::create_dir_all(&mac).unwrap();
        fs::write(app.join("Info.plist"), b"<plist></plist>").unwrap();
        fs::write(mac.join("Info.plist"), b"<plist></plist>").unwrap();
        fs::write(root.join("Widget.nib"), b"NIBArchive").unwrap();
        fs::write(root.join("Assets.car"), b"BOMStore").unwrap();
        assert_eq!(identify(&app).unwrap().as_deref(), Some("app-bundle"));
        assert_eq!(
            identify(&root.join("Mac.app")).unwrap().as_deref(),
            Some("app-bundle")
        );
        assert_eq!(identify(&root.join("Widget.nib")).unwrap().as_deref(), Some("nib"));
        assert_eq!(
            identify(&root.join("Assets.car")).unwrap().as_deref(),
            Some("asset-catalog")
        );
        assert_eq!(identify(&root).unwrap(), None);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn nib_lists_keys_and_classes_and_a_short_magic_stays_empty() {
        assert_eq!(reconstruct(b"NIBArchive"), None);
        let mut buf = vec![0u8; 50];
        buf[..10].copy_from_slice(b"NIBArchive");
        buf[10..14].copy_from_slice(&1u32.to_le_bytes());
        buf[26..30].copy_from_slice(&1u32.to_le_bytes());
        buf[30..34].copy_from_slice(&50u32.to_le_bytes());
        buf[42..46].copy_from_slice(&1u32.to_le_bytes());
        buf[46..50].copy_from_slice(&56u32.to_le_bytes());
        buf.push(0x85);
        buf.extend_from_slice(b"frame");
        buf.push(0x88);
        buf.push(0x80);
        buf.extend_from_slice(b"NSObject");
        let got = reconstruct(&buf).unwrap();
        assert_eq!(got.kind, "nib");
        assert_eq!(got.object_count, Some(0));
        assert_eq!(got.keys.unwrap(), vec!["frame".to_string()]);
        assert_eq!(got.classes.unwrap(), vec!["NSObject".to_string()]);
    }

    #[test]
    fn bom_lists_carheader_and_rendition_facts() {
        assert_eq!(reconstruct(b"BOMStore"), None);
        // Blocks: 0 CARHEADER at 104, 1 tree descriptor at 252, 2 leaf node at
        // 273, 3 CSI header at 293. Vars sit at 68 and end at 101.
        let mut buf = vec![0u8; 480];
        buf[..8].copy_from_slice(b"BOMStore");
        buf[16..20].copy_from_slice(&32u32.to_be_bytes());
        buf[24..28].copy_from_slice(&68u32.to_be_bytes());
        buf[32..36].copy_from_slice(&4u32.to_be_bytes());
        buf[36..40].copy_from_slice(&104u32.to_be_bytes());
        buf[40..44].copy_from_slice(&148u32.to_be_bytes());
        buf[44..48].copy_from_slice(&252u32.to_be_bytes());
        buf[48..52].copy_from_slice(&21u32.to_be_bytes());
        buf[52..56].copy_from_slice(&273u32.to_be_bytes());
        buf[56..60].copy_from_slice(&20u32.to_be_bytes());
        buf[60..64].copy_from_slice(&293u32.to_be_bytes());
        buf[64..68].copy_from_slice(&184u32.to_be_bytes());
        // Vars: CARHEADER -> block 0, RENDITIONS -> block 1.
        buf[68..72].copy_from_slice(&2u32.to_be_bytes());
        buf[72..76].copy_from_slice(&0u32.to_be_bytes());
        buf[76] = 9;
        buf[77..86].copy_from_slice(b"CARHEADER");
        buf[86..90].copy_from_slice(&1u32.to_be_bytes());
        buf[90] = 10;
        buf[91..101].copy_from_slice(b"RENDITIONS");
        // CARHEADER block: magic RATC, rendition count 3, version "1.0".
        buf[104..108].copy_from_slice(b"RATC");
        buf[120..124].copy_from_slice(&3u32.to_be_bytes());
        buf[124..127].copy_from_slice(b"1.0");
        // Tree descriptor: child = block 2 (field at +8), path count 1 (+16).
        buf[252..256].copy_from_slice(b"tree");
        buf[260..264].copy_from_slice(&2u32.to_be_bytes());
        buf[268..272].copy_from_slice(&1u32.to_be_bytes());
        // Leaf node: one entry, value block 3, key block 1.
        buf[273..275].copy_from_slice(&1u16.to_be_bytes());
        buf[275..277].copy_from_slice(&1u16.to_be_bytes());
        buf[285..289].copy_from_slice(&3u32.to_be_bytes());
        buf[289..293].copy_from_slice(&1u32.to_be_bytes());
        // CSI header: 32x16 BGRA named "icon".
        buf[293..297].copy_from_slice(b"ISTC");
        buf[305..309].copy_from_slice(&32u32.to_le_bytes());
        buf[309..313].copy_from_slice(&16u32.to_le_bytes());
        buf[317..321].copy_from_slice(b"ARGB");
        buf[333..338].copy_from_slice(b"icon\0");
        let got = reconstruct(&buf).unwrap();
        assert_eq!(got.blocks.unwrap(), vec!["CARHEADER".to_string(), "RENDITIONS".to_string()]);
        assert_eq!(got.rendition_count, Some(3));
        assert_eq!(got.version.as_deref(), Some("1.0"));
        assert_eq!(
            got.renditions.unwrap(),
            vec!["icon 32x16 BGRA8 payload 0 bytes".to_string()]
        );
    }

    #[test]
    fn csi_payload_prefix_is_reported() {
        // Same catalog as above, but the CSI block is 232 bytes: 184 header
        // plus 48 payload bytes that look like the tag-length-value metadata a
        // real catalog carries there. The line reports the length and the
        // first 16 payload bytes as hex; 0x89 0xff 0xfe land at relative
        // offsets 13-15, so 0x80 falls outside the prefix.
        let mut buf = vec![0u8; 525];
        buf[..8].copy_from_slice(b"BOMStore");
        buf[16..20].copy_from_slice(&32u32.to_be_bytes());
        buf[24..28].copy_from_slice(&68u32.to_be_bytes());
        buf[32..36].copy_from_slice(&4u32.to_be_bytes());
        buf[36..40].copy_from_slice(&104u32.to_be_bytes());
        buf[40..44].copy_from_slice(&148u32.to_be_bytes());
        buf[44..48].copy_from_slice(&252u32.to_be_bytes());
        buf[48..52].copy_from_slice(&21u32.to_be_bytes());
        buf[52..56].copy_from_slice(&273u32.to_be_bytes());
        buf[56..60].copy_from_slice(&20u32.to_be_bytes());
        buf[60..64].copy_from_slice(&293u32.to_be_bytes());
        buf[64..68].copy_from_slice(&232u32.to_be_bytes());
        // Vars: CARHEADER -> block 0, RENDITIONS -> block 1.
        buf[68..72].copy_from_slice(&2u32.to_be_bytes());
        buf[72..76].copy_from_slice(&0u32.to_be_bytes());
        buf[76] = 9;
        buf[77..86].copy_from_slice(b"CARHEADER");
        buf[86..90].copy_from_slice(&1u32.to_be_bytes());
        buf[90] = 10;
        buf[91..101].copy_from_slice(b"RENDITIONS");
        // Tree descriptor and leaf node as before.
        buf[252..256].copy_from_slice(b"tree");
        buf[260..264].copy_from_slice(&2u32.to_be_bytes());
        buf[268..272].copy_from_slice(&1u32.to_be_bytes());
        buf[273..275].copy_from_slice(&1u16.to_be_bytes());
        buf[275..277].copy_from_slice(&1u16.to_be_bytes());
        buf[285..289].copy_from_slice(&3u32.to_be_bytes());
        buf[289..293].copy_from_slice(&1u32.to_be_bytes());
        // CSI header: 32x16 BGRA named "icon".
        buf[293..297].copy_from_slice(b"ISTC");
        buf[305..309].copy_from_slice(&32u32.to_le_bytes());
        buf[309..313].copy_from_slice(&16u32.to_le_bytes());
        buf[317..321].copy_from_slice(b"ARGB");
        buf[333..338].copy_from_slice(b"icon\0");
        // Payload region: a tag-length-value pair, then non-UTF-8 bytes.
        buf[477..481].copy_from_slice(&1001u32.to_le_bytes());
        buf[481..485].copy_from_slice(&20u32.to_le_bytes());
        buf[490..494].copy_from_slice(&[0x89, 0xff, 0xfe, 0x80]);
        let got = reconstruct(&buf).unwrap();
        assert_eq!(
            got.renditions.unwrap(),
            vec!["icon 32x16 BGRA8 payload 48 bytes e9 03 00 00 14 00 00 00 00 00 00 00 00 89 ff fe".to_string()]
        );
    }

    #[test]
    fn an_svg_payload_with_valid_utf8_includes_its_text() {
        // Same catalog shape, but the CSI block names pixel format "SVG " and
        // the payload is valid UTF-8 (an SVG source prefix): the line carries
        // the hex prefix and the text, capped at 256 bytes.
        let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>";
        let csi_len = 184 + svg.len();
        let mut buf = vec![0u8; 525];
        buf[..8].copy_from_slice(b"BOMStore");
        buf[16..20].copy_from_slice(&32u32.to_be_bytes());
        buf[24..28].copy_from_slice(&68u32.to_be_bytes());
        buf[32..36].copy_from_slice(&4u32.to_be_bytes());
        buf[36..40].copy_from_slice(&104u32.to_be_bytes());
        buf[40..44].copy_from_slice(&148u32.to_be_bytes());
        buf[44..48].copy_from_slice(&252u32.to_be_bytes());
        buf[48..52].copy_from_slice(&21u32.to_be_bytes());
        buf[52..56].copy_from_slice(&273u32.to_be_bytes());
        buf[56..60].copy_from_slice(&20u32.to_be_bytes());
        buf[60..64].copy_from_slice(&293u32.to_be_bytes());
        buf[64..68].copy_from_slice(&(csi_len as u32).to_be_bytes());
        // Vars: CARHEADER -> block 0, RENDITIONS -> block 1.
        buf[68..72].copy_from_slice(&2u32.to_be_bytes());
        buf[72..76].copy_from_slice(&0u32.to_be_bytes());
        buf[76] = 9;
        buf[77..86].copy_from_slice(b"CARHEADER");
        buf[86..90].copy_from_slice(&1u32.to_be_bytes());
        buf[90] = 10;
        buf[91..101].copy_from_slice(b"RENDITIONS");
        // Tree descriptor and leaf node as before.
        buf[252..256].copy_from_slice(b"tree");
        buf[260..264].copy_from_slice(&2u32.to_be_bytes());
        buf[268..272].copy_from_slice(&1u32.to_be_bytes());
        buf[273..275].copy_from_slice(&1u16.to_be_bytes());
        buf[275..277].copy_from_slice(&1u16.to_be_bytes());
        buf[285..289].copy_from_slice(&3u32.to_be_bytes());
        buf[289..293].copy_from_slice(&1u32.to_be_bytes());
        // CSI header: 32x16 SVG named "icon".
        buf[293..297].copy_from_slice(b"ISTC");
        buf[305..309].copy_from_slice(&32u32.to_le_bytes());
        buf[309..313].copy_from_slice(&16u32.to_le_bytes());
        buf[317..321].copy_from_slice(b"SVG ");
        buf[333..338].copy_from_slice(b"icon\0");
        // Payload: the SVG source.
        buf[477..477 + svg.len()].copy_from_slice(svg);
        let got = reconstruct(&buf).unwrap();
        let hex_head = svg[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            got.renditions.unwrap(),
            vec![format!(
                "icon 32x16 SVG payload {} bytes {hex_head} text {}",
                svg.len(),
                String::from_utf8_lossy(svg)
            )]
        );
    }

    #[test]
    fn nib_renders_scalar_values_beside_keys() {
        let mut buf = vec![0u8; 50];
        buf[..10].copy_from_slice(b"NIBArchive");
        buf[18..22].copy_from_slice(&1u32.to_le_bytes());
        buf[22..26].copy_from_slice(&50u32.to_le_bytes());
        buf[26..30].copy_from_slice(&2u32.to_le_bytes());
        buf[30..34].copy_from_slice(&53u32.to_le_bytes());
        buf[34..38].copy_from_slice(&2u32.to_le_bytes());
        buf[38..42].copy_from_slice(&62u32.to_le_bytes());
        buf[42..46].copy_from_slice(&1u32.to_le_bytes());
        buf[46..50].copy_from_slice(&70u32.to_le_bytes());
        // Object 0: class 0, values from index 0, count 2.
        buf.push(0x80);
        buf.push(0x80);
        buf.push(0x82);
        // Keys "alpha" and "on".
        buf.push(0x85);
        buf.extend_from_slice(b"alpha");
        buf.push(0x82);
        buf.extend_from_slice(b"on");
        // Value 0: int32 7. Value 1: true.
        buf.push(0x80);
        buf.push(2);
        buf.extend_from_slice(&7i32.to_le_bytes());
        buf.push(0x81);
        buf.push(4);
        // Class "NSObject".
        buf.push(0x89);
        buf.push(0x80);
        buf.extend_from_slice(b"NSObject\0");
        let got = reconstruct(&buf).unwrap();
        assert_eq!(
            got.values.unwrap(),
            vec!["NSObject.alpha = 7".to_string(), "NSObject.on = true".to_string()]
        );
    }

    #[test]
    fn nib_caps_objects_and_marks_undecodable_types() {
        let mut buf = vec![0u8; 50];
        buf[..10].copy_from_slice(b"NIBArchive");
        buf[18..22].copy_from_slice(&130u32.to_le_bytes());
        buf[22..26].copy_from_slice(&50u32.to_le_bytes());
        buf[26..30].copy_from_slice(&1u32.to_le_bytes());
        buf[30..34].copy_from_slice(&440u32.to_le_bytes());
        buf[34..38].copy_from_slice(&1u32.to_le_bytes());
        buf[38..42].copy_from_slice(&442u32.to_le_bytes());
        buf[42..46].copy_from_slice(&1u32.to_le_bytes());
        buf[46..50].copy_from_slice(&444u32.to_le_bytes());
        for _ in 0..130 {
            buf.push(0x80);
            buf.push(0x80);
            buf.push(0x80);
        }
        buf.push(0x81);
        buf.extend_from_slice(b"k");
        buf.push(0x80);
        buf.push(200);
        buf.push(0x89);
        buf.push(0x80);
        buf.extend_from_slice(b"NSObject\0");
        let got = reconstruct(&buf).unwrap();
        assert_eq!(got.object_count, Some(130));
        assert_eq!(got.values.unwrap(), vec!["... 2 more objects".to_string()]);
    }

    #[test]
    fn nib_undecodable_value_renders_type_and_stops() {
        let mut buf = vec![0u8; 50];
        buf[..10].copy_from_slice(b"NIBArchive");
        buf[18..22].copy_from_slice(&1u32.to_le_bytes());
        buf[22..26].copy_from_slice(&50u32.to_le_bytes());
        buf[26..30].copy_from_slice(&1u32.to_le_bytes());
        buf[30..34].copy_from_slice(&53u32.to_le_bytes());
        buf[34..38].copy_from_slice(&2u32.to_le_bytes());
        buf[38..42].copy_from_slice(&55u32.to_le_bytes());
        buf[42..46].copy_from_slice(&1u32.to_le_bytes());
        buf[46..50].copy_from_slice(&63u32.to_le_bytes());
        buf.push(0x80);
        buf.push(0x80);
        buf.push(0x82);
        buf.push(0x81);
        buf.extend_from_slice(b"k");
        // Value 0: int32 5. Value 1: type 200 has an unknown shape with no
        // way to know its length; it renders as `type 200` and the list stops.
        buf.push(0x80);
        buf.push(2);
        buf.extend_from_slice(&5i32.to_le_bytes());
        buf.push(0x80);
        buf.push(200);
        buf.push(0x89);
        buf.push(0x80);
        buf.extend_from_slice(b"NSObject\0");
        let got = reconstruct(&buf).unwrap();
        assert_eq!(
            got.values.unwrap(),
            vec!["NSObject.k = 5".to_string(), "NSObject.k = type 200".to_string()]
        );
    }

}
