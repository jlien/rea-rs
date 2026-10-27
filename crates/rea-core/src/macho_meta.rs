//! Load-command facts for one Mach-O slice, plus each fat slice's uuid, dylibs, rpaths, build version, code directory, and entitlements.

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MachoFacts {
    pub dylibs: Vec<String>,
    pub uuid: Option<String>,     // lowercase hex, 32 chars, no dashes
    pub platform: Option<String>, // "macos", "ios", "tvos", "watchos", "bridgeos", or "platform-{n}"
    pub minos: Option<String>,    // "x.y.z" from LC_BUILD_VERSION
    pub sdk: Option<String>,
    /// `LC_RPATH` paths. The directories are not searched.
    pub rpaths: Vec<String>,
    pub has_code_signature: bool,
    /// Code-directory identifier, hash type, team id, and hash slots. `None` when the load command is absent or the code directory does not fit.
    pub signature: Option<MachoSignature>,
    /// CMS signature blob, slot `0x10000`. `None` when that slot is absent or does not fit. A missing blob does not fail the parse.
    pub cms: Option<MachoBlob>,
    /// `Some(true)` when a sha1 or sha256 digest of the code directory is a contiguous window in the stored CMS bytes.
    /// `Some(false)` when both are present and the digest is absent. `None` otherwise. This is not an Apple trust decision.
    pub cms_verified: Option<bool>,
    /// Entitlements slot (`0x10005`) of the CMS superblob: top-level keys with their immediate string or boolean
    /// values, and the XML payload capped at 8 KiB (hex when the payload is not XML). `None` when the slot is absent
    /// or empty. Not an Apple trust decision.
    pub entitlements: Option<MachoEntitlements>,
    /// Byte size of the DER entitlements slot (`0x10006`), when present. The DER contents stay unparsed.
    pub entitlements_der_size: Option<u32>,
    /// `__info_plist` section, when its identifying keys are present.
    pub info_plist: Option<crate::plist::PlistInfo>,
    /// NUL-terminated printable C strings from every section whose name contains `objc`
    /// (class names, method names, type strings), in file order, capped at
    /// [`OBJC_STRINGS_CAP`] with a trailing `... N more` marker. A section that holds
    /// pointers instead of characters contributes nothing. No `class_ro_t`, method list,
    /// or protocol is walked. A string that is a name [`crate::demangle::swift`] accepts
    /// carries its `module.name` text beside the raw string; a name `swift` rejects
    /// stays raw.
    pub objc_strings: Vec<ObjcString>,
    /// Bytes past the last segment's file range.
    pub overlay: Option<crate::Overlay>,
}

/// One ObjC section string: the raw text, plus the Swift `module.name` demangling when
/// [`crate::demangle::swift`] accepts the raw text. The `... N more` cap marker is an
/// entry with no demangling.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ObjcString {
    /// The raw string as it appears in the section, or the `... N more` marker.
    pub text: String,
    /// `module.name` from `crate::demangle::swift`, when the raw text demangles. Types,
    /// generics, punycode, and labels stay unread; a rejected name stays raw.
    pub module_name: Option<String>,
}

/// The Mach-O code directory inside `LC_CODE_SIGNATURE`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MachoSignature {
    /// Identifier string from the code directory.
    pub identifier: String,
    /// `sha1`, `sha256`, `sha256-truncated`, `sha384`, `none`, or `hash-{n}`.
    pub hash_type: String,
    /// Team id when the code directory version is at least `0x20200` and `teamOffset` is set.
    pub team_id: Option<String>,
    /// Hash slots that fit in the code directory. Special slots use a negative index. Slots that do not fit are omitted.
    pub hashes: Vec<MachoHashSlot>,
    /// `nSpecialSlots` — the count of special hash slots that precede the code slots.
    pub special_slots: u32,
    /// `execSegBase` from code directory version `0x20400` or later. The segment is not validated.
    pub exec_seg_offset: Option<u64>,
    /// `execSegLimit - execSegBase` from code directory version `0x20400` or later.
    pub exec_seg_size: Option<u64>,
    /// `execSegFlags` from code directory version `0x20400` or later.
    pub exec_seg_flags: Option<u64>,
}

/// One code-directory hash slot. `index` `-1` is the first special slot.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MachoHashSlot {
    pub index: i32,
    /// Lowercase hex of the slot bytes. The digest is not recomputed.
    pub digest: String,
}

/// A code-signature blob. `bytes` holds the blob when it is at most 4096 bytes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MachoBlob {
    /// Big-endian value of the first four bytes, or zero when the blob is shorter.
    pub magic: u32,
    pub length: u32,
    pub bytes: Vec<u8>,
}

/// One entitlement key with its value. A top-level `<key>` carries its immediate `<string>` or boolean
/// value; a nested `<dict>` or `<array>` carries its own key with no value and is followed by one level of
/// entries inside it: `parent.child` for a dict child, `parent[0]`, `parent[1]`, ... for array items,
/// capped at 32 with a trailing `... N more` marker.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MachoEntitlement {
    /// The top-level `<key>` name, or the derived `parent.child` / `parent[i]` form for a nested entry.
    pub key: String,
    /// The immediate `<string>` text, or `true`/`false` for `<true/>`/`<false/>`. `None` for every other value kind
    /// (array, dict, data, date, integer, real) and for a key with no readable value.
    pub value: Option<String>,
}

/// The entitlements slot (`0x10005`) of a CMS superblob. This is a read of stored bytes, not an Apple trust decision.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MachoEntitlements {
    /// Top-level keys with their immediate string or boolean values, in file order. A nested dict or array keeps
    /// its own key with no value and contributes one level of entries inside it (`parent.child`, `parent[i]`),
    /// capped at 32 with a `... N more` marker; a deeper dict or array is skipped.
    pub entries: Vec<MachoEntitlement>,
    /// The XML payload capped at 8 KiB with an appended `…` marker. A payload that is not XML is the lowercase hex
    /// of its first 8 KiB, with the same marker when truncated.
    pub payload: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MachoArch {
    pub cpu: String, // "arm64", "x86_64", "arm", "x86", or "cpu-{n}"
    pub offset: u64,
    pub size: u64,
    /// UUID of this slice. `None` when the slice bytes are absent or unreadable.
    pub uuid: Option<String>,
    /// Dylibs of this slice. Empty when the slice bytes are absent or unreadable.
    pub dylibs: Vec<String>,
    /// `LC_RPATH` paths of this slice. The directories are not searched.
    pub rpaths: Vec<String>,
    pub platform: Option<String>,
    pub minos: Option<String>,
    pub sdk: Option<String>,
    /// Code directory of this slice. `None` when the slice bytes are absent or the directory does not fit.
    pub signature: Option<MachoSignature>,
    /// CMS blob of this slice. `None` when the slice is absent or the slot does not fit.
    pub cms: Option<MachoBlob>,
    /// Same check as [`MachoFacts::cms_verified`] for this slice.
    pub cms_verified: Option<bool>,
    /// Entitlements of this slice, same shape as [`MachoFacts::entitlements`]. `None` when the slice is absent or the slot does not fit.
    pub entitlements: Option<MachoEntitlements>,
    /// DER entitlements slot size of this slice, same shape as [`MachoFacts::entitlements_der_size`].
    pub entitlements_der_size: Option<u32>,
    /// `__info_plist` of this slice.
    pub info_plist: Option<crate::plist::PlistInfo>,
    /// ObjC strings of this slice, same shape as [`MachoFacts::objc_strings`].
    pub objc_strings: Vec<ObjcString>,
    /// Bytes past this slice's last segment.
    pub overlay: Option<crate::Overlay>,
}

/// Parse one Mach-O slice (not a fat archive). Fat input returns Error::Parse.
pub fn facts(bytes: &[u8]) -> Result<MachoFacts> {
    let mo =
        goblin::mach::MachO::parse(bytes, 0).map_err(|e| Error::Parse(format!("mach-o: {e}")))?;
    let body = slice_body(&mo, bytes);
    Ok(MachoFacts {
        dylibs: body.dylibs,
        uuid: body.uuid,
        platform: body.platform,
        minos: body.minos,
        sdk: body.sdk,
        rpaths: body.rpaths,
        has_code_signature: body.has_code_signature,
        signature: body.signature,
        cms: body.cms,
        cms_verified: body.cms_verified,
        entitlements: body.entitlements,
        entitlements_der_size: body.entitlements_der_size,
        info_plist: body.info_plist,
        objc_strings: body.objc_strings,
        overlay: body.overlay,
    })
}

struct SliceBody {
    dylibs: Vec<String>,
    rpaths: Vec<String>,
    uuid: Option<String>,
    platform: Option<String>,
    minos: Option<String>,
    sdk: Option<String>,
    has_code_signature: bool,
    signature: Option<MachoSignature>,
    cms: Option<MachoBlob>,
    cms_verified: Option<bool>,
    entitlements: Option<MachoEntitlements>,
    entitlements_der_size: Option<u32>,
    info_plist: Option<crate::plist::PlistInfo>,
    objc_strings: Vec<ObjcString>,
    overlay: Option<crate::Overlay>,
}

fn slice_body(mo: &goblin::mach::MachO, bytes: &[u8]) -> SliceBody {
    let uuid = mo.load_commands.iter().find_map(|cmd| match &cmd.command {
        goblin::mach::load_command::CommandVariant::Uuid(uuid_cmd) => {
            Some(uuid_cmd.uuid.iter().map(|b| format!("{b:02x}")).collect())
        }
        _ => None,
    });
    let build = mo.load_commands.iter().find_map(|cmd| match &cmd.command {
        goblin::mach::load_command::CommandVariant::BuildVersion(cmd) => Some(*cmd),
        _ => None,
    });
    let (platform, minos, sdk) = match build {
        Some(cmd) => (
            Some(platform_name(cmd.platform)),
            Some(version_xyz(cmd.minos)),
            Some(version_xyz(cmd.sdk)),
        ),
        None => (None, None, None),
    };
    let has_code_signature = mo.load_commands.iter().any(|cmd| {
        matches!(
            &cmd.command,
            goblin::mach::load_command::CommandVariant::CodeSignature(_)
        )
    });
    let (signature, cms, cms_verified, entitlements, entitlements_der_size) =
        mo.load_commands.iter().find_map(|cmd| match &cmd.command {
            goblin::mach::load_command::CommandVariant::CodeSignature(linkedit) => {
                Some(signature_parts(bytes, linkedit.dataoff, linkedit.datasize))
            }
            _ => None,
        }).unwrap_or((None, None, None, None, None));
    SliceBody {
        dylibs: mo.libs.iter().map(|lib| (*lib).to_string()).collect(),
        rpaths: mo.rpaths.iter().map(|path| (*path).to_string()).collect(),
        uuid,
        platform,
        minos,
        sdk,
        has_code_signature,
        signature,
        cms,
        cms_verified,
        entitlements,
        entitlements_der_size,
        info_plist: embedded_plist(mo),
        objc_strings: objc_strings(mo),
        overlay: crate::trailing_overlay(segment_file_end(mo), bytes.len() as u64),
    }
}

fn segment_file_end(mo: &goblin::mach::MachO) -> u64 {
    mo.segments
        .iter()
        .map(|seg| seg.fileoff.saturating_add(seg.filesize))
        .max()
        .unwrap_or(0)
}

fn embedded_plist(mo: &goblin::mach::MachO) -> Option<crate::plist::PlistInfo> {
    for seg in mo.segments.iter() {
        let Ok(sections) = seg.sections() else {
            continue;
        };
        for (sect, data) in sections {
            let name = sect
                .sectname
                .iter()
                .take_while(|b| **b != 0)
                .map(|b| *b as char)
                .collect::<String>();
            if name == "__info_plist" {
                return crate::plist::identify(data);
            }
        }
    }
    None
}

const OBJC_STRINGS_CAP: usize = 128;

/// NUL-terminated printable C strings from every section whose name contains `objc`,
/// in file order. A section that holds pointers rather than characters (for example
/// `__objc_classlist`) yields no printable runs and contributes nothing; no `class_ro_t`,
/// method list, or protocol is walked. A string that is a name [`crate::demangle::swift`]
/// accepts carries its `module.name` beside the raw text; a name `swift` rejects stays
/// raw, and a demangle failure does not fail the parse.
fn objc_strings(mo: &goblin::mach::MachO) -> Vec<ObjcString> {
    let mut hits: Vec<ObjcString> = Vec::new();
    for seg in mo.segments.iter() {
        let Ok(sections) = seg.sections() else {
            continue;
        };
        for (sect, data) in sections {
            let name: String = sect
                .sectname
                .iter()
                .take_while(|b| **b != 0)
                .map(|b| *b as char)
                .collect();
            if !name.to_ascii_lowercase().contains("objc") {
                continue;
            }
            let mut start = None;
            for (i, &b) in data.iter().enumerate() {
                if (0x20..=0x7e).contains(&b) {
                    if start.is_none() {
                        start = Some(i);
                    }
                } else if b == 0 {
                    if let Some(s) = start.take() {
                        if i > s {
                            let text = String::from_utf8_lossy(&data[s..i]).into_owned();
                            let module_name = crate::demangle::swift(&text);
                            hits.push(ObjcString { text, module_name });
                        }
                    }
                } else {
                    start = None;
                }
            }
            // A printable run ending at the section's last byte with no NUL is not
            // NUL-terminated and stays unread.
        }
    }
    if hits.len() > OBJC_STRINGS_CAP {
        let more = hits.len() - OBJC_STRINGS_CAP;
        hits.truncate(OBJC_STRINGS_CAP);
        hits.push(ObjcString {
            text: format!("... {more} more"),
            module_name: None,
        });
    }
    hits
}

const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CSMAGIC_BLOBWRAPPER: u32 = 0xfade_0b01;
const CSSLOT_CODEDIRECTORY: u32 = 0;
const CSSLOT_SIGNATURESLOT: u32 = 0x10000;
const CSSLOT_ENTITLEMENTS: u32 = 0x10005;
const CSSLOT_ENTITLEMENTS_DER: u32 = 0x10006;
const CODE_DIRECTORY_BASE: usize = 44;
const TEAM_OFFSET_FIELD: usize = 48;
const EXEC_SEG_BASE_FIELD: usize = 64;
const EXEC_SEG_LIMIT_FIELD: usize = 72;
const EXEC_SEG_FLAGS_FIELD: usize = 80;
const EXEC_SEG_END: usize = 88;
const EXEC_SEG_VERSION: u32 = 0x20400;
const BLOB_BYTE_CAP: usize = 4096;
const ENTITLEMENTS_XML_CAP: usize = 8192;
const NESTED_ENTITLEMENTS_CAP: usize = 32;

/// Code directory, CMS blob, and entitlement slots from `LC_CODE_SIGNATURE`.
///
/// A missing blob, a bad magic, a short directory, or a slot that does not fit is `None` and does not fail the Mach-O parse.
fn signature_parts(
    bytes: &[u8],
    dataoff: u32,
    datasize: u32,
) -> (
    Option<MachoSignature>,
    Option<MachoBlob>,
    Option<bool>,
    Option<MachoEntitlements>,
    Option<u32>,
) {
    let Some(blob) = superblob(bytes, dataoff, datasize) else {
        return (None, None, None, None, None);
    };
    let signature = code_directory(blob);
    let cms = cms_blob(blob);
    let verified = match (code_directory_bytes(blob), cms.as_ref()) {
        (Some(directory), Some(cms)) => cms_digest_present(directory, &cms.bytes),
        _ => None,
    };
    let entitlements = entitlements_slot(blob);
    let entitlements_der_size = slot_bytes(blob, CSSLOT_ENTITLEMENTS_DER).map(|der| {
        let declared = if der.len() >= 8 { be_u32(der, 4).map(|v| v as usize) } else { None };
        match declared {
            Some(v) if v >= 8 && v <= der.len() => v as u32,
            _ => der.len() as u32,
        }
    });
    (signature, cms, verified, entitlements, entitlements_der_size)
}

/// The bytes of one superblob slot. The slot blob's declared length (big-endian at its offset + 4) is honored when it
/// fits, so a slot that is not last in the index does not swallow the slots after it; otherwise the bytes run to the
/// end of the superblob.
fn slot_bytes(blob: &[u8], slot_type: u32) -> Option<&[u8]> {
    let length = blob.len();
    let count = be_u32(blob, 8)? as usize;
    let index_end = 12usize.checked_add(count.checked_mul(8)?)?;
    if index_end > length {
        return None;
    }
    let off = (0..count).find_map(|i| {
        let at = 12 + i * 8;
        let ty = be_u32(blob, at)?;
        let slot = be_u32(blob, at + 4)? as usize;
        (ty == slot_type).then_some(slot)
    })?;
    let rest = blob.get(off..length)?;
    if rest.len() >= 8 {
        if let Some(declared) = be_u32(rest, 4).map(|v| v as usize) {
            if declared >= 8 && declared <= rest.len() {
                return Some(&rest[..declared]);
            }
        }
    }
    Some(rest)
}

/// Entitlements XML from slot `0x10005`. A `blob-wrapper` header (`0xfade_0b01`) is stripped. An empty or absent slot
/// is `None`.
fn entitlements_slot(blob: &[u8]) -> Option<MachoEntitlements> {
    let slot = slot_bytes(blob, CSSLOT_ENTITLEMENTS)?;
    let payload = if slot.len() >= 8 && be_u32(slot, 0) == Some(CSMAGIC_BLOBWRAPPER) {
        let declared = be_u32(slot, 4)? as usize;
        if declared >= 8 && declared <= slot.len() {
            &slot[8..declared]
        } else {
            &slot[8..]
        }
    } else {
        slot
    };
    if payload.is_empty() {
        return None;
    }
    let xml = std::str::from_utf8(payload)
        .ok()
        .filter(|text| text.contains("<plist") || text.contains("<dict"));
    let entries = xml.map(entitlement_entries).unwrap_or_default();
    let payload = match xml {
        Some(text) => cap_text(text),
        None => cap_hex(payload),
    };
    Some(MachoEntitlements { entries, payload })
}

/// Top-level `<key>` names with their immediate `<string>` or boolean value. A nested `<dict>` or `<array>`
/// keeps its own entry with no value and also contributes one level of entries inside it: a dict child of
/// string or boolean type becomes `parent.child`, and an array item becomes `parent[0]`, `parent[1]`, ..., in
/// order, capped at [`NESTED_ENTITLEMENTS_CAP`] entries with a trailing `... N more` marker. A deeper dict or
/// array is skipped the way the top level skips one. A truncated payload keeps the keys that parsed.
fn entitlement_entries(text: &str) -> Vec<MachoEntitlement> {
    let mut out = Vec::new();
    let mut at = match text.find("<dict") {
        Some(open) => open + "<dict".len(),
        None => return out,
    };
    while let Some(key_at) = text[at..].find("<key>") {
        let key_at = at + key_at + "<key>".len();
        let Some(key_end) = text[key_at..].find("</key>") else {
            break;
        };
        let key = text[key_at..key_at + key_end].trim().to_string();
        let after_key = key_at + key_end + "</key>".len();
        let Some(tag_at) = text[after_key..].find('<').map(|i| after_key + i) else {
            at = after_key;
            continue;
        };
        if text[tag_at..].starts_with("<dict") || text[tag_at..].starts_with("<array") {
            out.push(MachoEntitlement { key: key.clone(), value: None });
            let (nested, next) = nested_entries(text, tag_at, &key);
            out.extend(nested);
            at = next;
        } else {
            at = match immediate_value(text, after_key) {
                Some((value, next)) => {
                    out.push(MachoEntitlement { key, value });
                    next
                }
                None => after_key,
            };
        }
    }
    out
}

/// One level inside the `<dict>` or `<array>` whose tag starts at `tag_at`, under the top-level key
/// `parent`. A dict child of string or boolean type becomes `parent.child`; any other child element keeps
/// the derived key with no value. An array item becomes `parent[0]`, `parent[1]`, ...; a non-string,
/// non-boolean item keeps the index with no value. Entries past [`NESTED_ENTITLEMENTS_CAP`] are counted,
/// not stored, and leave a trailing `... N more` marker. Returns the entries and the offset past the
/// element's close tag; a payload that never closes stops at the end of `text`.
fn nested_entries(text: &str, tag_at: usize, parent: &str) -> (Vec<MachoEntitlement>, usize) {
    let mut out = Vec::new();
    let mut more = 0usize;
    let Some(name_end) = text[tag_at..].find(['>', ' ']) else {
        return (out, tag_at);
    };
    let name = text[tag_at + 1..tag_at + name_end].trim_end_matches('/').to_string();
    let Some(gt) = text[tag_at..].find('>') else {
        return (out, tag_at);
    };
    let tag_end = tag_at + gt + 1;
    if text[..tag_end].ends_with("/>") {
        return (out, tag_end);
    }
    let close = format!("</{name}>");
    let is_dict = name == "dict";
    let mut at = tag_end;
    let mut index = 0usize;
    loop {
        let Some(next) = text[at..].find('<') else {
            return (marker(out, parent, more), text.len());
        };
        let pos = at + next;
        if text[pos..].starts_with(&close) {
            return (marker(out, parent, more), pos + close.len());
        }
        let (full_key, value_at) = if is_dict {
            if !text[pos..].starts_with("<key>") {
                at = pos + 1;
                continue;
            }
            let body = &text[pos + "<key>".len()..];
            let Some(key_end) = body.find("</key>") else {
                return (marker(out, parent, more), text.len());
            };
            let child = body[..key_end].trim();
            let after_key = pos + "<key>".len() + key_end + "</key>".len();
            let Some(vtag) = text[after_key..].find('<').map(|i| after_key + i) else {
                return (marker(out, parent, more), text.len());
            };
            (format!("{parent}.{child}"), vtag)
        } else {
            (format!("{parent}[{index}]"), pos)
        };
        let (value, next) = nested_value(text, value_at);
        if out.len() < NESTED_ENTITLEMENTS_CAP {
            out.push(MachoEntitlement { key: full_key, value });
        } else {
            more += 1;
        }
        index += 1;
        at = next;
    }
}

/// The trailing `... N more` marker for the nested entries of `parent` past the cap.
fn marker(out: Vec<MachoEntitlement>, parent: &str, more: usize) -> Vec<MachoEntitlement> {
    if more == 0 {
        return out;
    }
    let mut out = out;
    out.push(MachoEntitlement { key: parent.to_string(), value: Some(format!("... {more} more")) });
    out
}

/// The value of one nested entry: `Some(value)` for a `<string>`, `<true/>`, or `<false/>`, `None` for any
/// other element, which is skipped whole. Returns the offset past the element; an element that never closes
/// stops at the end of `text`.
fn nested_value(text: &str, at: usize) -> (Option<String>, usize) {
    // A tag with no `>` or space before the end of `text` never closes; stop
    // at `text.len()` so the caller's loop (which restarts at the returned
    // offset) terminates instead of spinning on the same `<`.
    let Some(name_end) = text[at..].find(['>', ' ']) else {
        return (None, text.len());
    };
    let name = &text[at + 1..at + name_end];
    if name.is_empty() || name.starts_with(['/', '!', '?']) {
        return (None, at + 1);
    }
    if text[at..].starts_with("<string>") {
        let rest = &text[at + "<string>".len()..];
        let Some(end) = rest.find("</string>") else {
            return (None, text.len());
        };
        let value = rest[..end].trim();
        let value = (!value.is_empty()).then(|| value.to_string());
        return (value, at + "<string>".len() + end + "</string>".len());
    }
    for (tag, value) in [("<true/>", "true"), ("<false/>", "false")] {
        if text[at..].starts_with(tag) {
            return (Some(value.to_string()), at + tag.len());
        }
    }
    let name = name.trim_end_matches('/');
    let next = skip_element(text, at, name).unwrap_or(text.len());
    (None, next)
}

/// The value element right after a `</key>`: `Some((value, offset past it))` for a `<string>`, `<true/>`, or
/// `<false/>`, and `Some((None, offset past it))` for any other complete element that is skipped. `None` when
/// no element starts there. A nested `<dict>` or `<array>` is handled by [`entitlement_entries`] before this
/// is called.
fn immediate_value(text: &str, at: usize) -> Option<(Option<String>, usize)> {
    let tag_at = at + text[at..].find('<')?;
    if text[tag_at..].starts_with("<string>") {
        let rest = &text[tag_at + "<string>".len()..];
        let end = rest.find("</string>")?;
        let value = rest[..end].trim();
        let value = (!value.is_empty()).then(|| value.to_string());
        return Some((value, tag_at + "<string>".len() + end + "</string>".len()));
    }
    for (tag, value) in [("<true/>", "true"), ("<false/>", "false")] {
        if text[tag_at..].starts_with(tag) {
            return Some((Some(value.to_string()), tag_at + tag.len()));
        }
    }
    None
}

/// Offset past the element `<name ...>` that starts at `start`, nesting-aware.
/// A self-closing opener (`<name ... />`) passes through without counting. An
/// element that never closes stops the scan at the end of `text`.
fn skip_element(text: &str, start: usize, name: &str) -> Option<usize> {
    let open = format!("<{name}");
    let close = format!("</{name}>");
    let tag_end = text[start..].find('>')? + start + 1;
    if text[..tag_end].ends_with("/>") {
        return Some(tag_end);
    }
    let mut depth = 1usize; // the opener itself is a nesting level
    let mut at = tag_end;
    loop {
        let open_at = text[at..].find(&open).map(|i| at + i);
        let close_at = text[at..].find(&close).map(|i| at + i);
        match (open_at, close_at) {
            (None, None) => return Some(text.len()),
            (o, c) if o.is_some() && (c.is_none() || o < c) => {
                let o = o?;
                let nested_end = text[o..].find('>')? + o + 1;
                if !text[..nested_end].ends_with("/>") {
                    depth += 1;
                }
                at = nested_end;
            }
            (_, c) => {
                let c = c?;
                depth -= 1; // depth starts at 1, so a close is always matched
                at = c + close.len();
                if depth == 0 {
                    return Some(at);
                }
            }
        }
    }
}

/// The payload text capped at 8 KiB on a char boundary, with `…` appended when truncated.
fn cap_text(text: &str) -> String {
    if text.len() <= ENTITLEMENTS_XML_CAP {
        return text.to_string();
    }
    let mut end = ENTITLEMENTS_XML_CAP;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

/// Lowercase hex of the first 8 KiB, with `…` appended when the payload is longer.
fn cap_hex(payload: &[u8]) -> String {
    let taken = payload.len().min(ENTITLEMENTS_XML_CAP);
    let mut out = payload[..taken].iter().map(|b| format!("{b:02x}")).collect::<String>();
    if payload.len() > ENTITLEMENTS_XML_CAP {
        out.push('…');
    }
    out
}

fn code_directory_bytes(blob: &[u8]) -> Option<&[u8]> {
    let length = blob.len();
    let count = be_u32(blob, 8)? as usize;
    let index_end = 12usize.checked_add(count.checked_mul(8)?)?;
    if index_end > length {
        return None;
    }
    let cd_off = (0..count).find_map(|i| {
        let at = 12 + i * 8;
        let ty = be_u32(blob, at)?;
        let off = be_u32(blob, at + 4)? as usize;
        (ty == CSSLOT_CODEDIRECTORY).then_some(off)
    })?;
    let cd = blob.get(cd_off..length)?;
    if be_u32(cd, 0)? != CSMAGIC_CODEDIRECTORY {
        return None;
    }
    let cd_len = be_u32(cd, 4)? as usize;
    if cd_len < CODE_DIRECTORY_BASE || cd_len > cd.len() {
        return None;
    }
    Some(&cd[..cd_len])
}

fn cms_digest_present(directory: &[u8], cms: &[u8]) -> Option<bool> {
    if directory.len() < CODE_DIRECTORY_BASE {
        return None;
    }
    let digest: Vec<u8> = match directory[37] {
        1 => crate::hash::sha1(directory).to_vec(),
        2 => crate::hash::sha256(directory).to_vec(),
        3 => truncated_digest(&crate::hash::sha256(directory), directory[36] as usize)?,
        4 => truncated_digest(&crate::hash::sha384(directory), directory[36] as usize)?,
        _ => return None,
    };
    Some(cms.windows(digest.len()).any(|window| window == digest.as_slice()))
}

/// Hash types 3 and 4 compare only the leading `hashSize` bytes of the digest.
/// The size clamps to the digest length, so a size past the digest compares
/// the whole digest; a zero size compares nothing and leaves `cms_verified`
/// empty.
fn truncated_digest(digest: &[u8], hash_size: usize) -> Option<Vec<u8>> {
    let size = hash_size.min(digest.len());
    (size > 0).then(|| digest[..size].to_vec())
}

fn superblob(bytes: &[u8], dataoff: u32, datasize: u32) -> Option<&[u8]> {
    let start = dataoff as usize;
    let end = start.checked_add(datasize as usize)?;
    let blob = bytes.get(start..end)?;
    let length = be_u32(blob, 4)? as usize;
    if be_u32(blob, 0)? != CSMAGIC_EMBEDDED_SIGNATURE || length > blob.len() || length < 12 {
        return None;
    }
    Some(&blob[..length])
}

fn code_directory(blob: &[u8]) -> Option<MachoSignature> {
    let length = blob.len();
    let count = be_u32(blob, 8)? as usize;
    let index_end = 12usize.checked_add(count.checked_mul(8)?)?;
    if index_end > length {
        return None;
    }
    let cd_off = (0..count).find_map(|i| {
        let at = 12 + i * 8;
        let ty = be_u32(blob, at)?;
        let off = be_u32(blob, at + 4)? as usize;
        (ty == CSSLOT_CODEDIRECTORY).then_some(off)
    })?;
    if cd_off.checked_add(CODE_DIRECTORY_BASE)? > length {
        return None;
    }
    let cd = &blob[cd_off..length];
    if be_u32(cd, 0)? != CSMAGIC_CODEDIRECTORY {
        return None;
    }
    let cd_len = be_u32(cd, 4)? as usize;
    if cd_len < CODE_DIRECTORY_BASE || cd_len > cd.len() {
        return None;
    }
    let version = be_u32(cd, 8)?;
    let special_slots = be_u32(cd, 24).unwrap_or(0);
    let ident_off = be_u32(cd, 20)? as usize;
    let identifier = cstr_at(cd, cd_len, ident_off)?;
    let team_id = if version >= 0x20200 && cd_len >= TEAM_OFFSET_FIELD + 4 {
        let team_off = be_u32(cd, TEAM_OFFSET_FIELD)? as usize;
        if team_off == 0 {
            None
        } else {
            cstr_at(cd, cd_len, team_off)
        }
    } else {
        None
    };
    let (exec_seg_offset, exec_seg_size, exec_seg_flags) = if version >= EXEC_SEG_VERSION && cd_len >= EXEC_SEG_END {
        let base = be_u64(cd, EXEC_SEG_BASE_FIELD)?;
        let limit = be_u64(cd, EXEC_SEG_LIMIT_FIELD)?;
        (
            Some(base),
            Some(limit.saturating_sub(base)),
            Some(be_u64(cd, EXEC_SEG_FLAGS_FIELD)?),
        )
    } else {
        (None, None, None)
    };
    Some(MachoSignature {
        identifier,
        hash_type: hash_name(cd[37]),
        team_id,
        hashes: hash_slots(cd, cd_len),
        special_slots,
        exec_seg_offset,
        exec_seg_size,
        exec_seg_flags,
    })
}

fn cms_blob(blob: &[u8]) -> Option<MachoBlob> {
    let rest = slot_bytes(blob, CSSLOT_SIGNATURESLOT)?;
    if rest.is_empty() {
        return None;
    }
    let magic = if rest.len() >= 4 {
        be_u32(rest, 0)?
    } else {
        0
    };
    let declared = if rest.len() >= 8 {
        be_u32(rest, 4)? as usize
    } else {
        rest.len()
    };
    let taken = if declared >= 8 && declared <= rest.len() {
        declared
    } else {
        rest.len()
    };
    let stored = taken.min(BLOB_BYTE_CAP);
    Some(MachoBlob {
        magic,
        length: taken as u32,
        bytes: rest[..stored].to_vec(),
    })
}

/// Special slots sit immediately before `hashOffset`. Code slot 0 starts there.
fn hash_slots(cd: &[u8], cd_len: usize) -> Vec<MachoHashSlot> {
    if cd_len < CODE_DIRECTORY_BASE || cd.len() < CODE_DIRECTORY_BASE {
        return Vec::new();
    }
    let hash_off = be_u32(cd, 16).unwrap_or(0) as usize;
    let n_special = be_u32(cd, 24).unwrap_or(0) as usize;
    let n_code = be_u32(cd, 28).unwrap_or(0) as usize;
    let hash_size = cd[36] as usize;
    if hash_size == 0 || hash_off == 0 || n_special.saturating_add(n_code) == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    if n_special > 0 {
        let Some(span) = n_special.checked_mul(hash_size) else {
            return out;
        };
        let Some(special_at) = hash_off.checked_sub(span) else {
            return out;
        };
        // Slots ascend from special_at; only those inside the directory
        // carry a digest, so stop at the first one past the end instead of
        // walking a hostile count.
        if special_at < cd_len {
            for i in 0..n_special {
                // nSpecialSlots can be any u32; the index is -(n - i) and
                // must not negate through i32::MIN.
                let index = -(i64::from(n_special as u32) - i as i64) as i32;
                let at = special_at + i * hash_size;
                if at >= cd_len {
                    break;
                }
                if let Some(digest) = digest_at(cd, cd_len, at, hash_size) {
                    out.push(MachoHashSlot { index, digest });
                }
            }
        }
    }
    for i in 0..n_code {
        let Some(at) = hash_off.checked_add(i.saturating_mul(hash_size)) else {
            break;
        };
        if let Some(digest) = digest_at(cd, cd_len, at, hash_size) {
            out.push(MachoHashSlot {
                index: i as i32,
                digest,
            });
        }
    }
    out
}

fn digest_at(buf: &[u8], limit: usize, at: usize, len: usize) -> Option<String> {
    let end = at.checked_add(len)?;
    if end > limit || end > buf.len() {
        return None;
    }
    Some(buf[at..end].iter().map(|b| format!("{b:02x}")).collect())
}

fn be_u32(buf: &[u8], at: usize) -> Option<u32> {
    let raw = buf.get(at..at + 4)?;
    Some(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn be_u64(buf: &[u8], at: usize) -> Option<u64> {
    let raw = buf.get(at..at + 8)?;
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(raw);
    Some(u64::from_be_bytes(bytes))
}

fn cstr_at(buf: &[u8], limit: usize, off: usize) -> Option<String> {
    if off >= limit || off > buf.len() {
        return None;
    }
    let end = buf[off..limit]
        .iter()
        .position(|b| *b == 0)
        .map(|i| off + i)
        .unwrap_or(limit);
    if end - off > 256 {
        return None;
    }
    std::str::from_utf8(&buf[off..end])
        .ok()
        .map(str::to_string)
}

fn hash_name(hash_type: u8) -> String {
    match hash_type {
        0 => "none".to_string(),
        1 => "sha1".to_string(),
        2 => "sha256".to_string(),
        3 => "sha256-truncated".to_string(),
        4 => "sha384".to_string(),
        n => format!("hash-{n}"),
    }
}

/// Architecture headers from the original file, which may be a fat archive.
///
/// Each slice that is present contributes its uuid, dylibs, rpaths, build version, code directory, CMS blob, entitlements, Info.plist, and overlay. A missing or unreadable slice leaves those fields empty and does not fail the parse.
pub fn architectures(bytes: &[u8]) -> Result<Vec<MachoArch>> {
    match goblin::mach::Mach::parse(bytes).map_err(|e| Error::Parse(format!("mach-o: {e}")))? {
        goblin::mach::Mach::Fat(multi) => {
            let arches = multi
                .arches()
                .map_err(|e| Error::Parse(format!("mach-o: {e}")))?;
            Ok(arches
                .into_iter()
                .map(|arch| {
                    let goblin::mach::fat::FatArch {
                        cputype,
                        offset,
                        size,
                        ..
                    } = arch;
                    arch_of(cpu_name(cputype), u64::from(offset), u64::from(size), arch.slice(bytes))
                })
                .collect())
        }
        goblin::mach::Mach::Binary(mo) => {
            Ok(vec![arch_of(cpu_name(mo.header.cputype()), 0, bytes.len() as u64, bytes)])
        }
    }
}

fn arch_of(cpu: String, offset: u64, size: u64, slice: &[u8]) -> MachoArch {
    let body = slice_facts(slice);
    MachoArch {
        cpu,
        offset,
        size,
        uuid: body.uuid,
        dylibs: body.dylibs,
        rpaths: body.rpaths,
        platform: body.platform,
        minos: body.minos,
        sdk: body.sdk,
        signature: body.signature,
        cms: body.cms,
        cms_verified: body.cms_verified,
        entitlements: body.entitlements,
        entitlements_der_size: body.entitlements_der_size,
        info_plist: body.info_plist,
        objc_strings: body.objc_strings,
        overlay: body.overlay,
    }
}

/// Identity of one slice. An empty or unreadable slice is empty and does not fail the caller.
fn slice_facts(slice: &[u8]) -> SliceBody {
    if slice.is_empty() {
        return empty_slice();
    }
    match goblin::mach::MachO::parse(slice, 0) {
        Ok(mo) => slice_body(&mo, slice),
        Err(_) => empty_slice(),
    }
}

fn empty_slice() -> SliceBody {
    SliceBody {
        dylibs: Vec::new(),
        rpaths: Vec::new(),
        uuid: None,
        platform: None,
        minos: None,
        sdk: None,
        has_code_signature: false,
        signature: None,
        cms: None,
        cms_verified: None,
        entitlements: None,
        entitlements_der_size: None,
        info_plist: None,
        objc_strings: Vec::new(),
        overlay: None,
    }
}

fn platform_name(platform: u32) -> String {
    match platform {
        1 => "macos".to_string(),
        2 => "ios".to_string(),
        3 => "tvos".to_string(),
        4 => "watchos".to_string(),
        5 => "bridgeos".to_string(),
        n => format!("platform-{n}"),
    }
}

/// `xxxx.yy.zz` packed as `(major << 16) | (minor << 8) | patch`.
fn version_xyz(value: u32) -> String {
    let major = value >> 16;
    let minor = (value >> 8) & 0xff;
    let patch = value & 0xff;
    format!("{major}.{minor}.{patch}")
}

fn cpu_name(cputype: u32) -> String {
    match cputype {
        0x0100_000c => "arm64".to_string(),
        0x0100_0007 => "x86_64".to_string(),
        12 => "arm".to_string(),
        7 => "x86".to_string(),
        n => format!("cpu-{n}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_macho() {
        assert!(facts(b"not a macho").is_err());
    }

    #[test]
    fn rejects_fat_archive() {
        let err = facts(&[0xca, 0xfe, 0xba, 0xbe]).unwrap_err();
        assert!(matches!(err, Error::Parse(_)));
    }

    #[test]
    fn reads_fat_arch_header_without_slice_bytes() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xcafe_babe_u32.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&0x0100_000c_u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&0x4000u32.to_be_bytes());
        bytes.extend_from_slice(&0x100u32.to_be_bytes());
        bytes.extend_from_slice(&14u32.to_be_bytes());
        assert_eq!(
            architectures(&bytes).unwrap(),
            vec![MachoArch {
                cpu: "arm64".into(),
                offset: 0x4000,
                size: 0x100,
                uuid: None,
                dylibs: Vec::new(),
                rpaths: Vec::new(),
                platform: None,
                minos: None,
                sdk: None,
                signature: None,
                cms: None,
                cms_verified: None,
                entitlements: None,
                entitlements_der_size: None,
                info_plist: None,
                objc_strings: Vec::new(),
                overlay: None,
            }]
        );
    }

    #[test]
    fn architectures_rejects_non_macho() {
        assert!(architectures(b"nope").is_err());
    }

    #[test]
    fn reads_build_version_and_code_signature() {
        let bytes = thin_macho(0x0100_000c, true);
        let got = facts(&bytes).unwrap();
        assert_eq!(got.platform.as_deref(), Some("ios"));
        assert_eq!(got.minos.as_deref(), Some("15.4.1"));
        assert_eq!(got.sdk.as_deref(), Some("16.0.0"));
        assert!(got.has_code_signature);
        assert_eq!(got.signature, None);
        assert_eq!(got.uuid, None);
        assert_eq!(
            architectures(&bytes).unwrap(),
            vec![MachoArch {
                cpu: "arm64".into(),
                offset: 0,
                size: bytes.len() as u64,
                uuid: None,
                dylibs: vec!["self".into()],
                rpaths: Vec::new(),
                platform: Some("ios".into()),
                minos: Some("15.4.1".into()),
                sdk: Some("16.0.0".into()),
                signature: None,
                cms: None,
                cms_verified: None,
                entitlements: None,
                entitlements_der_size: None,
                info_plist: None,
                objc_strings: Vec::new(),
                overlay: None,
            }]
        );
    }

    #[test]
    fn omits_version_without_build_command() {
        let bytes = thin_macho(7, false);
        let got = facts(&bytes).unwrap();
        assert_eq!(got.platform, None);
        assert_eq!(got.minos, None);
        assert_eq!(got.sdk, None);
        assert!(!got.has_code_signature);
        assert_eq!(got.signature, None);
        assert_eq!(architectures(&bytes).unwrap()[0].cpu, "x86");
    }

    #[test]
    fn reads_code_directory_and_the_cms_blob() {
        let bytes = signed_macho();
        let got = facts(&bytes).unwrap();
        assert!(got.has_code_signature);
        assert_eq!(got.signature.as_ref(), Some(&got_signature()));
        assert!(!format!("{:?}", got.signature).contains("CMS-BLOB"));
        let cms = got.cms.expect("cms");
        assert_eq!(cms.length, 8);
        assert_eq!(cms.magic, u32::from_be_bytes(*b"CMS-"));
        assert_eq!(cms.bytes, b"CMS-BLOB");
        assert_eq!(got.cms_verified, Some(false));

        let cms_only = signed_macho_without_code_directory();
        let got = facts(&cms_only).unwrap();
        assert!(got.has_code_signature);
        assert_eq!(got.signature, None);
        assert_eq!(got.cms.as_ref().map(|blob| blob.length), Some(20));
        assert_eq!(got.cms_verified, None);

        let past = signed_macho_with_short_blob();
        let got = facts(&past).unwrap();
        assert!(got.has_code_signature);
        assert_eq!(got.signature, None);
        assert_eq!(got.cms, None);
        assert_eq!(got.cms_verified, None);

        let arches = architectures(&bytes).unwrap();
        assert_eq!(arches[0].signature.as_ref(), Some(&got_signature()));
        assert_eq!(arches[0].cms.as_ref().map(|blob| blob.bytes.as_slice()), Some(b"CMS-BLOB".as_slice()));
        assert!(!format!("{:?}", arches[0].signature).contains("CMS-BLOB"));
        assert_eq!(architectures(&cms_only).unwrap()[0].signature, None);
    }

    #[test]
    fn cms_window_matches_the_code_directory_digest() {
        let mut cd = vec![0u8; 79];
        write_be(&mut cd, 0, 0xfade_0c02);
        write_be(&mut cd, 4, 79);
        write_be(&mut cd, 8, 0x20200);
        write_be(&mut cd, 20, 52);
        cd[37] = 2;
        write_be(&mut cd, 48, 68);
        cd[52..68].copy_from_slice(b"com.example.app\0");
        cd[68..79].copy_from_slice(b"TEAM123456\0");
        let digest = crate::hash::sha256(&cd);
        let cms_len = 8 + digest.len();
        let mut cms = vec![0u8; cms_len];
        write_be(&mut cms, 0, 0x434d_532d);
        write_be(&mut cms, 4, cms_len as u32);
        cms[8..].copy_from_slice(&digest);

        let blob_len = 28 + cd.len() + cms.len();
        let mut blob = vec![0u8; blob_len];
        write_be(&mut blob, 0, 0xfade_0cc0);
        write_be(&mut blob, 4, blob_len as u32);
        write_be(&mut blob, 8, 2);
        write_be(&mut blob, 12, 0x10000);
        write_be(&mut blob, 16, (28 + cd.len()) as u32);
        write_be(&mut blob, 20, 0);
        write_be(&mut blob, 24, 28);
        blob[28..28 + cd.len()].copy_from_slice(&cd);
        blob[28 + cd.len()..].copy_from_slice(&cms);

        let mut file = Vec::new();
        let mut push = |v: u32| file.extend_from_slice(&v.to_le_bytes());
        push(0xfeed_facf);
        push(0x0100_000c);
        push(0);
        push(1);
        push(1);
        push(16);
        push(0);
        push(0);
        push(0x1d);
        push(16);
        push(48);
        push(blob.len() as u32);
        file.extend_from_slice(&blob);
        assert_eq!(facts(&file).unwrap().cms_verified, Some(true));
    }

    /// A code directory with the given hash type and `hashSize` byte.
    fn code_directory_with_hash(hash_type: u8, hash_size: u8) -> Vec<u8> {
        let mut cd = vec![0u8; 79];
        write_be(&mut cd, 0, 0xfade_0c02);
        write_be(&mut cd, 4, 79);
        write_be(&mut cd, 8, 0x20200);
        write_be(&mut cd, 20, 52);
        cd[36] = hash_size;
        cd[37] = hash_type;
        write_be(&mut cd, 48, 68);
        cd[52..68].copy_from_slice(b"com.example.app\0");
        cd[68..79].copy_from_slice(b"TEAM123456\0");
        cd
    }

    /// A superblob holding that directory plus a CMS blob of a filler byte and
    /// `cms_digest`, so the window search has to slide.
    fn signed_macho_with_cms_digest(cd: &[u8], cms_digest: &[u8]) -> Vec<u8> {
        let cms_len = 9 + cms_digest.len();
        let mut cms = vec![0u8; cms_len];
        write_be(&mut cms, 0, 0x434d_532d);
        write_be(&mut cms, 4, cms_len as u32);
        cms[8] = 0x5a;
        cms[9..].copy_from_slice(cms_digest);

        let blob_len = 28 + cd.len() + cms.len();
        let mut blob = vec![0u8; blob_len];
        write_be(&mut blob, 0, 0xfade_0cc0);
        write_be(&mut blob, 4, blob_len as u32);
        write_be(&mut blob, 8, 2);
        write_be(&mut blob, 12, 0x10000);
        write_be(&mut blob, 16, (28 + cd.len()) as u32);
        write_be(&mut blob, 20, 0);
        write_be(&mut blob, 24, 28);
        blob[28..28 + cd.len()].copy_from_slice(cd);
        blob[28 + cd.len()..].copy_from_slice(&cms);

        let mut file = Vec::new();
        let mut push = |v: u32| file.extend_from_slice(&v.to_le_bytes());
        push(0xfeed_facf);
        push(0x0100_000c);
        push(0);
        push(1);
        push(1);
        push(16);
        push(0);
        push(0);
        push(0x1d);
        push(16);
        push(48);
        push(blob.len() as u32);
        file.extend_from_slice(&blob);
        file
    }

    #[test]
    fn cms_window_matches_truncated_sha256_and_sha384_digests() {
        // Type 3: the leading hashSize bytes of sha256.
        let cd = code_directory_with_hash(3, 20);
        let mut digest = crate::hash::sha256(&cd).to_vec();
        digest.truncate(20);
        let file = signed_macho_with_cms_digest(&cd, &digest);
        assert_eq!(facts(&file).unwrap().cms_verified, Some(true));

        // Type 4: sha384 truncated to hashSize bytes.
        let cd = code_directory_with_hash(4, 32);
        let mut digest = crate::hash::sha384(&cd).to_vec();
        digest.truncate(32);
        let file = signed_macho_with_cms_digest(&cd, &digest);
        assert_eq!(facts(&file).unwrap().cms_verified, Some(true));

        // A wrong truncated digest stays false.
        let cd = code_directory_with_hash(3, 20);
        let mut digest = crate::hash::sha256(&cd).to_vec();
        digest.truncate(20);
        digest[0] ^= 0xff;
        let file = signed_macho_with_cms_digest(&cd, &digest);
        assert_eq!(facts(&file).unwrap().cms_verified, Some(false));

        // Types `none` and unassigned leave cms_verified empty.
        let cd = code_directory_with_hash(0, 32);
        let file = signed_macho_with_cms_digest(&cd, &[0u8; 20]);
        assert_eq!(facts(&file).unwrap().cms_verified, None);
        let cd = code_directory_with_hash(5, 20);
        let file = signed_macho_with_cms_digest(&cd, &[0u8; 20]);
        assert_eq!(facts(&file).unwrap().cms_verified, None);
    }

    /// A superblob with slot 0x10005 holding the XML `xml` and, when `der` is given, a DER slot after it.
    fn entitled_macho(xml: &[u8], der: Option<&[u8]>) -> Vec<u8> {
        let entitlements_len = 8 + xml.len();
        let mut slot = vec![0u8; entitlements_len];
        write_be(&mut slot, 0, CSMAGIC_BLOBWRAPPER);
        write_be(&mut slot, 4, entitlements_len as u32);
        slot[8..].copy_from_slice(xml);
        let slots: &[(u32, &[u8])] = match der {
            Some(der) => &[(CSSLOT_ENTITLEMENTS, &slot), (CSSLOT_ENTITLEMENTS_DER, der)],
            None => &[(CSSLOT_ENTITLEMENTS, &slot)],
        };
        let index_len = slots.len() * 8;
        let blob_len = 12 + index_len + slots.iter().map(|(_, s)| s.len()).sum::<usize>();
        let mut blob = vec![0u8; blob_len];
        write_be(&mut blob, 0, CSMAGIC_EMBEDDED_SIGNATURE);
        write_be(&mut blob, 4, blob_len as u32);
        write_be(&mut blob, 8, slots.len() as u32);
        let mut at = 12 + index_len;
        for (i, (ty, bytes)) in slots.iter().enumerate() {
            write_be(&mut blob, 12 + i * 8, *ty);
            write_be(&mut blob, 12 + i * 8 + 4, at as u32);
            blob[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
        }
        lc_signature_file(&blob)
    }

    /// One `LC_CODE_SIGNATURE` pointing at `blob` at offset 48.
    fn lc_signature_file(blob: &[u8]) -> Vec<u8> {
        let mut file = Vec::new();
        let mut push = |v: u32| file.extend_from_slice(&v.to_le_bytes());
        push(0xfeed_facf);
        push(0x0100_000c);
        push(0);
        push(1);
        push(1);
        push(16);
        push(0);
        push(0);
        push(0x1d);
        push(16);
        push(48);
        push(blob.len() as u32);
        file.extend_from_slice(blob);
        file
    }

    fn entitlement_xml(keys: &[(&str, &str)]) -> Vec<u8> {
        let mut xml = String::from("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>");
        for (key, value) in keys {
            xml.push_str(&format!("<key>{key}</key><string>{value}</string>"));
        }
        xml.push_str("</dict></plist>");
        xml.into_bytes()
    }

    #[test]
    fn reads_entitlements_keys_and_the_capped_xml() {
        let xml = entitlement_xml(&[("com.example.container", "group.example"), ("keychain-access-groups", "x")]);
        let got = facts(&entitled_macho(&xml, None)).unwrap();
        let ent = got.entitlements.expect("entitlements");
        assert_eq!(
            ent.entries,
            vec![
                MachoEntitlement { key: "com.example.container".into(), value: Some("group.example".into()) },
                MachoEntitlement { key: "keychain-access-groups".into(), value: Some("x".into()) },
            ]
        );
        assert_eq!(ent.payload, String::from_utf8(xml).unwrap());

        let mut long = entitlement_xml(&[("one", "1")]);
        long.extend(std::iter::repeat(b'a').take(ENTITLEMENTS_XML_CAP + 64));
        let got = facts(&entitled_macho(&long, None)).unwrap();
        let ent = got.entitlements.expect("entitlements");
        assert_eq!(ent.payload.len(), ENTITLEMENTS_XML_CAP + "…".len());
        assert!(ent.payload.ends_with('…'));
        assert!(ent.payload.starts_with("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>one</key>"));
    }

    #[test]
    fn boolean_and_nested_entitlement_values() {
        let xml = b"<?xml version=\"1.0\"?><plist><dict>\
            <key>get-task-allow</key><true/>\
            <key>com.apple.private.skip-library-validation</key><false/>\
            <key>com.apple.security.application-groups</key><array><string>group.inner</string></array>\
            <key>platform-application</key><string>yes</string>\
            </dict></plist>";
        let got = facts(&entitled_macho(xml, None)).unwrap();
        assert_eq!(
            got.entitlements.expect("entitlements").entries,
            vec![
                MachoEntitlement { key: "get-task-allow".into(), value: Some("true".into()) },
                MachoEntitlement { key: "com.apple.private.skip-library-validation".into(), value: Some("false".into()) },
                MachoEntitlement { key: "com.apple.security.application-groups".into(), value: None },
                MachoEntitlement { key: "com.apple.security.application-groups[0]".into(), value: Some("group.inner".into()) },
                MachoEntitlement { key: "platform-application".into(), value: Some("yes".into()) },
            ]
        );
    }

    #[test]
    fn nested_dict_children_become_parent_dot_keys() {
        let xml = b"<?xml version=\"1.0\"?><plist><dict>\
            <key>com.apple.security.assets</key><dict>\
            <key>team</key><string>abc</string>\
            <key>flag</key><true/>\
            <key>off</key><false/>\
            <key>deep</key><dict><key>inner</key><string>x</string></dict>\
            <key>arr</key><array><string>y</string></array>\
            <key>num</key><integer>5</integer>\
            </dict>\
            <key>after</key><string>z</string>\
            </dict></plist>";
        let got = facts(&entitled_macho(xml, None)).unwrap();
        assert_eq!(
            got.entitlements.expect("entitlements").entries,
            vec![
                MachoEntitlement { key: "com.apple.security.assets".into(), value: None },
                MachoEntitlement { key: "com.apple.security.assets.team".into(), value: Some("abc".into()) },
                MachoEntitlement { key: "com.apple.security.assets.flag".into(), value: Some("true".into()) },
                MachoEntitlement { key: "com.apple.security.assets.off".into(), value: Some("false".into()) },
                // A deeper dict or array is skipped the way the top level skips one: the key stays, no value.
                MachoEntitlement { key: "com.apple.security.assets.deep".into(), value: None },
                MachoEntitlement { key: "com.apple.security.assets.arr".into(), value: None },
                MachoEntitlement { key: "com.apple.security.assets.num".into(), value: None },
                MachoEntitlement { key: "after".into(), value: Some("z".into()) },
            ]
        );
    }

    #[test]
    fn nested_array_items_are_indexed_in_order() {
        let mut xml = String::from("<?xml version=\"1.0\"?><plist><dict><key>groups</key><array>");
        for name in ["a", "b", "c"] {
            xml.push_str(&format!("<string>{name}</string>"));
        }
        xml.push_str("</array><key>tail</key><string>t</string></dict></plist>");
        let got = facts(&entitled_macho(xml.as_bytes(), None)).unwrap();
        assert_eq!(
            got.entitlements.expect("entitlements").entries,
            vec![
                MachoEntitlement { key: "groups".into(), value: None },
                MachoEntitlement { key: "groups[0]".into(), value: Some("a".into()) },
                MachoEntitlement { key: "groups[1]".into(), value: Some("b".into()) },
                MachoEntitlement { key: "groups[2]".into(), value: Some("c".into()) },
                MachoEntitlement { key: "tail".into(), value: Some("t".into()) },
            ]
        );
    }

    #[test]
    fn nested_entries_cap_at_32_with_a_more_marker() {
        let mut xml = String::from("<?xml version=\"1.0\"?><plist><dict><key>many</key><array>");
        for i in 0..35 {
            xml.push_str(&format!("<string>{i}</string>"));
        }
        xml.push_str("</array></dict></plist>");
        let got = facts(&entitled_macho(xml.as_bytes(), None)).unwrap();
        let entries = got.entitlements.expect("entitlements").entries;
        assert_eq!(entries.len(), 2 + NESTED_ENTITLEMENTS_CAP);
        assert_eq!(entries[0].key, "many");
        assert_eq!(entries[0].value, None);
        assert_eq!(entries[1].key, "many[0]");
        assert_eq!(entries[1].value, Some("0".into()));
        assert_eq!(entries[32].key, "many[31]");
        assert_eq!(entries[32].value, Some("31".into()));
        assert_eq!(entries[33].key, "many");
        assert_eq!(entries[33].value, Some("... 3 more".into()));
    }

    #[test]
    fn truncated_nested_payload_keeps_the_keys_that_parsed() {
        let xml = b"<?xml version=\"1.0\"?><plist><dict>\
            <key>outer</key><dict>\
            <key>one</key><string>1</string>\
            <key>two</key><string>2";
        let got = facts(&entitled_macho(xml, None)).unwrap();
        assert_eq!(
            got.entitlements.expect("entitlements").entries,
            vec![
                MachoEntitlement { key: "outer".into(), value: None },
                MachoEntitlement { key: "outer.one".into(), value: Some("1".into()) },
                MachoEntitlement { key: "outer.two".into(), value: None },
            ]
        );
    }

    #[test]
    fn an_array_tag_cut_before_its_close_terminates_and_keeps_parsed_keys() {
        // `<array><string` ends mid-tag: the `<string` has no `>` or space
        // before the end of the payload. The array loop used to restart at
        // that same `<` and spin forever. It must stop at the end of `text`
        // and keep the keys that parsed before it.
        for (cut, want) in [
            (
                "<array><string",
                vec![
                    MachoEntitlement { key: "g".into(), value: None },
                    MachoEntitlement { key: "g[0]".into(), value: None },
                ],
            ),
            (
                "<array><",
                vec![
                    MachoEntitlement { key: "g".into(), value: None },
                    MachoEntitlement { key: "g[0]".into(), value: None },
                ],
            ),
        ] {
            let xml = format!(
                "<?xml version=\"1.0\"?><plist><dict>\
                 <key>g</key>{}",
                cut
            );
            let got = facts(&entitled_macho(xml.as_bytes(), None)).unwrap();
            assert_eq!(got.entitlements.expect("entitlements").entries, want);
        }
        // A complete value after the array still parses.
        let xml = b"<?xml version=\"1.0\"?><plist><dict>\
            <key>g</key><array><string>a</string></array>\
            <key>h</key><string>b</string></dict></plist>";
        let got = facts(&entitled_macho(xml, None)).unwrap();
        assert_eq!(
            got.entitlements.expect("entitlements").entries,
            vec![
                MachoEntitlement { key: "g".into(), value: None },
                MachoEntitlement { key: "g[0]".into(), value: Some("a".into()) },
                MachoEntitlement { key: "h".into(), value: Some("b".into()) },
            ]
        );
    }

    #[test]
    fn self_closing_and_tight_self_closing_values_keep_later_keys() {
        // Both self-closing spellings must skip cleanly and leave the
        // following keys readable; neither may panic.
        for sep in ["<dict />", "<dict/>", "<array />", "<array/>"] {
            let xml = format!(
                "<?xml version=\"1.0\"?><plist><dict>\
                 <key>first</key>{sep}\
                 <key>second</key><string>yes</string>\
                 </dict></plist>"
            );
            let got = facts(&entitled_macho(xml.as_bytes(), None)).unwrap();
            assert_eq!(
                got.entitlements.expect("entitlements").entries,
                vec![
                    MachoEntitlement { key: "first".into(), value: None },
                    MachoEntitlement { key: "second".into(), value: Some("yes".into()) },
                ],
                "sep: {sep}"
            );
        }
    }

    #[test]
    fn non_xml_entitlement_payload_stays_hex() {
        let got = facts(&entitled_macho(b"\x30\x82\x01\x0a\x02\x01\x01", None)).unwrap();
        let ent = got.entitlements.expect("entitlements");
        assert!(ent.entries.is_empty());
        assert_eq!(ent.payload, "3082010a020101");
    }

    #[test]
    fn der_slot_is_a_size_only() {
        let der = b"\x30\x82\x04\x10\x02\x01\x01";
        let xml = entitlement_xml(&[("com.example.one", "1")]);
        let got = facts(&entitled_macho(&xml, Some(der))).unwrap();
        assert_eq!(got.entitlements_der_size, Some(der.len() as u32));
        assert_eq!(got.entitlements.expect("entitlements").entries.len(), 1);

        let got = facts(&entitled_macho(&xml, None)).unwrap();
        assert_eq!(got.entitlements_der_size, None);
    }

    #[test]
    fn missing_entitlements_slot_is_none() {
        let got = facts(&signed_macho()).unwrap();
        assert_eq!(got.entitlements, None);
        assert_eq!(got.entitlements_der_size, None);
        assert!(architectures(&signed_macho()).unwrap()[0].entitlements.is_none());
    }

    #[test]
    fn mid_index_entitlement_slot_does_not_swallow_the_der_slot() {
        let xml = entitlement_xml(&[("com.example.two", "2")]);
        let der = b"\x30\x03\x02\x01\x01";
        let file = entitled_macho(&xml, Some(der));
        let got = facts(&file).unwrap();
        assert_eq!(got.entitlements_der_size, Some(5));
        let xml = std::str::from_utf8(&xml).unwrap();
        assert!(got.entitlements.expect("entitlements").payload.starts_with(xml));
    }

    #[test]
    fn fat_slices_keep_their_own_entitlements() {
        let xml_arm = entitlement_xml(&[("com.example.arm", "arm")]);
        let xml_intel = entitlement_xml(&[("com.example.intel", "intel")]);
        let arm = entitled_macho(&xml_arm, None);
        let intel = entitled_macho(&xml_intel, None);
        let bytes = fat_two(&arm, &intel);
        let arches = architectures(&bytes).unwrap();
        let arm_ent = arches[0].entitlements.as_ref().expect("arm entitlements");
        let intel_ent = arches[1].entitlements.as_ref().expect("intel entitlements");
        assert_eq!(arm_ent.entries[0].key, "com.example.arm");
        assert_eq!(intel_ent.entries[0].key, "com.example.intel");
        assert!(arches[0].entitlements_der_size.is_none());

        let mixed = fat_two(&entitled_macho(&xml_arm, None), b"not-a-slice");
        let arches = architectures(&mixed).unwrap();
        assert!(arches[0].entitlements.is_some());
        assert!(arches[1].entitlements.is_none());
        assert!(arches[1].entitlements_der_size.is_none());
    }

    #[test]
    fn exec_segment_fields_come_from_a_newer_code_directory() {
        let mut cd = vec![0u8; 96];
        write_be(&mut cd, 0, CSMAGIC_CODEDIRECTORY);
        write_be(&mut cd, 4, 96);
        write_be(&mut cd, 8, 0x20500);
        write_be(&mut cd, 20, 52);
        write_be(&mut cd, 24, 1);
        cd[37] = 2;
        write_be(&mut cd, 48, 52);
        cd[64..72].copy_from_slice(&0u64.to_be_bytes());
        cd[72..80].copy_from_slice(&4096u64.to_be_bytes());
        cd[80..88].copy_from_slice(&1u64.to_be_bytes());
        let blob = cd_blob(&cd);
        let got = facts(&lc_signature_file(&blob)).unwrap();
        let sig = got.signature.expect("signature");
        assert_eq!(sig.exec_seg_offset, Some(0));
        assert_eq!(sig.exec_seg_size, Some(4096));
        assert_eq!(sig.exec_seg_flags, Some(1));
        assert_eq!(sig.special_slots, 1);

        let old = facts(&signed_macho()).unwrap();
        let sig = old.signature.expect("signature");
        assert_eq!(sig.exec_seg_offset, None);
        assert_eq!(sig.exec_seg_size, None);
        assert_eq!(sig.exec_seg_flags, None);
        assert_eq!(sig.special_slots, 0);
    }

    /// A superblob whose only slot is the code directory `cd`.
    fn cd_blob(cd: &[u8]) -> Vec<u8> {
        let mut blob = vec![0u8; 20 + cd.len()];
        write_be(&mut blob, 0, CSMAGIC_EMBEDDED_SIGNATURE);
        write_be(&mut blob, 4, (20 + cd.len()) as u32);
        write_be(&mut blob, 8, 1);
        write_be(&mut blob, 12, CSSLOT_CODEDIRECTORY);
        write_be(&mut blob, 16, 20);
        blob[20..].copy_from_slice(cd);
        blob
    }

    #[test]
    fn reads_code_directory_hash_slots() {
        let got = facts(&hashed_macho()).unwrap();
        let sig = got.signature.expect("signature");
        assert_eq!(
            sig.hashes,
            vec![
                MachoHashSlot { index: -1, digest: "aabb".into() },
                MachoHashSlot { index: 0, digest: "ccdd".into() },
            ]
        );
    }

    #[test]
    fn a_hostile_special_slot_count_does_not_panic() {
        // nSpecialSlots = 0x80000000 truncates to i32::MIN; the negation
        // used to abort. hashOffset 0x80000000 puts every special slot past
        // the 48-byte directory, so none is readable.
        let mut cd = vec![0u8; 48];
        write_be(&mut cd, 0, 0xfade_0c02);
        write_be(&mut cd, 4, 48);
        write_be(&mut cd, 8, 0x2_0000);
        write_be(&mut cd, 16, 0x8000_0000); // hashOffset
        write_be(&mut cd, 20, 44);
        write_be(&mut cd, 24, 0x8000_0000); // nSpecialSlots
        write_be(&mut cd, 28, 0); // nCodeSlots
        cd[36] = 1; // hashSize
        cd[37] = 2; // sha256
        cd[44..46].copy_from_slice(b"i\0");

        let blob_len = (20 + cd.len()) as u32;
        let mut blob = vec![0u8; blob_len as usize];
        write_be(&mut blob, 0, 0xfade_0cc0);
        write_be(&mut blob, 4, blob_len);
        write_be(&mut blob, 8, 1);
        write_be(&mut blob, 12, 0);
        write_be(&mut blob, 16, 20);
        blob[20..].copy_from_slice(&cd);

        let mut file = Vec::new();
        let mut push = |v: u32| file.extend_from_slice(&v.to_le_bytes());
        push(0xfeed_facf);
        push(0x0100_000c);
        push(0);
        push(1);
        push(1);
        push(16);
        push(0);
        push(0);
        push(0x1d);
        push(16);
        push(48);
        push(blob.len() as u32);
        file.extend_from_slice(&blob);

        let got = facts(&file).unwrap();
        let sig = got.signature.expect("signature");
        assert_eq!(sig.special_slots, 0x8000_0000);
        // The walk stops at the directory end: 48 single-byte slots read.
        assert_eq!(sig.hashes.len(), 48);
        // The first index is i32::MIN, computed without negation overflow.
        assert_eq!(sig.hashes[0].index, i32::MIN);
    }

    #[test]
    fn fat_slices_keep_their_own_code_directories() {
        let arm = signed_macho();
        let intel = retarget(signed_macho(), b"com.example.cmd\0", b"TEAM654321\0");
        let bytes = fat_two(&arm, &intel);
        let arches = architectures(&bytes).unwrap();
        assert!(facts(&bytes).is_err());
        assert_eq!(arches[0].cpu, "arm64");
        assert_eq!(arches[0].signature, Some(got_signature()));
        assert_eq!(arches[1].cpu, "x86_64");
        assert_eq!(
            arches[1].signature,
            Some(MachoSignature {
                identifier: "com.example.cmd".into(),
                hash_type: "sha256".into(),
                team_id: Some("TEAM654321".into()),
                hashes: Vec::new(),
                special_slots: 0,
                exec_seg_offset: None,
                exec_seg_size: None,
                exec_seg_flags: None,
            })
        );
        assert_eq!(arches[0].cms.as_ref().map(|blob| blob.bytes.as_slice()), Some(b"CMS-BLOB".as_slice()));
        assert!(!format!("{:?}", arches[0].signature).contains("CMS-BLOB"));
        assert!(!format!("{:?}", arches[1].signature).contains("CMS-BLOB"));
    }

    #[test]
    fn fat_slices_keep_their_own_identity() {
        let arm_uuid = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let intel_uuid = [0xaa; 16];
        let arm = identity_macho(
            0x0100_000c,
            arm_uuid,
            "libarm.dylib",
            "/opt/arm",
            Some((1, 12 << 16, (13 << 16) | (1 << 8))),
        );
        let intel = identity_macho(0x0100_0007, intel_uuid, "libx86.dylib", "/opt/x86", None);
        let thin = facts(&arm).unwrap();
        assert_eq!(thin.uuid.as_deref(), Some("0102030405060708090a0b0c0d0e0f10"));
        assert_eq!(thin.dylibs, vec!["self".to_string(), "libarm.dylib".to_string()]);
        assert_eq!(thin.rpaths, vec!["/opt/arm".to_string()]);
        assert_eq!(thin.platform.as_deref(), Some("macos"));
        assert_eq!(thin.minos.as_deref(), Some("12.0.0"));
        assert_eq!(thin.sdk.as_deref(), Some("13.1.0"));

        let bytes = fat_two(&arm, &intel);
        let arches = architectures(&bytes).unwrap();
        assert_eq!(arches[0].uuid.as_deref(), Some("0102030405060708090a0b0c0d0e0f10"));
        assert_eq!(arches[0].dylibs, vec!["self".to_string(), "libarm.dylib".to_string()]);
        assert_eq!(arches[0].rpaths, vec!["/opt/arm".to_string()]);
        assert_eq!(arches[0].platform.as_deref(), Some("macos"));
        assert_eq!(arches[1].uuid.as_deref(), Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert_eq!(arches[1].dylibs, vec!["self".to_string(), "libx86.dylib".to_string()]);
        assert_eq!(arches[1].rpaths, vec!["/opt/x86".to_string()]);
        assert_eq!(arches[1].platform, None);
        assert!(facts(&bytes).is_err());
    }

    #[test]
    fn unreadable_fat_slice_leaves_the_code_directory_empty() {
        let bytes = fat_two(&signed_macho(), b"not-a-slice");
        let arches = architectures(&bytes).unwrap();
        assert_eq!(
            arches[0].signature.as_ref().map(|sig| sig.identifier.as_str()),
            Some("com.example.app")
        );
        assert_eq!(arches[1].cpu, "x86_64");
        assert_eq!(arches[1].signature, None);
        assert_eq!(arches[1].uuid, None);
        assert!(arches[1].dylibs.is_empty());
        assert!(arches[1].rpaths.is_empty());
    }

    fn identity_macho(
        cputype: u32,
        uuid: [u8; 16],
        dylib: &str,
        rpath: &str,
        build: Option<(u32, u32, u32)>,
    ) -> Vec<u8> {
        let mut commands = vec![uuid_cmd(uuid), load_dylib(dylib), rpath_cmd(rpath)];
        if let Some((platform, minos, sdk)) = build {
            commands.push(build_version(platform, minos, sdk));
        }
        macho_object(cputype, &commands)
    }

    fn macho_object(cputype: u32, commands: &[Vec<u8>]) -> Vec<u8> {
        let sizeofcmds: u32 = commands.iter().map(|cmd| cmd.len() as u32).sum();
        let mut buf = Vec::new();
        let mut push = |v: u32| buf.extend_from_slice(&v.to_le_bytes());
        push(0xfeed_facf);
        push(cputype);
        push(0);
        push(1);
        push(commands.len() as u32);
        push(sizeofcmds);
        push(0);
        push(0);
        for cmd in commands {
            buf.extend_from_slice(cmd);
        }
        buf
    }

    fn uuid_cmd(uuid: [u8; 16]) -> Vec<u8> {
        let mut cmd = vec![0u8; 24];
        cmd[0..4].copy_from_slice(&0x1bu32.to_le_bytes());
        cmd[4..8].copy_from_slice(&24u32.to_le_bytes());
        cmd[8..24].copy_from_slice(&uuid);
        cmd
    }

    fn load_dylib(name: &str) -> Vec<u8> {
        cstring_cmd(0xc, 24, 24, name)
    }

    fn rpath_cmd(path: &str) -> Vec<u8> {
        cstring_cmd(0x8000_001c, 12, 12, path)
    }

    fn cstring_cmd(cmd: u32, header: usize, string_off: u32, value: &str) -> Vec<u8> {
        let bytes = value.as_bytes();
        let mut size = header + bytes.len() + 1;
        size = size.div_ceil(8) * 8;
        let mut out = vec![0u8; size];
        out[0..4].copy_from_slice(&cmd.to_le_bytes());
        out[4..8].copy_from_slice(&(size as u32).to_le_bytes());
        out[8..12].copy_from_slice(&string_off.to_le_bytes());
        let at = string_off as usize;
        out[at..at + bytes.len()].copy_from_slice(bytes);
        out
    }

    fn build_version(platform: u32, minos: u32, sdk: u32) -> Vec<u8> {
        let mut cmd = vec![0u8; 24];
        let mut push = |at: usize, v: u32| cmd[at..at + 4].copy_from_slice(&v.to_le_bytes());
        push(0, 0x32);
        push(4, 24);
        push(8, platform);
        push(12, minos);
        push(16, sdk);
        cmd
    }

    fn got_signature() -> MachoSignature {
        MachoSignature {
            identifier: "com.example.app".into(),
            hash_type: "sha256".into(),
            team_id: Some("TEAM123456".into()),
            hashes: Vec::new(),
            special_slots: 0,
            exec_seg_offset: None,
            exec_seg_size: None,
            exec_seg_flags: None,
        }
    }

    fn retarget(mut bytes: Vec<u8>, ident: &[u8], team: &[u8]) -> Vec<u8> {
        let ident_at = bytes
            .windows(ident.len())
            .position(|window| window == b"com.example.app\0")
            .expect("identifier");
        let team_at = bytes
            .windows(team.len())
            .position(|window| window == b"TEAM123456\0")
            .expect("team id");
        bytes[ident_at..ident_at + ident.len()].copy_from_slice(ident);
        bytes[team_at..team_at + team.len()].copy_from_slice(team);
        bytes
    }

    fn fat_two(first: &[u8], second: &[u8]) -> Vec<u8> {
        let off1 = 64u32;
        let off2 = off1 + first.len() as u32;
        let mut out = vec![0u8; off2 as usize + second.len()];
        write_be(&mut out, 0, 0xcafe_babe);
        write_be(&mut out, 4, 2);
        write_be(&mut out, 8, 0x0100_000c);
        write_be(&mut out, 16, off1);
        write_be(&mut out, 20, first.len() as u32);
        write_be(&mut out, 28, 0x0100_0007);
        write_be(&mut out, 36, off2);
        write_be(&mut out, 40, second.len() as u32);
        out[off1 as usize..off1 as usize + first.len()].copy_from_slice(first);
        out[off2 as usize..off2 as usize + second.len()].copy_from_slice(second);
        out
    }

    /// Little-endian 64-bit Mach-O. `with_meta` adds `LC_BUILD_VERSION` (iOS 15.4.1,
    /// SDK 16.0.0) and `LC_CODE_SIGNATURE`.
    fn thin_macho(cputype: u32, with_meta: bool) -> Vec<u8> {
        let ncmds: u32 = if with_meta { 2 } else { 0 };
        let sizeofcmds: u32 = if with_meta { 24 + 16 } else { 0 };
        let mut buf = Vec::new();
        let mut push = |v: u32| buf.extend_from_slice(&v.to_le_bytes());
        push(0xfeed_facf);
        push(cputype);
        push(0);
        push(1); // MH_OBJECT
        push(ncmds);
        push(sizeofcmds);
        push(0);
        push(0);
        if with_meta {
            push(0x32); // LC_BUILD_VERSION
            push(24);
            push(2); // PLATFORM_IOS
            push((15 << 16) | (4 << 8) | 1);
            push(16 << 16);
            push(0);
            push(0x1d); // LC_CODE_SIGNATURE
            push(16);
            push(0);
            push(0);
        }
        buf
    }

    /// One `LC_CODE_SIGNATURE`. The index lists the CMS slot first. The code directory is version `0x20200`, hash type sha256.
    fn signed_macho() -> Vec<u8> {
        let mut cd = vec![0u8; 79];
        write_be(&mut cd, 0, 0xfade_0c02);
        write_be(&mut cd, 4, 79);
        write_be(&mut cd, 8, 0x20200);
        write_be(&mut cd, 20, 52);
        cd[37] = 2;
        write_be(&mut cd, 48, 68);
        cd[52..68].copy_from_slice(b"com.example.app\0");
        cd[68..79].copy_from_slice(b"TEAM123456\0");

        let mut blob = vec![0u8; 115];
        write_be(&mut blob, 0, 0xfade_0cc0);
        write_be(&mut blob, 4, 115);
        write_be(&mut blob, 8, 2);
        write_be(&mut blob, 12, 0x10000);
        write_be(&mut blob, 16, 107);
        write_be(&mut blob, 20, 0);
        write_be(&mut blob, 24, 28);
        blob[28..107].copy_from_slice(&cd);
        blob[107..115].copy_from_slice(b"CMS-BLOB");

        let mut file = Vec::new();
        let mut push = |v: u32| file.extend_from_slice(&v.to_le_bytes());
        push(0xfeed_facf);
        push(0x0100_000c);
        push(0);
        push(1);
        push(1);
        push(16);
        push(0);
        push(0);
        push(0x1d);
        push(16);
        push(48);
        push(blob.len() as u32);
        file.extend_from_slice(&blob);
        file
    }

    fn signed_macho_without_code_directory() -> Vec<u8> {
        let mut blob = vec![0u8; 20];
        write_be(&mut blob, 0, 0xfade_0cc0);
        write_be(&mut blob, 4, 20);
        write_be(&mut blob, 8, 1);
        write_be(&mut blob, 12, 0x10000);
        write_be(&mut blob, 16, 0);
        let mut file = Vec::new();
        let mut push = |v: u32| file.extend_from_slice(&v.to_le_bytes());
        push(0xfeed_facf);
        push(0x0100_000c);
        push(0);
        push(1);
        push(1);
        push(16);
        push(0);
        push(0);
        push(0x1d);
        push(16);
        push(48);
        push(blob.len() as u32);
        file.extend_from_slice(&blob);
        file
    }

    /// `LC_CODE_SIGNATURE` whose blob is not in the file.
    fn signed_macho_with_short_blob() -> Vec<u8> {
        let mut file = Vec::new();
        let mut push = |v: u32| file.extend_from_slice(&v.to_le_bytes());
        push(0xfeed_facf);
        push(0x0100_000c);
        push(0);
        push(1);
        push(1);
        push(16);
        push(0);
        push(0);
        push(0x1d);
        push(16);
        push(4_000);
        push(32);
        file
    }

    /// One code slot `ccdd` and one special slot `aabb`.
    fn hashed_macho() -> Vec<u8> {
        let mut cd = vec![0u8; 52];
        write_be(&mut cd, 0, 0xfade_0c02);
        write_be(&mut cd, 4, 52);
        write_be(&mut cd, 8, 0x2_0000);
        write_be(&mut cd, 16, 50);
        write_be(&mut cd, 20, 44);
        write_be(&mut cd, 24, 1);
        write_be(&mut cd, 28, 1);
        cd[36] = 2;
        cd[37] = 2;
        cd[44..47].copy_from_slice(b"id\0");
        cd[48..50].copy_from_slice(&[0xaa, 0xbb]);
        cd[50..52].copy_from_slice(&[0xcc, 0xdd]);

        let blob_len = (20 + cd.len()) as u32;
        let mut blob = vec![0u8; blob_len as usize];
        write_be(&mut blob, 0, 0xfade_0cc0);
        write_be(&mut blob, 4, blob_len);
        write_be(&mut blob, 8, 1);
        write_be(&mut blob, 12, 0);
        write_be(&mut blob, 16, 20);
        blob[20..].copy_from_slice(&cd);

        let mut file = Vec::new();
        let mut push = |v: u32| file.extend_from_slice(&v.to_le_bytes());
        push(0xfeed_facf);
        push(0x0100_000c);
        push(0);
        push(1);
        push(1);
        push(16);
        push(0);
        push(0);
        push(0x1d);
        push(16);
        push(48);
        push(blob.len() as u32);
        file.extend_from_slice(&blob);
        file
    }

    #[test]
    fn reads_embedded_plist_and_overlay_without_failing_a_short_one() {
        let xml = b"<?xml version=\"1.0\"?><plist><dict>\
            <key>CFBundleIdentifier</key><string>com.example.plist</string>\
            <key>CFBundleName</key><string>Example</string>\
            </dict></plist>";
        let plist = segment_slice(0x0100_000c, "__info_plist", xml, b"");
        let got = facts(&plist).unwrap();
        let info = got.info_plist.expect("plist");
        assert_eq!(info.bundle_id.as_deref(), Some("com.example.plist"));
        assert_eq!(info.bundle_name.as_deref(), Some("Example"));
        assert_eq!(got.overlay, None);

        let short = segment_slice(0x0100_000c, "__info_plist", b"<plist>", b"");
        let got = facts(&short).unwrap();
        assert_eq!(got.info_plist, None);

        let over = segment_slice(0x0100_000c, "__text", &[0xc3], b"EXTRA");
        let got = facts(&over).unwrap();
        let overlay = got.overlay.expect("overlay");
        assert_eq!(overlay.size, 5);
        assert_eq!(&over[overlay.offset as usize..], b"EXTRA");
    }

    /// A minimal `bplist00` payload: one dict of the given ASCII keys and
    /// values, offset size 1, ref size 1.
    fn binary_plist(entries: &[(&str, &str)]) -> Vec<u8> {
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
            for s in [k, v] {
                let raw = s.as_bytes();
                let mut obj = if raw.len() < 0xF {
                    let mut obj = vec![0x50 | raw.len() as u8];
                    obj.extend_from_slice(raw);
                    obj
                } else {
                    let mut obj = vec![0x5F, 0x10, raw.len() as u8];
                    obj.extend_from_slice(raw);
                    obj
                };
                objects.push(std::mem::take(&mut obj));
            }
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
    fn reads_an_embedded_binary_plist() {
        let bp = binary_plist(&[("CFBundleIdentifier", "com.example.bplist"), ("CFBundleName", "Example")]);
        let file = segment_slice(0x0100_000c, "__info_plist", &bp, b"");
        let got = facts(&file).unwrap();
        let info = got.info_plist.expect("plist");
        assert_eq!(info.bundle_id.as_deref(), Some("com.example.bplist"));
        assert_eq!(info.bundle_name.as_deref(), Some("Example"));
        assert_eq!(info.bundle_version.as_deref(), None);
    }

    #[test]
    fn reads_objc_class_name_strings_from_the_named_section() {
        let body = b"NSObject\0UIViewController\0_something\0";
        let file = segment_slice(0x0100_000c, "__objc_classname", body, b"");
        let got = facts(&file).unwrap();
        assert_eq!(
            got.objc_strings,
            vec![
                ObjcString { text: "NSObject".into(), module_name: None },
                ObjcString { text: "UIViewController".into(), module_name: None },
                ObjcString { text: "_something".into(), module_name: None },
            ]
        );
        assert_eq!(architectures(&file).unwrap()[0].objc_strings, got.objc_strings);
    }

    #[test]
    fn objc_strings_skip_non_name_sections_and_untagged_runs() {
        // A pointer section (`__objc_classlist` holds 8-byte pointers): the bytes are
        // not printable runs ending in NUL, so the list stays empty.
        let pointers = 0u64.to_le_bytes();
        let file = segment_slice(0x0100_000c, "__objc_classlist", &pointers, b"");
        assert_eq!(facts(&file).unwrap().objc_strings, Vec::<ObjcString>::new());

        // A non-objc section with the same bytes contributes nothing.
        let text = b"NSObject\0";
        let file = segment_slice(0x0100_000c, "__cstring", text, b"");
        assert_eq!(facts(&file).unwrap().objc_strings, Vec::<ObjcString>::new());

        // A printable run with no terminating NUL is not a C string and stays unread.
        let unterminated = b"NSObject";
        let file = segment_slice(0x0100_000c, "__objc_classname", unterminated, b"");
        assert_eq!(facts(&file).unwrap().objc_strings, Vec::<ObjcString>::new());

        // An empty section and a section whose bytes cannot be read leave an empty
        // list and do not fail the parse.
        let file = segment_slice(0x0100_000c, "__objc_methname", b"", b"");
        assert_eq!(facts(&file).unwrap().objc_strings, Vec::<ObjcString>::new());
    }

    #[test]
    fn objc_strings_cap_at_128_with_a_more_marker() {
        let mut body = Vec::new();
        for i in 0..140 {
            body.extend_from_slice(format!("Cls{i}\0").as_bytes());
        }
        let file = segment_slice(0x0100_000c, "__objc_classname", &body, b"");
        let got = facts(&file).unwrap();
        assert_eq!(got.objc_strings.len(), 129);
        assert_eq!(got.objc_strings[0].text, "Cls0");
        assert_eq!(got.objc_strings[0].module_name, None);
        assert_eq!(got.objc_strings[127].text, "Cls127");
        assert_eq!(got.objc_strings[128].text, "... 12 more");
        assert_eq!(got.objc_strings[128].module_name, None);
    }

    #[test]
    fn a_swift_name_on_an_objc_section_string_carries_module_name() {
        let body = b"$s4main3fooyyF\0_$s4main3bar3quxSfE\0";
        let file = segment_slice(0x0100_000c, "__objc_classname", body, b"");
        let got = facts(&file).unwrap();
        assert_eq!(got.objc_strings.len(), 2);
        assert_eq!(got.objc_strings[0].text, "$s4main3fooyyF");
        assert_eq!(got.objc_strings[0].module_name.as_deref(), Some("main.foo"));
        assert_eq!(got.objc_strings[1].text, "_$s4main3bar3quxSfE");
        assert_eq!(got.objc_strings[1].module_name.as_deref(), Some("main.bar"));
        assert_eq!(architectures(&file).unwrap()[0].objc_strings, got.objc_strings);
    }

    #[test]
    fn a_swift_rejected_objc_string_stays_raw_and_does_not_fail_the_parse() {
        // A plain class name is not a Swift mangled name and stays raw.
        // A truncated Swift name is rejected and stays raw. Neither fails the parse.
        let body = b"NSObject\0$s4main\0";
        let file = segment_slice(0x0100_000c, "__objc_classname", body, b"");
        let got = facts(&file).unwrap();
        assert_eq!(got.objc_strings.len(), 2);
        assert_eq!(got.objc_strings[0].text, "NSObject");
        assert_eq!(got.objc_strings[0].module_name, None);
        assert_eq!(got.objc_strings[1].text, "$s4main");
        assert_eq!(got.objc_strings[1].module_name, None);
    }

    /// One 64-bit `__TEXT` segment. `extra` is past `filesize`.
    fn segment_slice(cputype: u32, sectname: &str, body: &[u8], extra: &[u8]) -> Vec<u8> {
        let code_off = 32 + 152;
        let filesize = code_off + body.len();
        let mut file = vec![0u8; filesize + extra.len()];
        write_le(&mut file, 0, 0xfeed_facf);
        write_le(&mut file, 4, cputype);
        write_le(&mut file, 12, 1);
        write_le(&mut file, 16, 1);
        write_le(&mut file, 20, 152);
        write_le(&mut file, 32, 0x19);
        write_le(&mut file, 36, 152);
        file[40..46].copy_from_slice(b"__TEXT");
        write_le64(&mut file, 56, 0);
        write_le64(&mut file, 64, filesize as u64);
        write_le64(&mut file, 72, 0);
        write_le64(&mut file, 80, filesize as u64);
        write_le(&mut file, 88, 7);
        write_le(&mut file, 92, 5);
        write_le(&mut file, 96, 1);
        let sect = 32 + 72;
        let name = sectname.as_bytes();
        file[sect..sect + name.len()].copy_from_slice(name);
        file[sect + 16..sect + 22].copy_from_slice(b"__TEXT");
        write_le64(&mut file, sect + 32, 0x1000);
        write_le64(&mut file, sect + 40, body.len() as u64);
        write_le(&mut file, sect + 48, code_off as u32);
        file[code_off..code_off + body.len()].copy_from_slice(body);
        file[filesize..].copy_from_slice(extra);
        file
    }

    fn write_be(buf: &mut [u8], at: usize, value: u32) {
        buf[at..at + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn write_le(buf: &mut [u8], at: usize, value: u32) {
        buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_le64(buf: &mut [u8], at: usize, value: u64) {
        buf[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
}
