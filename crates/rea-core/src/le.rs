//! Minimal Linear Executable (LE) support — the Watcom/DOS/4GW linear
//! executable format used by classic 1990s DOS games (e.g. the original
//! Warcraft demo). Layout was derived empirically from a DOS/4GW binary and
//! cross-checked against the OS/2 `exe386` structure definitions
//! (E32_* / O32_* fields).
//!
//! Scope: object table, page map, entry point, internal fixups, and
//! page-granular vaddr→file-offset translation (enough for info/sections/disasm).
//! Entry bundles and iterated (compressed) pages are not yet handled.

use crate::{Arch, Error, Result, Section};

fn u16_at(bytes: &[u8], off: usize) -> Result<u16> {
    bytes
        .get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| Error::Parse("le: truncated header".into()))
}

fn u32_at(bytes: &[u8], off: usize) -> Result<u32> {
    bytes
        .get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| Error::Parse("le: truncated header".into()))
}

#[derive(Debug, Clone)]
struct LeObject {
    base: u32,
    size: u32,
    flags: u32,
    /// 1-based index of this object's first entry in the page map.
    pagemap: u32,
    /// Number of page-map entries covering this object.
    mapsize: u32,
}

/// Page-granular virtual-address translation for an LE image.
///
/// Linear section mapping does not work for LE (pages are scattered and may
/// be compressed), so translation goes through the object table + page map:
///
/// ```text
/// off_in_obj = vaddr - object.base
/// page       = page_map[object.pagemap - 1 + off_in_obj / page_size] (high u16)
/// file_off   = header + datapage + (page - 1) * page_size + off_in_obj % page_size
/// ```
#[derive(Debug, Clone)]
pub struct LePages {
    header_off: usize,
    pagesize: u32,
    /// Byte offset of the data-page area, relative to the LE header.
    datapage: u32,
    objects: Vec<LeObject>,
    /// Page numbers (1-based) from the object page table.
    pages: Vec<u16>,
}

impl LePages {
    /// Map a virtual address to a file offset. Returns `None` for addresses
    /// outside any object, beyond an object's mapped pages, or in page types
    /// we cannot expand (iterated/compressed).
    pub fn translate(&self, vaddr: u64) -> Option<u64> {
        let pagesize = u64::from(self.pagesize);
        let obj = self.objects.iter().find(|o| {
            vaddr >= u64::from(o.base) && vaddr < u64::from(o.base) + u64::from(o.size)
        })?;
        let off = vaddr - u64::from(obj.base);
        let idx = (off / pagesize) as usize;
        if idx >= obj.mapsize as usize {
            return None;
        }
        let page = u64::from(*self.pages.get(obj.pagemap as usize - 1 + idx)?);
        if page == 0 {
            return None;
        }
        Some(
            self.header_off as u64
                + u64::from(self.datapage)
                + (page - 1) * pagesize
                + off % pagesize,
        )
    }
    /// Reverse translation: file offset (inside the data-page area) back to
    /// a virtual address. Needed for string/constant cross-referencing.
    pub fn offset_to_vaddr(&self, file_off: u64) -> Option<u64> {
        let area = self.header_off as u64 + u64::from(self.datapage);
        if file_off < area {
            return None;
        }
        let in_area = file_off - area;
        let pagesize = u64::from(self.pagesize);
        let page_idx = (in_area / pagesize) as usize;
        let page_no = *self.pages.get(page_idx)? as u64;
        if page_no == 0 {
            return None;
        }
        let mut start_idx = 0usize;
        for o in &self.objects {
            let idx = page_idx.checked_sub(start_idx)?;
            if (idx as u64) < u64::from(o.mapsize) {
                return Some(
                    u64::from(o.base) + idx as u64 * pagesize + in_area % pagesize,
                );
            }
            start_idx += o.mapsize as usize;
        }
        None
    }
}

/// Fixup records. A source-offset list (`src_flags & 0x20`) is stored after
/// the target tail: the target is variable-length and has to be parsed first.
const F_SOURCE_TYPE_MASK: u8 = 0xF;
const F_SOURCE_LIST: u8 = 0x20;
const F_TARGET_TYPE_MASK: u8 = 0x3;
const F_TARGET_OFF32: u8 = 0x10;
const F_TARGET_ADDITIVE: u8 = 0x4;
const F_TARGET_ADD32: u8 = 0x20;
const F_TARGET_ORD16: u8 = 0x40;
/// Import-by-ordinal: set means the import ordinal is a `u8`, clear means `u16`.
const F_TARGET_ORD8: u8 = 0x80;

/// Parsed LE image.
#[derive(Debug, Clone)]
pub struct LeImage {
    pub pages: LePages,
    /// Entry point as a linear address (DOS/4GW writes `e32_eip` absolute;
    /// if it falls below the start object's base we treat it as
    /// object-relative per the OS/2 convention).
    pub entry: u64,
    cpu: u16,
    /// Header-relative offset of the fixup page table (0 = none).
    fpagetab: u32,
    /// Header-relative offset of the fixup record table.
    frectab: u32,
    /// Number of pages (bounds the fixup page table).
    mpages: u32,
}

/// Quick detection: MZ stub with a locatable LE overlay header.
pub fn is_le(bytes: &[u8]) -> bool {
    find_le_header(bytes).is_some()
}

/// Locate the LE overlay header within a DOS/4GW image.
///
/// The classic DOS/4GW 1.x linker records the header offset in the MZ
/// `e_lfanew` slot (offset 0x3c). Later DOS/4GW 2.x builds (e.g. SimCity 2000's
/// extender) leave that slot stale/garbage and embed the overlay deeper in the
/// stub, so fall back to scanning for the first header that passes the same
/// field sanity checks parse() applies. The fast path is preserved intact.
pub fn find_le_header(bytes: &[u8]) -> Option<usize> {
    fn honest(off: usize, bytes: &[u8]) -> bool {
        if off + 0x84 > bytes.len() {
            return false;
        }
        let Ok(cpu) = u16_at(bytes, off + 0x08) else {
            return false;
        };
        let Ok(pagesize) = u32_at(bytes, off + 0x28) else {
            return false;
        };
        let Ok(startobj) = u32_at(bytes, off + 0x18) else {
            return false;
        };
        let Ok(objcnt) = u32_at(bytes, off + 0x44) else {
            return false;
        };
        let Ok(objtab) = u32_at(bytes, off + 0x40) else {
            return false;
        };
        cpu != 0
            && pagesize >= 0x100
            && pagesize <= 0x10000
            && startobj > 0
            && objcnt > 0
            && objcnt < 0x800
            && startobj <= objcnt
            && objtab > 0
            && objtab < bytes.len().try_into().unwrap()
    }
    if bytes.len() >= 2 && bytes[0] == b'M' && bytes[1] == b'Z' {
        // Fast path: classic e_lfanew slot pointing straight at the header.
        let Ok(le_off) = u32_at(bytes, 0x3c) else {
            return None;
        };
        let o = le_off as usize;
        if o + 2 <= bytes.len() && bytes[o] == b'L' && bytes[o + 1] == b'E' && honest(o, bytes) {
            return Some(o);
        }
        // DOS/4GW 2.x: stale e_lfanew, overlay buried in the stub. Scan.
        let limit = bytes.len();
        for i in 3..(limit - 2) {
            if bytes[i] == b'L' && bytes[i + 1] == b'E' && honest(i, bytes) {
                return Some(i);
            }
        }
    }
    None
}

impl LeImage {
    /// Parse an LE image from raw file bytes (including the DOS stub).
    pub fn parse(bytes: &[u8]) -> Result<LeImage> {
        if !is_le(bytes) {
            return Err(Error::Parse("le: not a linear executable".into()));
        }
        let found = find_le_header(bytes);
        if found.is_none() {
            return Err(Error::Parse("le: not a linear executable".into()));
        }
        let header_off = found.unwrap();
        let h = |off: usize| u32_at(bytes, header_off + off);
        let h16 = |off: usize| u16_at(bytes, header_off + off);

        let cpu = h16(0x08)?;
        let mpages = h(0x14)?;
        let startobj = h(0x18)?;
        let eip = h(0x1c)?;
        let pagesize = h(0x28)?;
        let objtab = h(0x40)? as usize;
        let objcnt = h(0x44)?;
        let objmap = h(0x48)? as usize;
        let fpagetab = h(0x68)?;
        let frectab = h(0x6c)?;
        let datapage = h(0x80)?;

        if pagesize == 0 || startobj == 0 || startobj > objcnt {
            return Err(Error::Parse("le: nonsensical header values".into()));
        }

        let mut objects = Vec::with_capacity(objcnt as usize);
        for i in 0..objcnt as usize {
            let o = objtab + i * 24; // O32_OBJ: 6 dwords (OS/2 exe386 layout)
            objects.push(LeObject {
                base: u32_at(bytes, header_off + o + 4)?,
                size: h(o)?,
                flags: u32_at(bytes, header_off + o + 8)?,
                pagemap: u32_at(bytes, header_off + o + 12)?,
                mapsize: u32_at(bytes, header_off + o + 16)?,
            });
        }

        let mut pages = Vec::with_capacity(mpages as usize);
        for i in 0..mpages as usize {
            // 4-byte page-map entries: low u16 = page type flags, high u16 =
            // 1-based page number (empirically confirmed; the OS/2 8-byte
            // o32_map variant does not match DOS/4GW files).
            let e = u32_at(bytes, header_off + objmap + i * 4)?;
            pages.push((e >> 16) as u16);
        }

        let start = &objects[startobj as usize - 1];
        let entry = if eip >= start.base {
            u64::from(eip) // DOS/4GW: absolute linear EIP
        } else {
            u64::from(start.base) + u64::from(eip) // OS/2: offset within object
        };

        Ok(LeImage {
            pages: LePages {
                header_off,
                pagesize,
                datapage,
                objects,
                pages,
            },
            entry,
            cpu,
            fpagetab,
            frectab,
            mpages,
        })
    }

    /// Apply internal fixups to a mutable copy of the file bytes.
    /// Source type 7 writes the target linear address, type 5 the
    /// object-relative offset, and type 8 a 32-bit displacement from the
    /// source slot. Other source types and non-internal targets are parsed
    /// and skipped. Returns the number of source sites written.
    pub fn apply_fixups(&self, bytes: &mut Vec<u8>) -> Result<usize> {
        if self.fpagetab == 0 || self.frectab == 0 {
            return Ok(0);
        }

        let pagesize = u64::from(self.pages.pagesize);
        let mut page_base = Vec::with_capacity(self.mpages as usize);
        let mut seen: u32 = 0;
        for o in &self.pages.objects {
            let start = o.pagemap.checked_sub(1).ok_or_else(|| {
                Error::Parse("le: object page map out of range".into())
            })?;
            let slot_end = start.checked_add(o.mapsize).ok_or_else(|| {
                Error::Parse("le: object page map out of range".into())
            })?;
            if slot_end as usize > self.pages.pages.len() {
                return Err(Error::Parse("le: object page map out of range".into()));
            }
            for idx in 0..o.mapsize {
                page_base.push(u64::from(o.base) + u64::from(idx) * pagesize);
            }
            seen = seen.checked_add(o.mapsize).ok_or_else(|| {
                Error::Parse("le: object mapsize overflow".into())
            })?;
        }
        if seen != self.mpages {
            return Err(Error::Parse(
                "le: object mapsize sum does not match page count".into(),
            ));
        }

        fn truncated() -> Error {
            Error::Parse("le: truncated fixup record".into())
        }
        fn take<'a>(bytes: &'a [u8], off: &mut usize, end: usize, n: usize) -> Result<&'a [u8]> {
            let next = off.checked_add(n).ok_or_else(truncated)?;
            if next > end || next > bytes.len() {
                return Err(truncated());
            }
            let slice = &bytes[*off..next];
            *off = next;
            Ok(slice)
        }
        fn take_u8(bytes: &[u8], off: &mut usize, end: usize) -> Result<u8> {
            Ok(take(bytes, off, end, 1)?[0])
        }
        fn take_u16(bytes: &[u8], off: &mut usize, end: usize) -> Result<u16> {
            let b = take(bytes, off, end, 2)?;
            Ok(u16::from_le_bytes([b[0], b[1]]))
        }
        fn take_i16(bytes: &[u8], off: &mut usize, end: usize) -> Result<i16> {
            Ok(take_u16(bytes, off, end)? as i16)
        }
        fn take_u32(bytes: &[u8], off: &mut usize, end: usize) -> Result<u32> {
            let b = take(bytes, off, end, 4)?;
            Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        }

        let mut applied = 0usize;
        let header = self.pages.header_off;
        for page_i in 0..self.mpages as usize {
            let tab = header + self.fpagetab as usize + page_i * 4;
            let beg = u32_at(bytes, tab)
                .map_err(|_| Error::Parse("le: truncated fixup page table".into()))?;
            let end = u32_at(bytes, tab + 4)
                .map_err(|_| Error::Parse("le: truncated fixup page table".into()))?;
            if end < beg {
                return Err(Error::Parse("le: fixup page range inverted".into()));
            }
            if end == beg {
                continue;
            }
            let rec_base = header + self.frectab as usize;
            let mut off = rec_base.checked_add(beg as usize).ok_or_else(truncated)?;
            let off_end = rec_base.checked_add(end as usize).ok_or_else(truncated)?;
            let vbase = page_base[page_i];

            while off < off_end {
                let src_flags = take_u8(bytes, &mut off, off_end)?;
                let trg_flags = take_u8(bytes, &mut off, off_end)?;
                let src_type = src_flags & F_SOURCE_TYPE_MASK;
                let trg_type = trg_flags & F_TARGET_TYPE_MASK;

                let list_count = if src_flags & F_SOURCE_LIST != 0 {
                    Some(take_u8(bytes, &mut off, off_end)?)
                } else {
                    None
                };
                let single_src = if list_count.is_none() {
                    take_i16(bytes, &mut off, off_end)?
                } else {
                    0
                };

                let mut off_field: u64 = 0;
                let mut ordinal: Option<u32> = None;
                match trg_type {
                    0 | 3 => {
                        let ord = if trg_flags & F_TARGET_ORD16 != 0 {
                            u32::from(take_u16(bytes, &mut off, off_end)?)
                        } else {
                            u32::from(take_u8(bytes, &mut off, off_end)?)
                        };
                        if trg_type == 0 {
                            ordinal = Some(ord);
                        }
                        // Selector fixups (source type 2) have no target offset.
                        if src_type != 2 {
                            off_field = if trg_flags & F_TARGET_OFF32 != 0 {
                                u64::from(take_u32(bytes, &mut off, off_end)?)
                            } else {
                                u64::from(take_u16(bytes, &mut off, off_end)?)
                            };
                        }
                    }
                    1 => {
                        if trg_flags & F_TARGET_ORD16 != 0 {
                            take_u16(bytes, &mut off, off_end)?;
                        } else {
                            take_u8(bytes, &mut off, off_end)?;
                        }
                        if trg_flags & F_TARGET_ORD8 != 0 {
                            take_u8(bytes, &mut off, off_end)?;
                        } else {
                            take_u16(bytes, &mut off, off_end)?;
                        }
                    }
                    _ => {
                        // Target type 2: import by name.
                        if trg_flags & F_TARGET_ORD16 != 0 {
                            take_u16(bytes, &mut off, off_end)?;
                        } else {
                            take_u8(bytes, &mut off, off_end)?;
                        }
                        if trg_flags & F_TARGET_OFF32 != 0 {
                            take_u32(bytes, &mut off, off_end)?;
                        } else {
                            take_u16(bytes, &mut off, off_end)?;
                        }
                    }
                }

                let add_field = if trg_flags & F_TARGET_ADDITIVE != 0 {
                    if trg_flags & F_TARGET_ADD32 != 0 {
                        u64::from(take_u32(bytes, &mut off, off_end)?)
                    } else {
                        u64::from(take_u16(bytes, &mut off, off_end)?)
                    }
                } else {
                    0
                };

                let src_offs = if let Some(count) = list_count {
                    let mut v = Vec::with_capacity(count as usize);
                    for _ in 0..count {
                        v.push(take_i16(bytes, &mut off, off_end)?);
                    }
                    v
                } else {
                    vec![single_src]
                };

                if trg_type != 0 {
                    continue;
                }
                let Some(ord) = ordinal else {
                    continue;
                };
                let Some(obj) = ord
                    .checked_sub(1)
                    .and_then(|i| self.pages.objects.get(i as usize))
                else {
                    continue;
                };

                let rel = off_field + add_field;
                let base = u64::from(obj.base);
                for src_off in src_offs {
                    // Offsets are page-relative. A negative or past-the-page
                    // value is not a site on this logical page.
                    if src_off < 0 || u64::from(src_off as u16) >= pagesize {
                        continue;
                    }
                    let src_vaddr = vbase + u64::from(src_off as u16);
                    match src_type {
                        7 => {
                            let value = (base.wrapping_add(rel) as u32).to_le_bytes();
                            if self.patch_site(bytes, src_vaddr, &value) {
                                applied += 1;
                            }
                        }
                        5 => {
                            let Ok(word) = u16::try_from(rel) else {
                                continue;
                            };
                            if self.patch_site(bytes, src_vaddr, &word.to_le_bytes()) {
                                applied += 1;
                            }
                        }
                        8 => {
                            let disp = base
                                .wrapping_add(rel)
                                .wrapping_sub(src_vaddr.wrapping_add(4));
                            let value = (disp as u32).to_le_bytes();
                            if self.patch_site(bytes, src_vaddr, &value) {
                                applied += 1;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(applied)
    }

    /// Store `value` at `src_vaddr`, one translated byte at a time.
    /// Returns false, writing nothing, if any byte is unmapped.
    fn patch_site(&self, bytes: &mut [u8], src_vaddr: u64, value: &[u8]) -> bool {
        let mut file_offs = Vec::with_capacity(value.len());
        for i in 0..value.len() {
            let Some(fo) = self.pages.translate(src_vaddr + i as u64) else {
                return false;
            };
            let fo = fo as usize;
            if fo >= bytes.len() {
                return false;
            }
            file_offs.push(fo);
        }
        for (i, fo) in file_offs.into_iter().enumerate() {
            bytes[fo] = value[i];
        }
        true
    }

    pub fn arch(&self) -> Arch {
        // e32_cpu: 1 = 80286, 2 = 80386, 3 = 80486 (all disassemble as x86).
        match self.cpu {
            1..=3 => Arch::X86,
            _ => Arch::Unknown,
        }
    }

    /// Objects as sections. LE objects carry no names, so they are named by
    /// access flags (`code` when executable, else `data`) plus ordinal.
    pub fn sections(&self) -> Vec<Section> {
        let pagesize = u64::from(self.pages.pagesize);
        self.pages
            .objects
            .iter()
            .enumerate()
            .map(|(i, o)| {
                let kind = if o.flags & 0x4 != 0 { "code" } else { "data" };
                // Offset of the object's first mapped page (approximate for
                // display; exact translation goes through the page map).
                let file_offset = if o.mapsize > 0 && (o.pagemap as usize) <= self.pages.pages.len()
                {
                    let page = u64::from(self.pages.pages[o.pagemap as usize - 1]);
                    self.pages.header_off as u64
                        + u64::from(self.pages.datapage)
                        + (page - 1) * pagesize
                } else {
                    0
                };
                Section {
                    name: format!("{kind}{i}"),
                    addr: u64::from(o.base),
                    size: u64::from(o.size),
                    file_offset,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal synthetic LE image: 1 object at base 0x400000 with a
    /// single 4096-byte page stored right after the header.
    fn synthetic() -> Vec<u8> {
        let mut b = vec![0u8; 0x240];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());

        let le = 0x40;
        b[le..le + 2].copy_from_slice(b"LE");
        b[le + 0x08..le + 0x0a].copy_from_slice(&2u16.to_le_bytes()); // cpu 386
        b[le + 0x14..le + 0x18].copy_from_slice(&1u32.to_le_bytes()); // mpages
        b[le + 0x18..le + 0x1c].copy_from_slice(&1u32.to_le_bytes()); // startobj
        b[le + 0x1c..le + 0x20].copy_from_slice(&5u32.to_le_bytes()); // eip (object-relative)
        b[le + 0x28..le + 0x2c].copy_from_slice(&4096u32.to_le_bytes()); // pagesize
        b[le + 0x40..le + 0x44].copy_from_slice(&0xC0u32.to_le_bytes()); // objtab
        b[le + 0x44..le + 0x48].copy_from_slice(&1u32.to_le_bytes()); // objcnt
        b[le + 0x48..le + 0x4c].copy_from_slice(&0xD8u32.to_le_bytes()); // objmap
        b[le + 0x80..le + 0x84].copy_from_slice(&0x100u32.to_le_bytes()); // datapage

        // object 0 at le+0xC0
        let o = le + 0xC0;
        b[o..o + 4].copy_from_slice(&16u32.to_le_bytes()); // size
        b[o + 4..o + 8].copy_from_slice(&0x400000u32.to_le_bytes()); // base
        b[o + 8..o + 12].copy_from_slice(&0x2045u32.to_le_bytes()); // flags (r+x)
        b[o + 12..o + 16].copy_from_slice(&1u32.to_le_bytes()); // pagemap
        b[o + 16..o + 20].copy_from_slice(&1u32.to_le_bytes()); // mapsize

        // page map at le+0xD8: page 1, flags 0
        b[le + 0xD8..le + 0xDC].copy_from_slice(&(1u32 << 16).to_le_bytes());

        // data page at le+0x100
        for (i, byte) in [0x55u8, 0x89, 0xe5, 0xc3].iter().enumerate() {
            b[le + 0x100 + i] = *byte;
        }
        b
    }

    #[test]
    fn parses_synthetic_le() {
        let b = synthetic();
        assert!(is_le(&b));
        let img = LeImage::parse(&b).unwrap();
        assert_eq!(img.arch(), Arch::X86);
        // eip 5 is below base 0x400000 -> treated as object-relative
        assert_eq!(img.entry, 0x400005);
        assert_eq!(img.pages.translate(0x400000), Some(0x140));
        assert_eq!(img.pages.translate(0x400004), Some(0x144));
        // beyond the object's single page -> unmapped
        assert_eq!(img.pages.translate(0x400010), None);
        // below the object base -> unmapped
        assert_eq!(img.pages.translate(0x1000), None);
        let secs = img.sections();
        assert_eq!(secs.len(), 1);
        assert_eq!(secs[0].name, "code0");
        assert_eq!(secs[0].addr, 0x400000);
        let mut owned = b.clone();
        assert_eq!(img.apply_fixups(&mut owned).unwrap(), 0);
    }

    /// Fixup page table + records in the gap between the page map and the data page.
    fn with_fixup_records(records: &[u8]) -> Vec<u8> {
        let mut b = synthetic();
        let le = 0x40usize;
        let fpagetab = 0xDCu32;
        let frectab = 0xE4u32;
        assert!(
            records.len() <= 0x100 - frectab as usize,
            "records would overlap the data page"
        );
        b[le + 0x68..le + 0x6c].copy_from_slice(&fpagetab.to_le_bytes());
        b[le + 0x6c..le + 0x70].copy_from_slice(&frectab.to_le_bytes());
        let pt = le + fpagetab as usize;
        b[pt..pt + 4].copy_from_slice(&0u32.to_le_bytes());
        b[pt + 4..pt + 8].copy_from_slice(&(records.len() as u32).to_le_bytes());
        let rt = le + frectab as usize;
        b[rt..rt + records.len()].copy_from_slice(records);
        b
    }

    fn dword_at(bytes: &[u8], vaddr: u64, img: &LeImage) -> u32 {
        let off = img.pages.translate(vaddr).unwrap() as usize;
        u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap())
    }

    #[test]
    fn internal_offset32_writes_base_plus_target() {
        // src type 7, target type 0, 8-bit ordinal, 16-bit target offset 0x20.
        let rec = [0x07, 0x00, 0x00, 0x00, 0x01, 0x20, 0x00];
        let mut b = with_fixup_records(&rec);
        let img = LeImage::parse(&b).unwrap();
        assert_eq!(img.apply_fixups(&mut b).unwrap(), 1);
        assert_eq!(dword_at(&b, 0x400000, &img), 0x400020);
    }

    #[test]
    fn source_list_offsets_follow_target_tail() {
        // List of two sources, then a separate type-7 record. Offsets sit
        // after the ordinal and target offset, so the second record stays intact.
        let rec = [
            0x27, 0x00, // type 7, source list
            0x02, // count
            0x01, // object 1
            0x20, 0x00, // target offset
            0x00, 0x00, // source +0
            0x04, 0x00, // source +4
            0x07, 0x00, // plain type 7
            0x08, 0x00, // source +8
            0x01, // object 1
            0x30, 0x00, // target offset
        ];
        let mut b = with_fixup_records(&rec);
        let img = LeImage::parse(&b).unwrap();
        assert_eq!(img.apply_fixups(&mut b).unwrap(), 3);
        assert_eq!(dword_at(&b, 0x400000, &img), 0x400020);
        assert_eq!(dword_at(&b, 0x400004, &img), 0x400020);
        assert_eq!(dword_at(&b, 0x400008, &img), 0x400030);
    }

    #[test]
    fn offset16_stores_object_relative_target() {
        let rec = [0x05, 0x00, 0x00, 0x00, 0x01, 0x20, 0x00];
        let mut b = with_fixup_records(&rec);
        let o = 0x40 + 0xC0;
        b[o + 4..o + 8].copy_from_slice(&0x400010u32.to_le_bytes());
        let img = LeImage::parse(&b).unwrap();
        assert_eq!(img.apply_fixups(&mut b).unwrap(), 1);
        let off = img.pages.translate(0x400010).unwrap() as usize;
        let word = u16::from_le_bytes([b[off], b[off + 1]]);
        assert_eq!(word, 0x0020);
    }

    #[test]
    fn import_by_ordinal_does_not_eat_following_internal() {
        // Type 1: 8-bit module, 16-bit import ordinal, no additive, no list.
        let rec = [
            0x07, 0x01, // type 7 source, import-by-ordinal
            0x00, 0x00, // source +0 (not written)
            0x05, // module ordinal
            0x34, 0x12, // import ordinal
            0x07, 0x00, // internal type 7
            0x04, 0x00, // source +4
            0x01, 0x20, 0x00, // object 1, target 0x20
        ];
        let mut b = with_fixup_records(&rec);
        let img = LeImage::parse(&b).unwrap();
        assert_eq!(img.apply_fixups(&mut b).unwrap(), 1);
        let untouched = img.pages.translate(0x400000).unwrap() as usize;
        assert_eq!(&b[untouched..untouched + 4], &[0x55, 0x89, 0xe5, 0xc3]);
        assert_eq!(dword_at(&b, 0x400004, &img), 0x400020);
    }

    #[test]
    fn mapsize_larger_than_page_table_errors() {
        let mut b = synthetic();
        let le = 0x40;
        let o = le + 0xC0;
        b[o + 16..o + 20].copy_from_slice(&4u32.to_le_bytes());
        b[le + 0x68..le + 0x6c].copy_from_slice(&1u32.to_le_bytes());
        b[le + 0x6c..le + 0x70].copy_from_slice(&1u32.to_le_bytes());
        let img = LeImage::parse(&b).unwrap();
        assert!(img.apply_fixups(&mut b).is_err());
    }
}
