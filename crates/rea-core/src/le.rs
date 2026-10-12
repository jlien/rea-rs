//! Minimal Linear Executable (LE) support — the Watcom/DOS/4GW linear
//! executable format used by classic 1990s DOS games (e.g. the original
//! Warcraft demo). Layout was derived empirically from a DOS/4GW binary and
//! cross-checked against the OS/2 `exe386` structure definitions
//! (E32_* / O32_* fields).
//!
//! Scope: object table, page map, entry point, and page-granular
//! vaddr→file-offset translation (enough for info/sections/disasm). Fixups,
//! entry bundles, and iterated (compressed) pages are not yet handled.

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

/// Fixup (relocation) records. Format cross-checked against rizin's
/// `librz/bin/format/le` parser and empirically against WAR.EXE:
/// record = `[src_flags u8][trg_flags u8][src_off i16][ordinal][target……]`,
/// where source type 7 = 32-bit offset, target type 0 = internal.
const F_SOURCE_TYPE_MASK: u8 = 0xF;
const F_SOURCE_LIST: u8 = 0x20;
const F_TARGET_TYPE_MASK: u8 = 0x3;
const F_TARGET_OFF32: u8 = 0x10;
const F_TARGET_ADDITIVE: u8 = 0x4;
const F_TARGET_ADD32: u8 = 0x20;
const F_TARGET_CHAIN: u8 = 0x8;
const F_TARGET_ORD16: u8 = 0x40;

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

/// Quick detection: MZ stub with `e_lfanew` pointing at an "LE" magic.
pub fn is_le(bytes: &[u8]) -> bool {
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return false;
    }
    let Ok(le_off) = u32_at(bytes, 0x3c) else {
        return false;
    };
    let le_off = le_off as usize;
    le_off + 2 <= bytes.len() && &bytes[le_off..le_off + 2] == b"LE"
}

impl LeImage {
    /// Parse an LE image from raw file bytes (including the DOS stub).
    pub fn parse(bytes: &[u8]) -> Result<LeImage> {
        if !is_le(bytes) {
            return Err(Error::Parse("le: not a linear executable".into()));
        }
        let header_off = u32_at(bytes, 0x3c)? as usize;
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

    /// Apply internal fixups (relocations) to a mutable copy of the file
    /// bytes. For each 32-bit/16-bit-offset fixup targeting an internal
    /// object, the target linear address is written at the source location.
    /// Returns the number of fixups applied; chains, selectors, external
    /// imports and entry-point targets are counted but skipped.
    pub fn apply_fixups(&self, bytes: &mut Vec<u8>) -> Result<usize> {
        if self.fpagetab == 0 || self.frectab == 0 {
            return Ok(0);
        }
        let pagesize = self.pages.pagesize as u64;
        // Map page number -> starting vaddr (first page whose entry matches).
        let mut page_vaddr: Vec<u64> = vec![0; self.mpages as usize + 1];
        {
            let mut start_idx = 0usize;
            for o in &self.pages.objects {
                for idx in 0..o.mapsize as usize {
                    let page_no = self.pages.pages[start_idx + idx] as usize;
                    if page_no >= 1 && page_no <= self.mpages as usize && page_vaddr[page_no] == 0
                    {
                        page_vaddr[page_no] = u64::from(o.base) + idx as u64 * pagesize;
                    }
                }
                start_idx += o.mapsize as usize;
            }
        }

        let mut applied = 0usize;
        let mut skipped = 0usize;
        let read_u16 = |bytes: &[u8], off: usize| -> Option<u16> {
            let b = bytes.get(off..off + 2)?;
            Some(u16::from_le_bytes([b[0], b[1]]))
        };
        let read_u32 = |bytes: &[u8], off: usize| -> Option<u32> {
            let b = bytes.get(off..off + 4)?;
            Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        };

        for page_i in 0..self.mpages as usize {
            let start = self.pages.header_off
                + self.fpagetab as usize
                + page_i * 4; // fixup page table uses u32 entries (DOS/4GW)
            let Some(&beg) = u32_at(bytes, start).ok().as_ref() else {
                continue;
            };
            let Some(&end) = u32_at(bytes, start + 4).ok().as_ref() else {
                continue;
            };
            let (beg, end) = (beg as usize, end as usize);
            if end <= beg {
                continue;
            }
            let page_base = page_vaddr[page_i + 1]; // page numbers are 1-based
            let mut off = self.pages.header_off + self.frectab as usize + beg;
            let off_end = self.pages.header_off + self.frectab as usize + end;
            while off < off_end {
                let Some(&src_flags) = bytes.get(off) else {
                    break;
                };
                let Some(&trg_flags) = bytes.get(off + 1) else {
                    break;
                };
                off += 2;
                // Source list vs single source offset.
                let mut src_offs: Vec<i32> = Vec::new();
                if src_flags & F_SOURCE_LIST != 0 {
                    let Some(&count) = bytes.get(off) else {
                        break;
                    };
                    off += 1;
                    for _ in 0..count {
                        let Some(v) = read_u16(bytes, off) else {
                            break;
                        };
                        off += 2;
                        src_offs.push(v as i32);
                    }
                } else {
                    let Some(v) = read_u16(bytes, off) else {
                        break;
                    };
                    off += 2;
                    src_offs.push(v as i16 as i32);
                }
                // Target ordinal (object number for internal fixups).
                let ordinal: u32 = if trg_flags & F_TARGET_ORD16 != 0 {
                    let Some(v) = read_u16(bytes, off) else {
                        break;
                    };
                    off += 2;
                    u32::from(v)
                } else {
                    let Some(&v) = bytes.get(off) else {
                        break;
                    };
                    off += 1;
                    u32::from(v)
                };
                // Only internal targets can be resolved statically.
                let trg_type = trg_flags & F_TARGET_TYPE_MASK;
                let mut target: Option<u64> = None;
                if trg_type == 0 {
                    let obj_idx = ordinal.checked_sub(1).and_then(|i| {
                        self.pages.objects.get(i as usize).map(|o| u64::from(o.base))
                    });
                    if let Some(base) = obj_idx {
                        let tgt_off = if trg_flags & F_TARGET_OFF32 != 0 {
                            read_u32(bytes, off).map(u64::from)
                        } else {
                            read_u16(bytes, off).map(u64::from)
                        };
                        if let Some(t) = tgt_off {
                            off += if trg_flags & F_TARGET_OFF32 != 0 {
                                4
                            } else {
                                2
                            };
                            target = Some(base + t);
                        }
                    } else {
                        skipped += 1;
                        continue;
                    }
                    if trg_flags & F_TARGET_ADDITIVE != 0 {
                        let addend = if trg_flags & F_TARGET_ADD32 != 0 {
                            read_u32(bytes, off).map(u64::from)
                        } else {
                            read_u16(bytes, off).map(u64::from)
                        };
                        if let Some(a) = addend {
                            off += if trg_flags & F_TARGET_ADD32 != 0 {
                                4
                            } else {
                                2
                            };
                            target = Some(target.unwrap_or(0) + a);
                        }
                    }
                } else {
                    skipped += 1;
                    continue;
                }
                if trg_flags & F_TARGET_CHAIN != 0 {
                    skipped += 1; // chain fixups need page-data walking; rare
                    continue;
                }
                let Some(target) = target else {
                    continue;
                };
                let src_type = src_flags & F_SOURCE_TYPE_MASK;
                if src_type != 7 && src_type != 5 {
                    skipped += 1; // selectors / relative fixups: not applicable
                    continue;
                }
                for src_off in &src_offs {
                    if *src_off < 0 || *src_off as u64 >= pagesize {
                        continue;
                    }
                    let src_vaddr = page_base + *src_off as u64;
                    let Some(file_off) = self.pages.translate(src_vaddr) else {
                        continue;
                    };
                    let file_off = file_off as usize;
                    if src_type == 7 {
                        let Some(src) = bytes.get_mut(file_off..file_off + 4) else {
                            continue;
                        };
                        src.copy_from_slice(&(target as u32).to_le_bytes());
                    } else {
                        let Some(src) = bytes.get_mut(file_off..file_off + 2) else {
                            continue;
                        };
                        src.copy_from_slice(&(target as u16).to_le_bytes());
                    }
                    applied += 1;
                }
            }
        }
        Ok(applied)
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
    }
}
