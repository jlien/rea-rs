# Warcraft: Orcs & Humans (Demo) — Reverse Engineering Notes

Clean-room analysis of `WAR.EXE` (shareware demo, DOS/4GW LE) and
`DEMODATA/DATA.WAR` performed with rea-rs plus targeted Python cross-checks.
No original code or assets were copied; this documents format facts and
addresses discovered by inspection.

Samples analyzed (SHA-256 recorded at download time):
- `WAR.EXE` — 311 KB, LE executable, Watcom C/C++ 32-bit
- `DEMODATA/DATA.WAR` — 1.1 MB asset archive, 583 entries / 299 present blocks

## 1. Executable structure

- LE header at file offset `0x2a50` (found via DOS stub `e_lfanew`).
- Object 0 (`0x10000`): 201,303 B, 50 pages — code + read-only data.
- Object 1 (`0x50000`): 85,584 B, 8 pages — writable data (mostly BSS).
- Entry `0x23674` (absolute linear, DOS/4GW) → file `0x282c4`.
- Page map is identity (all pages present, type 0), so file offsets map
  linearly: `file = 0x14c50 + (vaddr - base_of_object_page_area)`.

### Using rea-rs

```
rea info WAR.EXE            # format le, entry 0x23674
rea disasm WAR.EXE --address 0x23674
rea funcs WAR.EXE           # 932 functions, 1317 call edges
rea strings WAR.EXE --xrefs # string → code reference annotation
rea xrefs WAR.EXE 0x505f6   # who references a data address
```

The `funcs` command combines three seeds: the entry point, a linear sweep
 harvesting every direct `call` target (skipdata mode recovers from embedded
data), and `push ebp; mov ebp, esp` prologues.

## 2. Key code & data landmarks (object-relative vaddrs)

| Address | Contents |
|---|---|
| `0x17488` | shared UI command callback (referenced by all command records) |
| `0x1a69f` | network/serial error handler ("Connection aborted.", "Packet Error:1") |
| `0x1c381` | sound-card detection ("Digitized sound card not found.") |
| `0x406c1` | unit training handler (refs "train cleric" + "train necrolyte") |
| `0x40da0–0x40f90` | per-unit descriptor table (see §3) |
| `0x51df0` | command record table (see §4) |
| `0x51e66` | unit name strings: Grunt, Footman, Peasant, Peon, Warlock, Conjurer… |
| `0x53b00` | cheat strings: "cheat enabled you wascaly wabbit", "cheat disabled" |
| `0x53b28` | debug format strings "attack:1", "bullet:6" |

## 3. Per-unit descriptor table (~`0x40da0`–`0x40f90`, code object)

Structure recovered by value archaeology (arrays appear exactly once each;
human/orc mirror units share values and sound callbacks):

- A u32 array of code addresses (`0x10000 + off`, e.g. `0xe0c8 → 0x1e0c8`) —
  per-unit sound/voice handlers, mirrored units share the same pointer.
- u16 HP array (mirror-paired): 60/60 Footman-Grunt, 40/40 Peasant-Peon,
  120/120 Catapult, 90/90 Knight-Raider, … matching WC1 published stats.
- u16 damage and gold-cost arrays: 300/250 … 400/400, 800/800, 700/700,
  900/900, 2500/2500, 5000/5000 (the 5000 pair is the demo's endpoint boss
  unit), plus build-time arrays.

**Access-path caveat (2026-10 re-scan):** scanning all 742 validated function
bodies for immediates or displacements landing in `0x3e000–0x42000` finds
**zero** data references into `0x40000+` (the only hits are branch targets
inside the last code functions, which end near `0x3f0b0`). Raw u32 searches
across the whole file likewise find no pointer to `0x40d00–0x40f90`. The
table is therefore reached either via a computed base+index from a pointer
stored elsewhere, or it is unreferenced demo cut-content. The array layout
above remains a value-archaeology inference, not a decoded accessor.

## 4. Command records (`0x51df0`, 14-byte stride)

`{u16 cmd_class, u16 index, u16 param, u32 callback (=0x17488), u16 pad}` —
the build/train menu entries, human/orc pairs `(1,1) (4,6) (5,5)`, each
pointing at the same dispatcher with an index into a string/behavior table.

**Callback 0x17488 decoded (2026-10):** it is a three-instruction no-op
thunk — `pop edx; pop ecx; ret` — i.e. "discard the two stacked arguments
and return". Command records that need no per-item action share it.

**Related 28-byte-stride records (obj1, ~`0x51b0c`):** dense record array
whose u16 view reads `{u16 type=7, u16 idA, u16 0, u16 0x7488, u16 1,
u16 0, u16 0, u16 type=7, u16 idB, u16 0x7488, u16 1, u16 0, u16 0}`.
The `0x17488` constant (and `0x7488` = its low half) recurs in every record;
`idA`/`idB` differ per record (0x3698/0x3724, 0x3990/0x3a1c, …). These look
like resource-reference pairs (id, id+0x10000 pattern in the u32 view) —
layout not fully pinned; listed for the next pass.

## 5. DATA.WAR archive format

- Header: `u32 magic 0x19`, `u16 count (583)`, `u16 type`, then `count` u32
  absolute file offsets (`0xFFFFFFFF` = absent; 299 present in the demo).
- Block header: `u32 (flags << 24) | uncompressed_length`. Flag `0x00` =
  stored; `0x20` = LZ77 (4096-byte window, per-8-token flag byte, match =
  u16 with `len-3` in the high nibble and offset in the low 12 bits).
- All 299 present blocks decompress cleanly with this decoder.

### Asset map (cross-checked against war1gus/war1tool mapping, not copied)

| Blocks | Content |
|---|---|
| 2 | MIDI music (`MIDFORM` IFF) |
| 217, 255, 260, 413, 414, 416, 418, 423, 424 | 768-byte VGA palettes (orc, human, title, outcome, victory/defeat, briefing) |
| 50, 56, 189–197, 376, 377, 396, 397 | level archives / tilesets (forest 190, swamp 193, dungeon 196) |
| 216–248 | UI images (logo, resource bars, panels, minimaps, title screen) |
| 347–358 | missile sprites (fireball, arrow, rain of fire, …) |
| 361–365 | portrait icons, menu buttons, icon borders |
| 406–420 | outcome/victory/defeat screens |
| 456–471 | victory scene art |
| 472–531 | sounds (VOC/W): chopping, sword attacks, acknowledgement/selected/annoyed voice lines |

### Image format (verified by decode)

UI image blocks: `u16 width, u16 height` then `width*height` palettized
pixels. Block 219 (orc top resource bar) = 240×12 with palette 217 —
decoded to PNG successfully (`/tmp/warblocks/orc_resource_bar.png`).

## 6. rea-rs additions made for this analysis

- `rea-core::analysis` — function discovery (entry + call-target sweep +
  prologue scan), 32-bit data xrefs, string xref annotation.
- `rea xrefs`, `rea funcs`, `rea strings --xrefs` CLI commands.
- Hex address parsing (`0x…`) for `xrefs` and `disasm`.
- **LE fixup engine** (`rea-core::le`): parses the fixup page table
  (LE header +`0x68`, header-relative) and record table (LE +`0x6C`);
  record = `[src_flags u8][trg_flags u8][src_off u16|list][ordinal][target
  off][addend]`. Source types 5/7 (16/32-bit offset) targeting internal
  objects are resolved and patched into a copy of the image at load time
  (constants cross-checked against rizin `le_specs.h`). Verified
  empirically on WAR.EXE: 8,457 fixups; the first record
  `07 00 eb 09 02 58 1b` writes obj2-base+0x1b58 at page1+0x9eb, and the
  patched bytes read back exactly that. `examples/le_fixup_stats.rs`
  prints the stats for any LE file.
- **Control-flow function bodies**: discovery now walks real control flow
  (visited-set BFS over disassembled instructions) instead of linear runs,
  so functions no longer bleed past forward jumps, jump tables, or padding.
  WAR.EXE: 742 functions / 2,386 call edges (was 932 over-long runs).

## 7. Icon/number strip blocks (218, 222, 223)

All three are 0x20-flagged (LZ77) 2,884-byte blocks. 222 and 223 share an
identical ~29-byte directory (rows of `f0 <u8>` pairs stepping by 0x12 —
a 0x12-byte row-stride table, 10 entries ≈ digit glyphs) and diverge in tile
data (2,815 of 2,884 bytes differ) — same UI number set, two variants
(human/orc). Not yet decoded to pixels; the directory/stride observation is
the entry point for a decoder.

## 8. Known gaps

- Stat-table field boundaries (where HP ends and damage starts) are
  inferred from value archaeology, not from a decoded accessor function —
  and see the access-path caveat in §3: no referencing code was found.
- The 28-byte-stride obj1 records (§4) are described but not decoded.
- Icon strip blocks 218/222/223 (§7) not decoded to pixels.
- Entry-point `e32_eip` handling: DOS/4GW writes it absolute but below the
  start-object base; rea-rs treats it as object-relative. Works for this
  binary; other LEs may differ.
