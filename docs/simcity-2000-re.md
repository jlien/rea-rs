# SimCity 2000 Special Edition (DOS) — Reverse Engineering Campaign

Clean-room study of the Maxis 1995 DOS Special Edition, acquired from
archive.org (`msdos_SimCity_2000_SE_1995`, MD5 `4a7634d6…` SHA1 `058af9bf…`
verified against the archive's published hashes). Install:
`~/Games/sc2k/`. Evidence files (written by the RE subagents, full hexdumps
and disassembly included):

- `~/Games/sc2k/RE/data-formats.md` — container formats, verified against bytes
- `~/Games/sc2k/RE/executable.md` — SC2K.EXE anatomy, vaddr-cited
- `~/Games/sc2k/RE/sc2000dat-files.tsv` — reconstructed 399-entry SC2000.DAT table

## Executive summary

SC2K.EXE is a DOS/4GW **2.x** LE image — the first real binary we've met whose
`e_lfanew` slot is stale garbage. That broke rea-rs's detection (misrouted to
PE) and forced the LE-header-scan fix (`find_le_header`), which now covers
both DOS/4GW 1.x (Warcraft) and 2.x (SimCity) families. The game itself is a
table-driven simulation: one ~80 KB monolithic sim function, resources in two
custom container formats (`.DAT`/`.URK`, same 16-byte directory entry), saves
in IFF `SCDH` chunks, VESA 640×480 + SB16 via config, Smacker cinematics
delegated to separate INTRO/WILLTV executables.

## Container formats (verified against bytes)

### SC2000.DAT — 399-entry resource pack (2,629,981 B)

- Directory: 16-byte entries — 12-byte NUL-padded uppercase name + u32 LE
  **absolute file offset** (not size). No count field.
- Directory length = first file's offset (`0x18F0` = 6,384) — that identity
  is the authoritative end-of-directory rule.
- Sizes are next-offset − this-offset; last file runs to EOF. All 399 files
  tile `0x18F0..EOF` contiguously with zero gaps (verified).
- Samples: `MINE.PAL` = 256×3 RGB palette; `NEWYRK12.FNT` = bitmap font;
  `531.VOC` = Creative Voice File header.

### .URK — Maxis resource archive (same 16-byte entry layout)

- `RESOURCE.URK`: 84 entries, directory spans `0..0x540` (= first entry's
  offset). Offsets need not be contiguous; blobs are inline.
- End sentinel `READONLY.XXX` (offset = filesize, size 0) in some archives.
- **Exception:** `TEMPSLAB.URK` is actually an IFF `FORM…SCDH MISC` chunk, not
  a URK archive.
- `.TIL` files in SCURKART are URK archives wrapping the standard tilesets
  (`LARGE/OTHER/SMALL .DAT/.HED`, `URKNAME.TXT`). Companion `.PCX` are
  standard 8-bit PCX.

### .SC2 (city save) / .SCN (scenario) — IFF SCDH

- `FORM` + **big-endian** u32 size + `SCDH` form type, then flat
  `4-char type + BE u32 size + data` chunks with no odd-padding.
- Chunks: `ALTM` (32,768 B terrain), `MISC` (RLE-ish stream starting
  `81 00 02 01 …`), `X*` tile maps, `CNAM` (32-B name + desc + date),
  `LTM/ZON/BLD` variants. Two save sub-variants (CNAM-first / CNAM-less).

### .SMK — Smacker v2 (`SMK2`)

104-byte header: signature/width/height/frames u32 LE, signed frame rate
(−6666 → 15.0 fps), flags, per-audio-track sizes/rates, trees sizes.
Cross-verified with ffprobe (320×140, 187 frames, pal8).

## Executable anatomy (vaddr-cited, see executable.md)

- **Format:** DOS/4GW 2.x LE, x86-32, entry `0x63678`, 4 objects:
  `code0` 636,220 B (vaddr `0x10000`, file `0x6503C`), `code1` 1 B stub,
  `data2` 126,208 B, `data3` 12,108 B. No symbols. **21,104 load-time
  fixups** — static file bytes are unrelocated, so raw-byte data-xref scans
  legitimately return 0; `strings --xrefs` (re-applies fixups) is the way.
- **1,528 functions discovered.** The two ~80 KB "monsters" (`0x8E2A4`,
  `0x8E510`) are one giant function spanning to `0xA19C5` — the table-driven
  city-simulation engine (`jmp cs:[esi+ebx]` dispatch, `0x7FFF` sentinels,
  object-graph traversal).
- **Entry/init:** LE entry `0x63678` inside function `0x630E1` — allocates a
  singleton at `0xBB34`, registers in a table at `0x7692`.
- **Resources:** `sc2000.dat` / `endof.dat` strings at data2 `0xC1E8C`;
  `large/small/other.dat`, `mine.pal`, `b%d.raw`, `cur.raw`, fonts,
  `*.sc2`, `.\scenario`, `.\sound\%s` — filenames in a resident string table
  at the code0 tail.
- **Hardware:** VESA VBE `4F02h` + INT 10h (`0x7E510`, `0x7E765` → thunk
  `0x7D50F`); VGA DAC via ports 3C7/3C8/3C9 (`0x881F6`, `0x8827A`); SB16
  port base read from `SC2000.CFG` (no hardcoded 220h); DOS/4GW INT 21h/33h
  install stubs at `0x4FB60`.

## Runtime & packaging

- Launcher: `~/Games/sc2k/sc2k` (dosbox-staging, `dosbox.conf`: svga_s3,
  16 MB, cycles 6000) — boots to VESA 101h 640×480 with SB16 A220/IRQ7/DMA1,
  verified stable.
- `SC2000.CFG` already carries the VESA + SB16 config the game reads.
- Self-contained HTML: `~/Games/sc2k/simcity2000.html` (13.4 MB) — DOS/ only
  zip (the `DATA/*.SMK` cinematics belong to INTRO.EXE/WILLTV.EXE; SC2K.EXE
  has a `NO_INTRO` path and never loads them). Browser-verified: extracts,
  launches, renders the game's 640×480 menu, zero console errors.

## Tooling delta (rea-rs)

- `find_le_header()` added (`le.rs`): fast path (e_lfanew → `"LE"` + sanity
  fields) preserved; on DOS/4GW 2.x images with stale e_lfanew, scans for the
  first header passing parse()'s own field checks. SC2K/INTRO/WILLTV now
  load; WAR.EXE unchanged; 31 core + MCP tests green.
- Known limitation recorded: standalone `rea xrefs` sees pre-fixup bytes —
  use `strings --xrefs` for data references until a post-fixup xref pass
  exists.
