# rea-rs iterations 7–11

Planning date: 27 Oct 2026. Branch inspected: `main` at `a98aff5` (merge of iteration 6). The review `#now` line names code commit `2d1dfab`. Test gate at that tree: `cargo test --workspace --offline` — rea-core 271 passed, rea-mcp 15 passed, rea-cli 4 passed. No code in this file.

`docs/iterations-3plus-plan.md` is closed. This plan does not repeat it (IL prefix opcodes, MSVC declarations, wasm host-import naming, UTF-16 runs, sha384 digest windows, assembly version and culture and public key, headers on MCP, Rust-path comments, binary plist identity keys, WASM and SQLite loader identity, MemberRef parents, CLR pointer tables, ObjC C strings, LE entry bundles, the Swift `module.name` subset, A32 function seeds, conditional pseudo-C flow, Swift header comments, MCP progress, rendition payload prefixes, stack-slot types, LE iterated pages, or the later slot-poison, hex-displacement, pre-index, and unscaled-store fixes).

Clauses below are quoted from `docs/rea-rs-review.html` as it stood at `a98aff5`. The command table, the CLR "Left unread" column, the "Out of this tree" paragraph, and the gaps table are the source. Where a task only narrows a clause, the review text should name what landed and what still stops. Docs must not claim behavior the code does not exhibit.

Each task is one offline commit. `cargo test --workspace --offline` must pass. Allowed external crates stay goblin, serde, serde_json, anyhow, thiserror, clap, and capstone. No new dependencies. Synthetic fixtures only. Arm64 instruction tests hand-encode bytes. Closeout updates `README.md` and `docs/rea-rs-review.html`: the newest code commit in the `#now` line, a Done row, and the touched clause rewritten to match the code. The banner's test counts move from 271 / 15 / 4 only as tests are added.

Within each iteration the last task is the one most likely to fail the test gate and stop the loop.

## Iteration 7 — small facts the tables already name

### 7.1 Name the x86 ISA-used GNU property

**Where:** `crates/rea-core/src/elf_meta.rs`

**Retires:** `rea elf` Reads: "not `x86 ISA used` or other property types, which stay hex." The used half only.

`parse_gnu_properties` already names type `0xc0008002` as `x86 ISA needed` with bits baseline, v2, v3, v4. Also name type `0xc0010002` as `x86 ISA used`, with those same four bit names. That constant is the current psABI value, the sibling of the needed type already in the function. The pre-correction assignment `0xc0000000` is the AArch64 feature type and must not be labeled x86 ISA used (task 10.1). A property type outside feature 1, ISA needed, and ISA used stays `0x…` with its data words in hex. A note whose bytes do not parse is still skipped. No library search is added.

**Difficulty:** small

**Commit:** `rea-rs: name the x86 isa-used gnu property`

### 7.2 Assembly hash id, flags word, and the AssemblyRef hash blob

**Where:** `crates/rea-core/src/pe_meta.rs`

**Retires:** CLR Assembly / AssemblyRef, Left unread: "The hash-algorithm id and the flags word. No strong-name check. On `AssemblyRef`, the `HashValue` blob."

The row widths already cover these fields (`32 => 16 + blob_w + str_w * 2`, `35 => 12 + blob_w * 2 + str_w * 2`). Store them. On `Assembly`, the leading `u32` is the hash-algorithm id and the `u32` at offset 12 is the flags word. On `AssemblyRef`, the `u32` at offset 8 is the flags word, and the blob index after the culture string is `HashValue`, rendered with the same length-plus-at-most-32-hex helper as the public-key blob. A blob index of 0, or a blob that does not fit, stays empty and does not fail the parse. Flags stay a raw integer. The hash-algorithm id stays a raw integer. No strong-name check. Do not change either row-width expression.

**Difficulty:** small

**Commit:** `rea-rs: assembly hash id flags and hashvalue`

### 7.3 A date value on the three plist keys

**Where:** `crates/rea-core/src/plist.rs`

**Retires:** `rea plist` Stops before: "NSKeyedArchiver, dates, and the UID graph stay undecoded." The dates word only. Also the Reads phrase "other object kinds (dates, UIDs, data, arrays, keyed archives) stay unread", the dates word only.

When a binary-plist value of `CFBundleIdentifier`, `CFBundleName`, or `CFBundleVersion` is marker byte `0x33`, store the field as the whole seconds of that Apple absolute time: an 8-byte big-endian IEEE-754 value, seconds since 2001-01-01. A truncated marker, a non-finite value, or a fraction that is not zero leaves that field unread and does not fail the parse. ASCII and UTF-16BE string values stay on the current path. A plist with none of the keys still returns null. XML plists are unchanged. NSKeyedArchiver, UIDs, data, arrays, and the UID graph stay undecoded. No general date object is added to the JSON shape; the three fields stay strings.

**Speculative:** the review names dates as unread and does not spell the 8-byte layout. If a fixture's `0x33` payload is not that absolute time, leave the field unread and keep the dates word in the clause.

**Difficulty:** small

**Commit:** `rea-rs: binary plist date values on the identity keys`

### 7.4 The existing Swift subset on ObjC section strings

**Where:** `crates/rea-core/src/macho_meta.rs`

**Retires:** gaps cell "Enhanced native (overview, ObjC, Swift, value and UI trace)", the clause "Swift names stay raw".

`objc_strings` already lists NUL-terminated C strings from sections whose names contain `objc`, capped at 128. When one of those strings is a name `demangle::swift` already accepts, store the `module.name` text beside the raw string. A name `swift` rejects stays raw, and a failure does not fail the parse. The cap and the `... more` marker stay. A pointer-only section still contributes nothing. A printable run with no terminating NUL stays unread.

The command-table Reads cell for `rea macho` currently omits the objc sentence the gaps cell and the README already state. The closeout puts that sentence back, including this demangle, so the table matches the code.

Does not walk `class_ro_t`, method lists, or protocols. Does not decode Swift types, generics, punycode, or labels (task 9.1 takes one type suffix on symbols, and does not change this string walk). Does not put the demangle into `rea headers`.

**Difficulty:** small

**Commit:** `rea-rs: swift module names on objc section strings`

### 7.5 UTF-32 runs beside the ASCII and UTF-16 scans

**Where:** `crates/rea-core/src/strings.rs`, plus the CLI and MCP string listings that print `StringHit`

**Retires:** `rea strings` Stops before: "A string that is neither a printable ASCII run nor a UTF-16 run: UTF-8 outside ASCII and UTF-32 stay unread." The UTF-32 half only.

Also report UTF-32LE and UTF-32BE runs whose code points sit in `0x20..=0x7E`, using the same minimum length as the ASCII scan, counted in code points. A UTF-32 hit adds `encoding` `utf-32le` or `utf-32be`. Where a UTF-32 run overlaps a longer ASCII or UTF-16 hit, keep the hit the current scan already keeps. ASCII and UTF-16 JSON stay as they are. The fixture `a_run_that_is_neither_ascii_nor_utf16_stays_unread` must grow a UTF-32 hit and still reject a non-ASCII UTF-8 run. UTF-8 outside ASCII stays unread until task 8.5. No language guess. Remeasure `rea strings /bin/ls` only if a real UTF-32 run shows up, and update that row from the command.

**Why last:** a UTF-32 window of `61 00 00 00` contains a UTF-16LE unit and an ASCII byte. A bad overlap rule rewrites the UTF-16 fixtures from iteration 3.

**Difficulty:** medium

**Commit:** `rea-rs: utf-32 runs beside ascii strings`

## Iteration 8 — listings that already have a parser

### 8.1 Operand-free IL opcodes the one-byte table still drops

**Where:** `crates/rea-core/src/clr_sig.rs`

**Retires:** CLR MethodDef, Left unread: "Any other unknown byte, including a `0xFE` second byte outside that set, stops the listing; token operands and `u16` immediates stay unread, so the walk does not invent their widths." The unknown-byte half, for this set only.

`opcode` already names a short operand-free set and stops on any other byte. Also name these operand-free opcodes, each pinned by a one-byte fixture: `stloc.2` (`0x0C`), `stloc.3` (`0x0D`), `dup` (`0x25`), `pop` (`0x26`), `neg` (`0x65`), `not` (`0x66`), `conv.i4` (`0x69`), `ldind.i4` (`0x4A`), `throw` (`0x7A`). An opcode outside the combined set still stops the listing at `op-XX`. The `0xFE` prefix set from iteration 3 is unchanged. Token operands and `u16` immediates stay unread, so this task invents no widths. The 48-opcode cap stays.

**Difficulty:** small

**Commit:** `rea-rs: operand-free il opcodes in the bounded listing`

### 8.2 Timestamps and argument text on a session record

**Where:** `crates/rea-core/src/session.rs`, and the CLI `rea session record` path in `crates/rea-cli/src/main.rs`

**Retires:** `rea session` Stops before: "Upstream's live session handle and memory mapping, and the timestamps and argument payloads the native store never recorded." The timestamps and argument-payloads half only.

`Record` gains an optional timestamp and an optional arguments string, both `#[serde(default)]` so a session file written before this task still loads. `record` stores the timestamp as unix seconds, decimal, from `SystemTime::now`. A test that needs a fixed value calls the helper with an explicit `u64` and does not read the clock. The CLI takes an optional arguments string and stores it as text, capped at 1024 bytes; omitted arguments stay null. `export_evidence` copies the stored timestamp and arguments. When either was not stored, that field stays null. `session_handle` and `live_mapping` stay null. Nothing is mapped between calls. The file on disk stays the source of truth. The export stays CLI-only.

**Difficulty:** medium

**Commit:** `rea-rs: session timestamps and argument text`

### 8.3 One level of nested entitlement values

**Where:** `crates/rea-core/src/macho_meta.rs`

**Retires:** `rea macho` Stops before: "Nested dict and array entitlement values are skipped, not listed."

`entitlement_entries` already keeps a top-level `<string>`, `<true/>`, or `<false/>`, and skips a nested `<dict>` or `<array>`. Also list one level inside that element. A nested dict contributes `parent.child` for an immediate string or boolean child. An array of strings contributes `parent[0]`, `parent[1]`, and so on, in order, capped at 32 nested entries with a `... more` marker. A deeper dict or array is skipped the way the top level skips today. A truncated payload keeps the keys that parsed. The DER slot stays a size only until task 9.4. `cms_verified` stays a digest window. This is not an Apple trust decision.

**Difficulty:** medium

**Commit:** `rea-rs: one level of nested entitlement values`

### 8.4 Six more i32 opcodes in the decoded map

**Where:** `crates/rea-core/src/wasm.rs`

**Retires:** `rea wasm` Stops before: "opcodes outside the decoded map stay comments or unread." For this set only. The same sentence also names non-`i32.const` segment offsets and global initializers; those stay until tasks 9.3 and 10.2.

`decode_ops` and `interpret` already execute `i32.const`, `i32.add`, `i32.sub`, `i32.mul`, `local.get`, `local.set`, `drop`, `call`, and `end`. Also decode and execute `i32.eqz` (`0x45`), `i32.eq` (`0x46`), `i32.ne` (`0x47`), `i32.and` (`0x71`), `i32.or` (`0x72`), and `i32.xor` (`0x73`). Comparisons push 0 or 1. Bitwise ops wrap. `--wat` and `--wat-full` print the mnemonics instead of `opcode 0xNN` / `(; opcode 0xNN ;)`. Any other opcode stays `op-NN` in the body and a comment in WAT, and execute still errors on it. Fuel stays 4096. Call depth stays 8. No memory opcode is added. WASI stays out. A host import is still named and not called.

**Difficulty:** medium

**Commit:** `rea-rs: i32 compare and bitwise opcodes`

### 8.5 UTF-8 runs outside ASCII

**Where:** `crates/rea-core/src/strings.rs`, plus the CLI and MCP string listings that print `StringHit`

**Retires:** `rea strings` Stops before: "UTF-8 outside ASCII and UTF-32 stay unread." The UTF-8 half. Task 7.5 has already taken UTF-32; if 7.5 did not land, this task still leaves UTF-32 unread.

Also report a valid UTF-8 run that contains at least one non-ASCII scalar, whose scalars are printable (not C0, not C1, not U+007F), using the same minimum length counted in scalars. The hit adds `encoding` `utf-8`. A run of only ASCII stays on the ASCII scan and does not gain `encoding`. Where the UTF-8 run overlaps an ASCII, UTF-16, or UTF-32 hit, keep the longer hit and, on a tie, the one the earlier scan already kept. An invalid UTF-8 sequence ends the run and stays unread. No language guess. No normalization. The fixture that rejects non-ASCII UTF-8 must grow a hit for a real multi-byte run and still reject a broken sequence. Remeasure `rea strings /bin/ls` only if a real UTF-8 run shows up.

**Why last:** the ASCII scanner and the UTF-16 overlap filter both walk the same bytes. A run that swallows an existing ASCII fixture changes the string-count tests and the `/bin/ls` row together.

**Difficulty:** medium

**Commit:** `rea-rs: utf-8 runs outside ascii`

## Iteration 9 — one Swift suffix, IL widths, wasm globals, then the scans that move fixtures

### 9.1 A trailing `yyF` on the Swift subset

**Where:** `crates/rea-core/src/demangle.rs`, `crates/rea-core/src/headers.rs`, and the Mach-O symbol assertion in `crates/rea-core/src/loader.rs`

**Retires:** `rea symbols` Stops before: "The rest of Swift: types, generic signatures, punycode identifiers, and labels." The types word, for this one suffix.

`swift` already returns `module.name` for `$s4main3fooyyF` and leaves the tail unread. When the unread tail is exactly `yyF`, the symbol demangle becomes `module.name()`. Any other tail, including the existing fixtures `$s4main3fooS2i_S2itSfE` and `$s4main3foo3barVyXEfU_`, still returns `module.name` and does not reject the match. Punycode, a bad length, and a leading `00` marker still return `None`.

`rea headers` keeps the comment `/* main.foo */`. The header prints the `module.name` from `demangle::swift`'s two-identifier result, and a Swift name does not go through `decl_from_demangled` even when the symbol text contains `()`. No parameter list is invented in the header. Imports stay omitted. ObjC section strings from task 7.4 stay `module.name` without the parentheses.

**Difficulty:** small

**Commit:** `rea-rs: a swift empty function suffix`

### 9.2 `u16` immediates on the `0xFE` local and argument opcodes

**Where:** `crates/rea-core/src/clr_sig.rs`

**Retires:** CLR MethodDef, Left unread: "token operands and `u16` immediates stay unread, so the walk does not invent their widths." The `u16` half only.

These `0xFE` second bytes take a little-endian `u16` and nothing else: `ldarg` (`0x09`), `ldarga` (`0x0A`), `starg` (`0x0B`), `ldloc` (`0x0C`), `ldloca` (`0x0D`), `stloc` (`0x0E`). Print `ldarg 3` and keep walking. A truncated immediate stops the listing the way a truncated `ldc.i4` already does. Any other `0xFE` second byte, including `ldftn` (`0x06`) whose operand is a token, still stops at `op-fe-NN`. One-byte token opcodes stay unread until task 10.3. The operand-free names from task 8.1 stay. The 48-opcode cap stays.

**Difficulty:** medium

**Commit:** `rea-rs: u16 immediates in the il listing`

### 9.3 Defined globals whose initializer is `i32.const`

**Where:** `crates/rea-core/src/wasm.rs`

**Retires:** `rea wasm` Stops before: "global initializers beyond the import valtype". For an `i32.const` initializer only.

Section id 6 is skipped today (`_ => {}`). Imported globals already store valtype and mutability. Also store each defined global's valtype, mutable flag, and initializer when the initializer expression is `i32.const N end` and the valtype is `i32`. `--wat-full` emits `(global $n (mut i32) (i32.const N))` or the const form without `mut`. A second global section is `duplicate wasm global section`, the same shape as a second table section. An initializer that is not `i32.const end`, or a valtype that is not `i32`, stores nothing for that global and does not fail the inspect. Execute does not read the global. Segment offsets stay `i32.const` until task 10.2. Fuel, depth, WASI, and memory access are unchanged.

**Difficulty:** medium

**Commit:** `rea-rs: wasm i32 global initializers`

### 9.4 Top-level DER entitlement keys

**Where:** `crates/rea-core/src/macho_meta.rs`

**Retires:** `rea macho` Stops before: "The DER entitlements payload stays unparsed: a size only."

The slot `0x10006` size is already stored. Also parse that payload when it is a DER sequence of pairs whose key is a UTF8String (tag `0x0C`) and whose value is a UTF8String or a BOOLEAN (tag `0x01`). Those pairs join the entitlement list as string or `true` / `false` values, beside the XML keys from task 8.3, capped at 32 new keys. A nested sequence or set is counted and skipped. A payload that does not start with a sequence, or a pair this task does not recognize, leaves the new keys empty, keeps the size, and does not fail the macho parse. The XML payload cap and the hex-when-not-XML path stay. Slot length accounting is unchanged, so a mid-index slot still does not swallow the next one. No signature is checked. `cms_verified` stays a digest window.

**Speculative:** the review says the payload stays unparsed and does not document the DER schema. If the first fixture's bytes are not this sequence-of-pairs shape, keep the size-only clause and stop.

**Difficulty:** medium

**Commit:** `rea-rs: top-level der entitlement keys`

### 9.5 The low 32 bits of a 64-bit pointer

**Where:** `crates/rea-core/src/analysis.rs`

**Retires:** `rea xrefs` Stops before: "The low 32 bits of a 64-bit pointer." The empty-range sentence stays: "A section whose clamped file range is empty contributes nothing."

`data_xrefs` matches an 8-byte little-endian address on a 64-bit target and ignores a 4-byte prefix. Also match a 4-byte little-endian value equal to the low 32 bits when `addr` fits in a `u32`, the match is 4-byte aligned, and those four bytes are not the leading half of an 8-byte hit already recorded at the same `from`. The 8-byte path is unchanged. The arm64, x86_64, 32-bit x86, and ARM/Thumb PC-relative paths are unchanged. This still over-matches raw bytes the way the 8-byte scan does. It is not a relocation pass. Remeasure `rea strings /bin/ls --xrefs --min-length 6` and `rea callgraph /bin/ls`, and update those rows only if the counts move. `/bin/ls` on this machine is arm64.

**Why last:** a 4-byte hit on every low address rewrites the xref fixtures and can move the measured `/bin/ls` string count (20) in the review.

**Difficulty:** medium

**Commit:** `rea-rs: low 32 bits of a 64-bit pointer`

## Iteration 10 — the remaining named unread forms, then LE page flags

### 10.1 The AArch64 feature-1 GNU property

**Where:** `crates/rea-core/src/elf_meta.rs`

**Retires:** `rea elf` Reads: "other property types, which stay hex." For this one type.

Task 7.1 has named `x86 ISA used`. Also name type `0xc0000000` as `aarch64 feature 1`, with bit 0 as `BTI` and bit 1 as `PAC`, joined the way `IBT and SHSTK` already is. Those are the current psABI values (`GNU_PROPERTY_AARCH64_FEATURE_1_AND`, `BTI`, `PAC`). Any other property type stays `0x…` with its data words in hex. A note whose bytes do not parse is still skipped.

**Difficulty:** small

**Commit:** `rea-rs: name the aarch64 feature-1 gnu property`

### 10.2 A `global.get` segment offset

**Where:** `crates/rea-core/src/wasm.rs`

**Retires:** `rea wasm` Stops before: "non-`i32.const` segment offsets". For `global.get` only.

`read_i32_offset` accepts `i32.const N end` and errors otherwise, and a bad element or data section is dropped without failing the inspect. Also accept `global.get X end` (`0x23`, a u32 leb index, `0x0b`). Store the offset as that global index and mark it so `--wat-full` prints `global.get N` instead of `i32.const`. An expression that is neither form still drops the section, and the inspect still succeeds. Element and data flags other than 0 still return `wasm element flags are unread` or `wasm data flags are unread`, and the section is still dropped. Execute does not evaluate the global. Memory stays untouched.

**Difficulty:** medium

**Commit:** `rea-rs: global.get segment offsets`

### 10.3 Token operands printed as hex

**Where:** `crates/rea-core/src/clr_sig.rs`

**Retires:** CLR MethodDef, Left unread: "token operands and `u16` immediates stay unread". Task 9.2 has taken the `u16` half. This task takes the token half for four opcodes, as hex only.

These one-byte opcodes take a 4-byte little-endian metadata token: `call` (`0x28`), `callvirt` (`0x6F`), `ldstr` (`0x72`), `newobj` (`0x73`). Print `call 0x06000001` and keep walking. A truncated token stops the listing. The token is not resolved to a name until task 11.2. Any other token opcode still stops at `op-XX`. The `0xFE` token opcodes, including `ldftn`, still stop. The 48-opcode cap stays.

**Difficulty:** medium

**Commit:** `rea-rs: il token operands as hex`

### 10.4 TypeSpec blobs the existing element parser accepts

**Where:** `crates/rea-core/src/pe_meta.rs`, using `sig_type` in `crates/rea-core/src/clr_sig.rs`

**Retires:** CLR InterfaceImpl, Left unread: "TypeSpec bodies are not decoded." And CLR MemberRef, Left unread: "The TypeSpec blob is not decoded."

TypeSpec rows are already sized (`27 => blob_w`) and contribute no body. Store one optional string per TypeSpec row, the text `sig_type` already returns for that blob (a primitive, `ptr`, `byref`, `szarray`, or `class` / `valuetype` with a coded index). A blob index of 0, or a blob `sig_type` rejects, stays empty and does not fail the parse. The recursion cap of 64 stays. The InterfaceImpl and MemberRef labels stay `typespec-N`. Do not replace those labels with the decoded body. Do not add a generic-instantiation tag. Do not change the `27 =>` width. Generic signatures stay unread.

**Difficulty:** medium

**Commit:** `rea-rs: typespec blobs the element parser accepts`

### 10.5 Zero-filled LE pages

**Where:** `crates/rea-core/src/le.rs`

**Retires:** "Out of this tree": "LE page-map flag values past identity and iterated (invalid, zero-filled) are refused, never expanded." The zero-filled half only.

The loader's own test names flag 3 as zero-filled (`a_zero_filled_page_flag_does_not_translate`): the page carries no file bytes, and `translate` returns `None`. Expand flag 3 the way iterated pages already expand, in the loader image before fixups, filling that page's range with zeros. The last page of an object fills only the object's remainder. `translate` then serves those zeros, and a fixup site on the page patches the zeros. Flag 0 and flag 1 stay on their current paths. Any other flag value still translates to none and is not expanded. Do not add a decompressor. Do not seed `rea funcs` from these pages. Update the flag-3 test to expect zeros.

**Why last:** `translate` is on the load path for every LE fixture. Treating flag 3 as a file offset again, or letting another flag value through, fails the loader tests.

**Difficulty:** hard

**Commit:** `rea-rs: le zero-filled pages`

## Iteration 11 — CLR row bodies the widths already skip, then cancellation

### 11.1 StandAloneSig blobs the method parser accepts

**Where:** `crates/rea-core/src/pe_meta.rs`

**Retires:** CLR "Every other table", Left unread: "The row bodies." And `rea pe` Stops before: "Metadata rows other than that table." For the StandAloneSig table only.

StandAloneSig is already sized (`17 => blob_w`) and stored as a count. Store one optional string per row, the text `method_sig` already returns for that blob. A blob index of 0, or a blob `method_sig` rejects, stays empty and does not fail the parse. Do not change the `17 =>` width. Constant, CustomAttribute, and every other unread table stay counts until the tasks below. No local-sig calling-convention is added beyond what `method_sig` already accepts.

**Difficulty:** small

**Commit:** `rea-rs: standalonesig blobs the method parser accepts`

### 11.2 Resolve a MethodDef or MemberRef token in the IL listing

**Where:** `crates/rea-core/src/clr_sig.rs` for the text, and `crates/rea-core/src/pe_meta.rs` where the listing is attached to a method

**Retires:** the remainder of "token operands … stay unread" that task 10.3 leaves as hex. Depends on task 10.3.

When a `call`, `callvirt`, or `newobj` token's high byte is MethodDef (`0x06`) or MemberRef (`0x0A`) and that 1-based row is already in the stored method or member-ref names, print the name beside the hex (`call 0x06000001 Run`). A row that is not in those lists stays the hex from task 10.3. `ldstr` (`0x70`, the user-string heap) stays hex. The user-string heap is not read. Any other token opcode still stops the listing. A missing name does not fail the parse. The 48-opcode cap stays.

**Difficulty:** medium

**Commit:** `rea-rs: resolve il method and memberref tokens`

### 11.3 Constant rows

**Where:** `crates/rea-core/src/pe_meta.rs`

**Retires:** "The row bodies." And "Metadata rows other than that table." For the Constant table only.

Constant is already sized (`11 => 2 + has_constant_w + blob_w`) and not stored. Store each row: the element-type byte as the name `sig_type` already uses for that tag (`int32`, `string`, and the rest of that match), the `HasConstant` parent as `Field#N`, `Param#N`, or `Property#N` (tag bits 0, 1, 2, the same coded width `has_constant_w` already computes), and the value blob as length plus at most 32 bytes of hex. A parent tag outside those three leaves the parent empty. A blob index of 0, or a blob that does not fit, stays empty and does not fail the parse. The constant is not evaluated. Do not change the `11 =>` width. CustomAttribute stays a count until task 11.4. The `Write` / `Read` name-alignment tests must still pass.

**Difficulty:** medium

**Commit:** `rea-rs: constant rows`

### 11.4 CustomAttribute parent, type, and value blob

**Where:** `crates/rea-core/src/pe_meta.rs`

**Retires:** "The row bodies." And "Metadata rows other than that table." For the CustomAttribute table only.

CustomAttribute is already sized (`12 => custom_parent_w + custom_type_w + blob_w`). Store each row. The parent tag uses the existing `custom_bits` order, printed as `MethodDef#N`, `Field#N`, and the other names in that array. The type tag uses the existing `custom_type_w` split: MethodDef or MemberRef, printed as `MethodDef#N` or `MemberRef#N`, and as the stored name when that row is already in the name lists. The value blob is length plus at most 32 bytes of hex. A tag this width does not name leaves that field empty. A blob that does not fit stays empty and does not fail the parse. The blob prolog and the named arguments stay unread. Do not change `custom_bits`, `custom_parent_w`, `custom_type_w`, or the `12 =>` width. Every table this task does not name stays a count.

**Difficulty:** hard

**Commit:** `rea-rs: customattribute parent type and value blob`

### 11.5 A cancellation line already buffered before the next progress stage

**Where:** `crates/rea-mcp/src/lib.rs`

**Retires:** `rea mcp` Stops before: "Cancellation is unimplemented."

The server reads one line, runs the call to completion, then reads the next line. Progress for `rea_funcs`, `rea_call_graph`, and `rea_strings` with xrefs is emitted at the start and between the load and the sweep. Between those stages, if the `BufRead` buffer already holds a full next line and that line is `notifications/cancelled` whose `params.requestId` equals the in-flight request id, stop the call and return text `cancelled`. The cancelled line is consumed. Any other buffered line stays for the next read, after the result. An empty buffer does not block and does not cancel. A cancellation with no matching id is unanswered, the same as any other notification. No token and no xrefs still mean no progress. Results stay text. The protocol stays `2024-11-05`. `rea_session` and `rea_bridge` still take no binary path. `notifications_are_silent` keeps passing for a notification that is not a matching cancellation.

A cancel that is not yet buffered is still unseen. This task does not add a thread, a non-blocking file descriptor, or a second read loop.

**Why last:** every MCP test enters `serve_internal`. A peek that consumes the next request, or that answers a notification, fails the fifteen-test MCP suite and the progress tests from iteration 6.

**Difficulty:** hard

**Commit:** `rea-rs: mcp cancellation when the line is already buffered`

## Parked / not planned

Standing exclusions from the repo owner. Each one is also named in the review:

- **EVM, firmware, Flutter, packets, signals.** Gaps row "Go, WASM, EVM, SQLite, firmware, Flutter, packets, signals": "No WASI, no memory access, no EVM, firmware, Flutter, packets, or signals."
- **WASI, and WASM memory access at execute time.** `rea wasm` Stops before: "WASI and memory access at execute time." Task 8.4 adds i32 compare and bitwise opcodes and does not add a memory opcode. Fuel 4096 and depth 8 stay caps.
- **Calling a host import.** "Out of this tree": "calling a host import (one is named, not called)."
- **Apple trust decisions.** `rea macho` Stops before: "An Apple trust decision." "Out of this tree": "Apple trust evaluation of a code signature." Tasks 8.3 and 9.4 read entitlement text. `cms_verified` stays a digest window.
- **Launching Hopper, Ghidra, IDA, JEB, or Frida; attaching; driving a browser; running adb.** `rea bridge` Stops before: "Launching those programs, attaching to a process, driving a browser, or running adb." The same limit is the "Out of this tree" paragraph and the gaps rows for the bridge (40), JavaScript / Electron / web / browser (32), Android / adb / apktool / JEB (35), and Frida (9).
- **Struct-type recovery and cross-function dataflow.** `rea decompile` Stops before: "A full type-recovering decompiler: no struct types, and no cross-function dataflow." Heap addresses and cross-function stack layouts are the rest of that same sentence ("Heap addresses and cross-function stack layouts keep no types."). A `(base, displacement)` heap slot is the next step of that decompiler, so it is not scheduled.
- **`rea funcs` seeding.** The LE review says entry addresses "are not seeded into `rea funcs`." Task 10.5 does not seed from zero-filled pages either. The funcs stop "A ground-truth procedure list. Counts are a heuristic." stays the contract.
- **Swift demangles in headers.** Task 9.1 may show `module.name()` on `rea symbols` and keeps the header comment at `/* module.name */`. No Swift declaration is added.
- **Objective-C class-metadata walking.** The gaps cell says "`class_ro_t`, method lists, and protocols stay unwalked." Task 7.4 demangles strings the walk already collects.
- **`--arch` beyond Mach-O slices.** `rea info` Stops before: "A second architecture's code. `rea sections`, `rea disasm`, and `rea decompile` take `--arch` for that slice." WASM and sqlite still reject those commands. Info does not grow a second slice.

Intentional limits the review states as the contract:

- **Imports in `rea headers`.** Stops before: "Imports."
- **Overlays on `rea sections`.** "Overlays. Those are an offset and a size on `rea macho` and `rea pe`."
- **`rea disasm` stops before pseudo-C.** "Pseudo-C. That listing is `rea decompile`."
- **A library that is not in the rpath or runpath directories** (`rea elf`, `rea macho`). A miss is the result. This Mac has no system ELF. `/bin/ls` is Mach-O.
- **SQLite caps and bad frames.** A missing table, a frame after a salt mismatch or a bad checksum, pages outside `1..=1048576`, the 1024-row cap, and limit 0.
- **A Go pointer that leaves the file.** "Out of this tree", and `rea goinfo` Stops before: "Host pointers are not dereferenced."
- **A live session handle and a mapping kept between calls.** Task 8.2 stores a timestamp and caller-supplied argument text. `session_handle` and `live_mapping` stay null on purpose.
- **Structured MCP content.** The comparison table says upstream results carry "Evidence, structured content, sessions, progress, and cancellation." Progress is landed. Task 11.5 takes cancellation. Structured content is not its own Stops-before cell.
- **Value and UI trace** in the enhanced-native gaps cell. That is dynamic tracing. Task 7.4 takes only the "Swift names stay raw" words.
- **Raising the 48-opcode IL cap, the 64-instruction decompile cap, the 64-op WASM body cap, or fuel 4096.** Those are stated bounds in the Reads cells.
- **The rest of the upstream surface** (about 150 contracts). Named cousins in the overlap table — `binary_overview`, `inspect_macho`, `list_architectures`, `inspect_binary_layout`, `list_segments`, `list_names`, `search_procedures`, `list_strings`, `search_strings`, `procedure_assembly`, `inspect_native_instruction`, `read_function_instructions`, `list_procedures`, `analyze_function`, `get_call_graph`, `procedure_pseudo_code`, `batch_decompile`, `xrefs`, `procedure_references`, `find_xrefs_to_name`, `inspect_go_binary`, `inspect_wasm_artifact`, `open_binary`, `binary_session`, `get_evidence_bundle`, `inspect_native_load_image` — are not scheduled as compatibility shims. API compatibility is none.

Considered and rejected:

- **Punycode, generic signatures, and Swift labels.** `rea symbols` Stops before names them beside types. Task 9.1 takes only a trailing `yyF`. The generic fixture `S2i_S2itSfE` must stay `module.name`. A punycode decoder or a label list is a second parser.
- **More Swift builtin suffixes (`ySiF` and the rest).** Only `yyF` is in the tree today. Inventing the other letters would claim a mangling the fixtures do not pin.
- **JPEG and bitmap expansion.** `rea artifact` Stops before: "No bitmap is expanded and no JPEG is decoded." The landed prefix task reports length, 16 hex bytes, and SVG text. The CSI fixture's payload is tag-length-value metadata, so a JPEG decoder at byte 184 would invent a layout. "Magic alone reconstructs to nothing" stays.
- **NSKeyedArchiver, UIDs, data, and arrays in plists.** Task 7.3 takes dates on the three keys. The rest of that stop stays.
- **Non-zero WASM element and data flags.** `wasm.rs` still returns `wasm element flags are unread` and `wasm data flags are unread`. The review's stop for a bad section is "A bad element or data section does not fail the inspect." Task 10.2 accepts one more offset expression and leaves the flag errors in place.
- **WASM `if` / `else` / `br`, division, and shifts.** Task 8.4's six opcodes do not trap and do not branch. Division needs trap rules the i32 interpreter does not have.
- **Defined globals whose initializer is not `i32.const`, and valtypes other than i32.** Task 9.3 leaves those unread on purpose.
- **Resolving `ldstr` and the user-string heap.** Task 11.2 keeps `0x70` tokens as hex. The heap is not a stored stream.
- **CustomAttribute named arguments, and a strong-name check.** Task 11.4 stores the value blob as length and hex. The Assembly left-unread sentence still says "No strong-name check" after task 7.2 stores the raw id and flags.
- **Invalid LE page flags, and any flag other than 0, 1, and 3.** Task 10.5 fills flag 3 with zeros. The review's "invalid" half stays refused.
- **A32 as a `rea disasm` mode.** The disasm Reads cell lists x86, x86_64, Thumb, and arm64. The Stops-before cell does not name A32. Funcs already seeds A32 bodies. There is no clause to retire.
- **An unterminated ObjC run.** A Done row says "A printable run with no terminating NUL stays unread." That sentence is not in the current command table or the gaps cell. Task 7.4 leaves it unread.
- **A further PE resource directory under a language id.** `pe_meta.rs` says so in a comment. The command table already lists type, name, language, data-entry size, code page, and payload.
- **Crash reports that are not text.** `rea crash` Stops before: "A report with none of those lines. That prints null." No other crash shape is named.
- **Plist, crash, and artifact on the MCP surface.** Their rows do not say "CLI only".
- **Threads, or a non-blocking read, for cancellation.** Task 11.5 only honors a `notifications/cancelled` line that is already in the buffer.
