# rea-rs iterations 3–6

Planning date: 26 Oct 2026. Branch inspected: `main` at `ef27480`. No code in this file.

This plan starts after iteration 2. It does not repeat iteration 1 (`3a413a8`..`ef27480`: field signatures and Param sequence numbers, WASM memory entries and the `--wat` listing, session binary mapping, nib values, rendition facts, width-based decompile types) or the six tasks in flight in the tasks-2 worktree:

| Iteration 2 | Commit subject already chosen | Clause it retires |
| --- | --- | --- |
| CLR Property/Event signatures and InterfaceImpl | `rea-rs: property and event signatures and interfaceimpl` | Property and Event signatures; `InterfaceImpl` skipped so MemberRef names stay aligned |
| Same-function unconditional flow in pseudo-C | `rea-rs: same-function flow in the pseudo-c window` | "no dataflow across basic blocks", for unconditional jumps inside one function only |
| ELF notes and section types | `rea-rs: elf notes and section types` | The note half of "Layout and note inspection inside the native file tools" |
| WAT for what the parser has already decoded | `rea-rs: full wat emission for decoded wasm` | "`--wat` … is not a full WAT writer", for decoded sections only |
| Evidence-format session export, CLI only | `rea-rs: evidence-format session export` | "Not an upstream Evidence record", via an export with explicit nulls |
| Mach-O entitlements and exec-segment facts | `rea-rs: entitlements and exec-segment facts` | Entitlements were unread on `rea macho`. `cms_verified` stays a digest window |

Start iteration 3 only after those six commits are on the branch. Each task is one offline commit, with fixture tests and the usual README plus `docs/rea-rs-review.html` closeout (newest commit in the `#now` line, a Done row, and the touched clause rewritten to match what the task actually reads). No new crates: sha384, binary plist, and the Swift subset are hand-rolled, same as `hash.rs` and `demangle.rs` today.

Clauses below are quoted from `docs/rea-rs-review.html` as it stood at `ef27480`. The command table, the CLR "Left unread" column, the "Out of this tree" paragraph, and the gaps table are the source. The archived evidence log still says signatures, IL, and WASM sections 9–11 are unread; the command table supersedes that log. Where a task only narrows a clause, the review text should name what landed and what still stops.

Within each iteration the last task is the one most likely to fail `cargo test --workspace --offline` and stop the loop.

## Iteration 3 — small facts already named in the tables

### 3.1 IL prefix opcodes the one-byte table drops

**Where:** `crates/rea-core/src/clr_sig.rs`

**Retires:** CLR MethodDef, Left unread: "An unknown opcode stops the listing."

`il_ops` already pushes `op-XX` and then breaks. This task handles the `0xFE` prefix for second bytes that take no further operand (`ceq`, `cgt`, `cgt.un`, `clt`, `clt.un`, `ckfinite`, `localloc`, `endfilter`). Those names join the listing. Any other unknown byte, including a `0xFE` second byte outside that set, still stops the listing. The 48-opcode cap stays. Token operands and `u16` immediates stay unread, so the walk does not invent their widths.

**Difficulty:** small

**Commit:** `rea-rs: il prefix opcodes in the bounded listing`

### 3.2 MSVC demangles become header declarations

**Where:** `crates/rea-core/src/headers.rs`

**Retires:** `rea headers` Stops before: "an MSVC `?` name."

`demangle::msvc` already returns strings such as `int foo(int)` and `void Foo::bar(int)`. `decl_from_demangled` drops them because the return type makes the left side fail the C-identifier check. Emit `extern int foo(int);` (and the qualified form) from that existing string. Do not parse the raw `?` mangling a second time. Imports stay omitted. Swift names stay omitted. A Rust path with no parentheses stays omitted. CLI only stays true until task 4.1.

**Difficulty:** small

**Commit:** `rea-rs: msvc names in the c header`

### 3.3 Name a host import when execute reaches one

**Where:** `crates/rea-core/src/wasm.rs`

**Retires:** `rea wasm` Stops before: "host imports."

`execute` today returns `wasm: imported function is not executed` when the export itself is an import, and `wasm: call target is missing` when a `call` index falls in the import range. Both errors should name the import that `inspect` already stored (`module.name`). The function is still not called. WASI stays out. Memory stays untouched. Fuel stays 4096 and the call depth stays 8. The review sentence keeps WASI and memory access as stops, and says a host import is named and not called.

**Difficulty:** small

**Commit:** `rea-rs: name the wasm host import`

### 3.4 UTF-16 runs beside the ASCII scan

**Where:** `crates/rea-core/src/strings.rs`, plus the CLI and MCP string listings that print `StringHit`

**Retires:** `rea strings` Stops before: "A string that is not a printable ASCII run."

Also report UTF-16LE and UTF-16BE runs whose code units sit in `0x20..=0x7E`, using the same minimum length as the ASCII scan. ASCII hits keep today's JSON shape. A UTF-16 hit adds an `encoding` field (`utf-16le` or `utf-16be`). A run that is not ASCII and not one of those UTF-16 runs stays unread. No UTF-8 outside ASCII, no UTF-32, no language guess. The measured `/bin/ls` string count in the review moves only if a real UTF-16 run shows up; update that row from the command.

**Difficulty:** small

**Commit:** `rea-rs: utf-16 runs beside ascii strings`

### 3.5 Digest window for the hash types the code directory already names

**Where:** `crates/rea-core/src/hash.rs`, `crates/rea-core/src/macho_meta.rs`

**Retires:** `rea macho` Stops before: "Hash types other than sha1 and sha256 leave `cms_verified` empty."

`hash_name` already returns `sha256-truncated` for type 3 and `sha384` for type 4. `cms_digest_present` only hashes types 1 and 2. `hash_slots` already reads `cd[36]` as the hash size. Compare type 3 as the leading `cd[36]` bytes of sha256, and type 4 as sha384 truncated to `cd[36]` bytes, with the same contiguous-window search used for sha256. `none` and `hash-{n}` still leave `cms_verified` empty. This stays a digest window. It is not an Apple trust decision. Hand-roll sha384 next to the existing sha256, and pin it with the same empty-string and `abc` test-vector style already in `hash.rs`.

**Difficulty:** medium

**Commit:** `rea-rs: sha384 and truncated digest windows`

### 3.6 Assembly and AssemblyRef version, culture, and public key

**Where:** `crates/rea-core/src/pe_meta.rs`

**Retires:** CLR Assembly / AssemblyRef, Left unread: "Version, culture, and the public-key blob." Also the gaps-table sentence "Other rows stay unread", for these three fields only.

The name columns are already stored. Add the four version numbers, the culture string, and the public-key (or public-key-token) blob on `Assembly` and `AssemblyRef`. A blob index of 0 stays empty. A blob that does not fit stays empty and does not fail the parse. Render the blob as a length plus hex capped at 32 bytes. Do not report the hash-algorithm id or the flags word. Do not check a strong name. Iteration 2's Property, Event, and InterfaceImpl work stays as it landed; this task does not reopen those rows.

**Difficulty:** medium

**Why last:** a wrong row width shifts every later CLR name. The tasks above do not touch `pe_meta.rs`.

**Commit:** `rea-rs: assembly version culture and public key`

## Iteration 4 — headers, plist, loader, then the CLR pointer tables

### 4.1 `rea headers` on the MCP surface

**Where:** `crates/rea-mcp/src/lib.rs`, and the tool-count sentences in `README.md` and the review

**Retires:** `rea headers` Stops before: "CLI only."

Add `rea_headers`. It takes a binary path, like `rea_info`, and returns the header text `headers::emit` already builds. The server then exposes eighteen tools. `rea_session` and `rea_bridge` still take no binary path. Plist, crash, and artifact stay CLI-only; their rows do not say "CLI only".

**Difficulty:** small

**Commit:** `rea-rs: headers on the mcp surface`

### 4.2 A Rust path with no parentheses is visible in the header

**Where:** `crates/rea-core/src/headers.rs`

**Retires:** `rea headers` Stops before: "a Rust path with no parentheses."

When the demangled form contains `::` and no `(`, emit a comment line with that path (`/* foo::bar */`). Do not invent a parameter list. Do not emit `extern void foo::bar();`. The raw name's existing C-identifier line may stay. Itanium and MSVC declarations from 3.2 stay as they are.

**Difficulty:** small

**Commit:** `rea-rs: rust paths in the c header`

### 4.3 The three plist keys from a binary plist

**Where:** `crates/rea-core/src/plist.rs` (the Mach-O embedded `__info_plist` path calls this same function)

**Retires:** `rea plist` Stops before: "A binary plist."

`identify` returns `None` for anything that is not XML. Also accept `bplist00` and read `CFBundleIdentifier`, `CFBundleName`, and `CFBundleVersion` when the object is an ASCII or UTF-16 string. A file with none of the keys still returns null and does not fail. XML plists stay on the current path. No NSKeyedArchiver, no dates, no UID graph, no general plist object model. The Mach-O reads cell that says "an embedded XML Info.plist" should drop the word XML once a binary payload in that section resolves.

**Difficulty:** medium

**Commit:** `rea-rs: binary plist identity keys`

### 4.4 WASM identity through the loader

**Where:** `crates/rea-core/src/loader.rs`, `crates/rea-core/src/lib.rs` (`Format`), `rea info` / `rea_info`

**Retires:** `rea wasm` Reads cell: "The loader still rejects WASM, so the command reads the file itself."

Recognize a WASM file before `goblin::peek` fails and let `rea info` report format `wasm` plus the counts `wasm::inspect` already computes (sections, defined functions, exports). `rea disasm`, `rea funcs`, `rea decompile`, and `rea xrefs` still error on that format. `rea wasm` remains the deep command and may keep reading the file itself. `--arch` still applies to Mach-O only. Linear memory is not mapped into a `Target`. WASI and execute-time memory access stay out.

**Difficulty:** medium

**Commit:** `rea-rs: wasm identity through the loader`

### 4.5 MemberRef parent index

**Where:** `crates/rea-core/src/pe_meta.rs`

**Retires:** CLR MemberRef, Left unread: "The parent index."

Iteration 2 retires the rest of that cell (`InterfaceImpl` skipped). Store the `MemberRefParent` coded index that the row walker already sizes (`member_parent_w`) as a table tag plus a row number. Resolve a parent to a TypeRef or TypeDef name when that row is already in the name lists. `ModuleRef`, `MethodDef`, and `TypeSpec` stay as `ModuleRef#N`, `MethodDef#N`, and `TypeSpec#N`. Do not decode a TypeSpec blob. A parent that does not fit leaves the field empty and does not fail the parse. Name alignment tests for `Write` / `Read` must still pass.

**Difficulty:** medium

**Commit:** `rea-rs: memberref parent index`

### 4.6 Apply FieldPtr, MethodPtr, and ParamPtr

**Where:** `crates/rea-core/src/pe_meta.rs`

**Retires:** "`FieldPtr` is skipped and not applied." "`MethodPtr` is skipped and not applied." "`ParamPtr` is skipped and not applied."

When the pointer table has one index per field, method, or param row, order the names through that index. A table that is shorter than the list, or an index that points past the list, leaves the existing order in place and does not fail the parse. The existing fixtures where a pointer row sits between tables and is skipped must gain a sibling fixture where the pointer is applied and the owned name moves. Do not decode Constant or CustomAttribute blobs. Iteration 2 may have stored counts for those; this task does not replace that with blob decoding. Do not change InterfaceImpl.

**Difficulty:** hard

**Why last:** this reorders names the alignment tests lock down. A bad index permutes `Fld` / `Run` / `a` / `b` and fails the CLR suite.

**Commit:** `rea-rs: apply the clr pointer tables`

## Iteration 5 — formats the tree names, then discovery and decompile

### 5.1 SQLite identity through the loader

**Where:** `crates/rea-core/src/loader.rs`, `crates/rea-core/src/lib.rs`, `rea info` / `rea_info`

**Retires:** `rea sqlite` Reads cell: "The loader still rejects a database."

Same shape as task 4.4. A file whose header `sqlite::header` accepts loads as format `sqlite` for `rea info`, with the application id and the `sqlite_schema` object count. Row reads, the WAL, and the caps (1024 rows, pages `1..=1048576`) stay on `rea sqlite`. Disassembly still errors. A missing table is still an error on the row command. `--arch` is still Mach-O only.

**Difficulty:** small

**Commit:** `rea-rs: sqlite identity through the loader`

### 5.2 ObjC class-name strings

**Where:** `crates/rea-core/src/macho_meta.rs` (surfaced on `rea macho` / `rea_macho`)

**Retires:** gaps cell "Enhanced native (overview, ObjC, Swift, value and UI trace)", whose rea-rs column is "local call graph on x86, x86_64, arm64, Thumb." This task covers the ObjC word only. There is no command-table Stops-before sentence that names ObjC.

List NUL-terminated C strings from Mach-O sections whose names contain `objc`, capped at 128, with a `... more` marker. A binary with no such section stores an empty list and does not fail the parse. Do not walk `class_ro_t`, method lists, or protocols. Do not demangle Swift.

**Speculative:** the review names ObjC as a gap area and does not name a section layout. A section that holds pointers rather than C strings yields an empty or useless list; if a fixture shows that, leave the gaps cell honest instead of parsing the pointer structure in this task.

**Difficulty:** medium

**Commit:** `rea-rs: objc class-name strings`

### 5.3 LE entry-bundle addresses

**Where:** `crates/rea-core/src/le.rs`

**Retires:** "Entry bundles and iterated pages are not handled" (overlap row and the "Out of this tree" paragraph), the entry-bundle half. The module comment says the same thing.

The walker already reads a fixed set of header fields (object table, page map, data page). Add the entry table beside that set, using the header fields that point at it. Report each entry's object index and offset. A bundle flag this task does not recognize is counted and skipped, and the review names that flag. Do not guess a second on-disk layout if the first fixture disagrees with the header; keep the clause in that case. Iterated pages stay unread until task 6.5. Do not seed `rea funcs` from these addresses in this task.

**Difficulty:** medium

**Commit:** `rea-rs: le entry bundle addresses`

### 5.4 A Swift mangling subset

**Where:** `crates/rea-core/src/demangle.rs`, and the Mach-O symbol path in `crates/rea-core/src/loader.rs` only if `$s` names do not already reach `demangle::any`

**Retires:** `rea symbols` Stops before: "Swift demangling." Also "Swift stays raw" on that row and in the "Out of this tree" paragraph, for this subset. A demangle failure still does not fail the listing.

After the existing one-underscore strip, a stored name starting with `$s` or `_$s` can demangle. Parse two length-prefixed identifiers (a decimal length, then that many bytes, the same shape as the Rust v0 ident parser). Render `module.name`. Bytes after the second identifier stay unread and do not reject the match, so a type suffix does not have to be decoded. The demangled text does not include that suffix. Punycode, a length that does not fit, and a first byte that is not a digit return `None`. The stored raw name stays. Objective-C thunks and generic signatures stay raw. Headers still omit Swift names until task 6.1.

**Difficulty:** medium

**Commit:** `rea-rs: a swift mangling subset`

### 5.5 A32 function seeds

**Where:** `crates/rea-core/src/analysis.rs`

**Retires:** "Out of this tree": "A32 function seeds".

`Arch::Arm` prologue scan is Thumb only (`push {r7, lr}`, bytes `80 b5`). The PC-relative xref pass already disassembles A32 in a second Capstone handle. Also seed 4-byte-aligned `push {r11, lr}` / `stmfd sp!, {..., lr}` words, and disassemble those bodies in ARM mode, ending at `bx lr`. Thumb seeds stay in Thumb mode. Do not switch mode in the middle of a section. The funcs row "A ground-truth procedure list. Counts are a heuristic." stays. Update the `/bin/ls` call-graph numbers only if they move; `/bin/ls` on this machine is arm64, so the fixture is synthetic.

**Difficulty:** medium

**Commit:** `rea-rs: a32 function seeds`

### 5.6 Short conditional flow in the pseudo-C window

**Where:** `crates/rea-core/src/decompile.rs`

**Retires:** the conditional half of `rea decompile` Stops before: "no dataflow across basic blocks". Iteration 2 retires the unconditional half and, by its own task text, leaves short conditional branches undone. Memory-object types, struct recovery, and cross-function dataflow stay unread (task 6.4 takes stack slots only).

After iteration 2's same-function unconditional walk, also follow one forward conditional (`jcc` on x86_64, `b.cond` on arm64) whose target is inside the same function and ahead of the branch. The 64-instruction cap and the depth cap of 8 stay. The visited-target set stays. A backward branch or a target outside the function is still a `goto` line and stops that path. Width types carry across the join only when every incoming path wrote the same type to the same register; otherwise the register becomes untyped at the join. An empty window is still `decompile: no instructions`.

**Difficulty:** hard

**Why last:** it changes the window shape the width-type tests lock down. A bad join rewrites `int v1` / `(void*)v1` fixtures from iteration 1.

**Commit:** `rea-rs: conditional flow in the pseudo-c window`

## Iteration 6 — the remaining hard clauses

### 6.1 Swift names in the header

**Where:** `crates/rea-core/src/headers.rs`

**Retires:** `rea headers` Stops before: "Swift names."

Depends on task 5.4. When a Swift demangle is present, emit the same comment form as task 4.2 (`/* module.name */`). Do not invent parameters, and do not emit a C declaration for a path that contains `.`. If the 5.4 subset returns `None` for every fixture, this task adds the comment path in code and leaves the review clause in place until a fixture name appears. Imports stay omitted.

**Difficulty:** small

**Commit:** `rea-rs: swift names in the c header`

### 6.2 Progress notifications when the client sends a token

**Where:** `crates/rea-mcp/src/lib.rs`

**Retires:** `rea mcp` Stops before: "Progress notifications."

The comparison table also says "Notifications are dropped." Incoming notifications (no `id`) stay dropped, so `notifications_are_silent` keeps passing. On `tools/call` for `rea_funcs`, `rea_call_graph`, and `rea_strings` with xrefs, if the request carries a progress token under `_meta`, emit at most four `notifications/progress` lines for that call (a start, and updates across the sweep) with `progress` and `total`. No token means no notification. Results stay text. The protocol version stays `2024-11-05`. Cancellation stays unimplemented. `rea_session` and `rea_bridge` still take no binary path.

**Difficulty:** medium

**Commit:** `rea-rs: mcp progress notifications`

### 6.3 Rendition payload prefix

**Where:** `crates/rea-core/src/artifact.rs`

**Retires:** `rea artifact` Stops before: "Pixel payloads stay compressed and undecoded." And "Out of this tree": "Undecoded asset-catalog pixel payloads." This task narrows both; it does not fully retire them.

`csi_line` already requires a 184-byte CSI header and reports name, dimensions, and the pixel-format string (`BGRA8`, `JPEG`, `SVG`, `DATA`, and the others in `pixel_format`). Also report, per rendition and under the existing 128 cap, the payload length and the first 16 bytes as hex. `SVG` text that is valid UTF-8 is included as text, capped at 256 bytes. No bitmap is expanded, no JPEG is decoded, and no file is written. "Magic alone reconstructs to nothing" stays.

**Speculative:** the review and the function comment document name, width, height, and pixel format. They do not say the payload begins at byte 184. If a fixture shows the pixels elsewhere, report only the block length minus the header and leave the bytes unread, and keep the clause.

**Difficulty:** medium

**Commit:** `rea-rs: rendition payload prefixes`

### 6.4 Stack-slot types in the pseudo-C window

**Where:** `crates/rea-core/src/decompile.rs`

**Retires:** "no memory-object or struct types", the memory-object half, on x86_64 and arm64 only. "Out of this tree" still stands for a full type-recovering decompiler. Struct recovery and cross-function dataflow stay unread.

Inside the window (including the flow from tasks in iteration 2 and 5.6), a store of a typed register to a stack slot (`[rbp±N]` / `[rsp±N]` on x86_64, `[sp, #N]` on arm64) and a later load from that same slot reuse the type. The synthetic local stays one local. A slot with two different types in the window becomes untyped. Heap addresses, struct fields, and cross-function stack layouts stay untyped. The 64-instruction cap stays.

**Difficulty:** hard

**Commit:** `rea-rs: stack-slot types in the pseudo-c window`

### 6.5 LE iterated pages

**Where:** `crates/rea-core/src/le.rs`

**Retires:** "iterated pages" in "Entry bundles and iterated pages are not handled", and the module comment that `translate` cannot expand iterated or compressed pages.

Page-map entries already split a low `u16` of flags from a high `u16` page number. Expand the iterated flag so `translate` returns the page bytes, with a fixture built the same way as the existing LE fixtures. Identity-mapped pages and internal fixups stay on their current path. Do not add a general decompressor for every flag value. If the first iterated record does not match the fixture, keep the clause and stop, as the loop's honest-limit rule requires.

**Difficulty:** hard

**Why last:** a wrong page-type check breaks `translate` for ordinary LE pages and fails the loader tests. Nothing in this iteration depends on it.

**Commit:** `rea-rs: le iterated pages`

## Parked / not planned

Standing exclusions from the repo owner. Each one is also named in the review, so they are not quietly dropped:

- **EVM, firmware, Flutter, packets, signals.** Gaps row "Go, WASM, EVM, SQLite, firmware, Flutter, packets, signals": "No WASI, no memory access, no EVM, firmware, Flutter, packets, or signals."
- **WASI, and WASM memory access in `--execute`.** `rea wasm` Stops before: "WASI, memory access at execute time". Task 3.3 names host imports and still does not call them. Fuel 4096 and depth 8 stay caps, not work items.
- **Apple trust decisions.** `rea macho` Stops before: "An Apple trust decision." "Out of this tree": "Apple trust evaluation of a code signature." Task 3.5 extends the digest window only. `cms_verified` stays that window.
- **Launching Hopper, Ghidra, IDA, JEB, or Frida; attaching; driving a browser; running adb.** `rea bridge` Stops before, the "Out of this tree" paragraph, and the gaps rows for the bridge (40), JavaScript / Electron / web / browser (32), Android / adb / apktool / JEB (35), and Frida (9). The tree already parses export lines and reports PATH presence.

Intentional limits the review states as the contract, not as unread bytes:

- **Imports in `rea headers`.** The landed roadmap item says "Imports are omitted." The Stops-before cell repeats it. Emitting imports would reverse that contract.
- **`rea info` and a second architecture's code.** The Stops-before cell points at `rea sections`, `rea disasm`, and `rea decompile`, which already take `--arch`. Info does not show code.
- **Overlays on `rea sections`.** "Overlays. Those are an offset and a size on `rea macho` and `rea pe`." They already have a home.
- **`rea disasm` stops before pseudo-C.** That listing is `rea decompile`.
- **A ground-truth procedure list.** "Counts are a heuristic." Task 5.5 adds A32 seeds and leaves the heuristic sentence.
- **A library that is not in the rpath or runpath directories** (`rea elf`, `rea macho`). A miss is the result. This Mac has no system ELF; `/bin/ls` is Mach-O.
- **SQLite caps and bad frames.** A missing table, a frame after a salt mismatch or a bad checksum, pages outside `1..=1048576`, the 1024-row cap, and limit 0. Overflow chains are already followed.
- **A Go pointer that leaves the file.** "Out of this tree", and `rea goinfo` Stops before: "Host pointers are not dereferenced." Splitting the inline module text into build settings is not a Stops-before clause.
- **Keeping a session's mapping between calls.** The review says the file on disk is the source of truth. Iteration 2's evidence export leaves live-mapping fields null on purpose.
- **Cancellation, and structured MCP content.** The comparison table says upstream results carry "Evidence, structured content, sessions, progress, and cancellation." Only "Progress notifications" is a Stops-before cell. Task 6.2 takes that cell. The other two words are not scheduled.
- **Value and UI trace** in the enhanced-native gaps cell. That is dynamic tracing. Task 5.2 takes only the ObjC word.
- **Struct recovery and cross-function dataflow.** The remainder of "A full type-recovering decompiler beyond the window-local width types" after tasks 5.6 and 6.4.
- **The rest of the upstream surface** (about 150 contracts). Named cousins in the overlap table — `binary_overview`, `inspect_macho`, `list_architectures`, `inspect_binary_layout`, `list_segments`, `list_names`, `search_procedures`, `list_strings`, `search_strings`, `procedure_assembly`, `inspect_native_instruction`, `read_function_instructions`, `list_procedures`, `analyze_function`, `get_call_graph`, `procedure_pseudo_code`, `batch_decompile`, `xrefs`, `procedure_references`, `find_xrefs_to_name`, `inspect_go_binary`, `inspect_wasm_artifact`, `open_binary`, `binary_session`, `get_evidence_bundle`, `inspect_native_load_image` — are not scheduled as compatibility shims. API compatibility is none.

Seen in the tree, not named by the current command table, CLR column, "Out of this tree" paragraph, or gaps table. Not scheduled, so a code comment is not promoted into a review clause:

- **Non-zero WASM element and data flags.** `wasm.rs` returns `wasm element flags are unread` and `wasm data flags are unread`. The review's current stop is "A bad element or data section does not fail the inspect."
- **Global valtypes, element offsets, and data offsets** named in the `wat` doc comment. Iteration 2's WAT task covers offsets for sections the parser has decoded, and leaves undecoded things out. The review's WASM stop list does not name globals.
- **A further PE resource directory under a language id** (`pe_meta.rs`). The command table already lists type, name, language, data-entry size, code page, and payload.
- **Constant and CustomAttribute blob bodies.** Iteration 2's task allows counts only. They sit under "Every other table" / "The row bodies," and overturning the count-only choice is not its own clause.
- **HashAlgId and Assembly flags.** Not in the Left unread cell. Task 3.6 skips them on purpose.
- **Crash reports that are not text** (for example `.ips`). `rea crash` Stops before: "A report with none of those lines. That prints null." No other crash shape is named.
- **Raising the 48-opcode IL cap** or the 64-instruction decompile cap. Both are stated bounds in the Reads cells.
