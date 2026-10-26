# rea-rs

Reverse engineer anything — from the terminal, or through your agent.

A clean-room Rust implementation of the MCP reverse-engineering toolkit
concept (inspired by [morluto/rea](https://github.com/morluto/rea)): one
tool surface for inspecting native binaries across **Mach-O** (including
fat/universal binaries), **ELF**, **PE**, and **LE** (Watcom/DOS/4GW)
formats. All analysis runs
locally; nothing leaves your machine.

## Install

Requires Rust 1.75+.

```bash
cargo install --path crates/rea-cli
```

Or build from a checkout:

```bash
cargo build --release
```

## CLI

```bash
# Identify a binary
rea info /bin/ls

# List sections, symbols, strings
rea sections /bin/ls
rea sections fat-binary --arch x86_64
rea symbols /bin/ls exports
rea strings /bin/ls --min-length 6

# Disassemble from the entry point (or any address)
rea disasm /bin/ls --count 32
rea disasm /bin/ls --address 0x100003f80
rea disasm fat-binary --arch arm64 --address 0x1000 --count 1

# C header of recovered names, plist and crash identity, artifact kind, nib values, rendition dimensions and pixel formats
rea headers /bin/ls
rea plist Info.plist
rea plist binary-Info.plist  # a bplist00 binary plist reads the same three keys
rea crash report.crash
rea artifact Example.app

# Functions, calls, and references
rea funcs /bin/ls
rea callgraph /bin/ls
rea xrefs /bin/ls 0x100003f80

# Format-specific facts
rea macho /bin/ls
rea wasm module.wasm
rea wasm module.wasm --wat
rea wasm module.wasm --wat-full
rea wasm module.wasm --execute f --arg 1
rea goinfo go-binary
rea pe program.exe
rea elf /path/to/elf
rea sqlite database.sqlite --table notes --limit 32
rea sqlite database.sqlite --wal database.sqlite-wal

# Bounded pseudo-C, a session directory, and an export parser
rea decompile /bin/ls --count 16
rea session --dir /tmp/rea-session open /bin/ls
rea session --dir /tmp/rea-session record 1 --tool info "identity check"
rea session --dir /tmp/rea-session export 1 --format evidence
rea bridge status

# All commands emit JSON — pipe anywhere
rea strings /bin/ls | jq '.count'
```

## MCP server

`rea mcp` speaks JSON-RPC 2.0 over stdio and exposes eighteen tools:

- `rea_info` — format, architecture, entry point, section/symbol counts. A WASM file loads as format `wasm` and adds its section, defined-function, and export counts under `wasm`.
- `rea_sections` — section names, virtual addresses, sizes, file offsets, and `rwx` permissions. ELF sections also carry the `sh_type` name (`PROGBITS`, `NOBITS`, `DYNAMIC`, ...) and `SHF_` flags beyond the `rwx` bits. Optional `arch` selects a Mach-O slice. The default is the host slice.
- `rea_symbols` — imports, exports, and locals, filterable by kind. Mach-O stab symbols are omitted. An Itanium, Rust v0, or MSVC name is also returned demangled. The raw name stays. A clang `__Z` or `__R` name drops one ABI underscore first. Swift stays raw.
- `rea_strings` — printable ASCII strings with file offsets, plus UTF-16LE and UTF-16BE runs (an `encoding` field names those; runs are deduped across endianness); optional `xrefs` annotates code references
- `rea_disasm` — instruction-level disassembly at any virtual address. Optional `arch` selects a Mach-O slice. The default is the host slice.
- `rea_funcs` — function boundaries from the entry point, direct calls, and prologues
- `rea_xrefs` — code locations referencing an address (pointer-width absolutes, plus arm64 ADRP, x86_64 RIP-relative, 32-bit x86, and ARM/Thumb PC-relative loads)
- `rea_call_graph` — direct calls between discovered functions
- `rea_wasm` — WASM section ids, imports (including imported table and global details), exports, type signatures, defined function count, function-body opcodes with local groups, element and data segments with their offsets, a capped custom payload, memory min/max with the shared flag, imported memories with their limits, table min/max with the shared flag, imported tables with their limits, data count, custom section names, and the start index. The loader recognizes a WASM file (`rea_info` reports format `wasm` with the section, defined-function, and export counts), but `rea_disasm`, `rea_funcs`, `rea_decompile`, and `rea_xrefs` still error on the format, and this tool reads the file itself. Optional `execute` runs one export with an i32 interpreter; a host import is named (`module.name`) and not called. No WASI, and `execute` does not touch memory. A `wat` listing is CLI-only: it prints a WAT-flavored readability listing of what is decoded (sections in order, types, imports, memories, exports, functions by index with their opcodes). A `wat_full` mode is also CLI-only: it prints a full WAT emission of the same decoded content — types with full param and result lists, imports per kind with limits and mutability, bodies as `(func $i ...)` with local groups, mnemonic instructions, and `call $n` targets, and segments carrying their offsets. Both are writers only for what was decoded; undecoded forms stay unread.
- `rea_go` — Go 1.18+ inline build info, and pre-1.18 strings reached by file offsets. A null or out-of-range offset is an error. Host pointers are not dereferenced.
- `rea_macho` — dylibs, UUID, build version, rpaths, code-directory identifier, hash type, team id, hash-slot digests, the special-slot count, exec-segment offset, size, and flags, the CMS blob, `cms_verified` when the hash type is sha1, sha256, sha256-truncated, or sha384, entitlements keys with their immediate string or boolean values and the XML payload capped at 8 KiB (hex when not XML), the DER entitlements slot size, an embedded Info.plist, an overlay, fat architectures, and rpath file hits. Each architecture includes that slice's uuid, dylibs, rpaths, build version, code directory, CMS blob, entitlements, plist, and overlay when the slice is present. A missing blob does not fail the parse. `cms_verified` is a digest window, not an Apple trust decision.
- `rea_pe` — subsystem, image base, raw COFF timestamp and its UTC date, data directories, CLR runtime header, metadata version, stream directory, table row counts, Module/TypeRef/TypeDef names, Field and MethodDef names on each TypeDef, field and method signatures, a bounded IL listing that names the operand-free `0xFE` prefix opcodes (`ceq`, `cgt`, `cgt.un`, `clt`, `clt.un`, `localloc`, `endfilter`) and `ckfinite` at its one-byte opcode `0xC3`, Param names and sequence numbers on each method, the `FieldPtr`, `MethodPtr`, and `ParamPtr` rows reordering the names they point at when each table holds one in-range index per row, MemberRef names, signatures, and each entry's resolved parent (TypeRef/TypeDef names when that row is in the name lists; `ModuleRef#N`, `MethodDef#N`, `TypeSpec#N` for those placeholder tags with no table-length check; empty for an unknown tag or a parent row absent from the name lists), Assembly and AssemblyRef rows with version numbers, cultures, and public-key (or public-key-token) blobs rendered as length plus at most 32 bytes of hex, ModuleRef names, each TypeDef's resolved InterfaceImpl names, Property names with their decoded signatures and Event names with their resolved EventType name, CodeView PDB path, root resource type ids, the name under each type, the language id under each name, the data-entry size and code page, the resource payload, and an overlay. A missing payload does not fail the parse.
- `rea_elf` — file type, machine, interpreter, needed libraries, soname, rpath, runpath, GNU build-id, and rpath or runpath file hits. Notes from PT_NOTE segments and SHT_NOTE sections render as (owner, type id, descriptor hex capped at 128 bytes); known types carry names (`NT_GNU_BUILD_ID`, `NT_PRPSINFO`, ...), unknown stay `0x…`. GNU property notes decode `x86 feature 1` (IBT and SHSTK) and `x86 ISA needed` (baseline, v2, v3, v4) — not `x86 ISA used` or other property types, which stay hex. A descriptor over the 128-byte cap still decodes its leading records.
- `rea_sqlite` — database header, including the application id, and `sqlite_schema` objects. Optional `table` lists capped rows. Optional `wal` replays committed frames before the read.
- `rea_headers` — a C header of recovered local and export names. An Itanium or MSVC demangle becomes a declaration, keeping its return type. A demangled path with `::` but no parameter list (a Rust path) becomes a comment line (`/* foo::bar */`), never a declaration. Imports are omitted, as are Swift names.
- `rea_decompile` — bounded pseudo-C at a virtual address: assignments, calls, gotos, and returns, following unconditional jumps inside the enclosing function (bounds from function discovery, else the forward-jump walk) up to 64 instructions and 8 hops; a repeated target, an out-of-function branch, or an indirect jump renders as `goto`. Width-based types on x86_64 and arm64: loads typed by signedness and width, `lea` and `adrp`+`add` targets as `void*`, synthetic typed locals (`int v1; void* v2;`) above the body, casts where a typed value flows into a call argument or a return; a type crosses a followed join only when the skipped gap writes nothing to the register, else it drops. Still not a type-recovering decompiler: no memory-object or struct types, no cross-function dataflow. Optional `arch` selects a Mach-O slice.
- `rea_session` — JSON evidence session: open, record a tool and a summary, or diff two sessions. `open` maps a loadable binary once and records its identity summary in the file; a path that does not load still opens. `record` takes an optional `tool` that re-runs one named rea command against the session's binary and embeds the output, capped at 16 KiB. `dir` is required. `path` is not. A CLI-only `rea session export --format evidence` maps a session file to the upstream-morphic Evidence shape (per record: tool name, arguments echo, capped output, timestamp, session id); fields the native store does not capture — argument echoes, timestamps, the upstream session handle, a live mapping — are explicit nulls. Session export stays CLI-only; the MCP surface is otherwise at eighteen tools.
- `rea_bridge` — PATH presence and export parsers for Hopper, Ghidra, IDA, JEB, Frida, CDP, and adb. Does not launch those programs and does not attach to a process.

Register it with any MCP-capable agent, e.g. Claude Code:

```bash
claude mcp add rea -- rea mcp
```

Or in an MCP client config:

```json
{
  "mcpServers": {
    "rea": { "command": "rea", "args": ["mcp"] }
  }
}
```

## Workspace

| Crate       | Purpose                                          |
| ----------- | ------------------------------------------------ |
| `rea-core`  | Binary loading (goblin) + analysis + disassembly (capstone) |
| `rea-mcp`   | MCP stdio server (hand-rolled JSON-RPC, zero server deps)  |
| `rea-cli`   | The `rea` binary                                  |

## Design notes

- **Fat binaries are first-class**: universal Mach-O files are resolved to
  the host-architecture slice before analysis. `rea sections`,
  `rea disasm`, and `rea decompile` take `--arch` to read another slice. The default stays the host.
- **Uniform surface**: every format loads into the same `Target` struct, so
  tools behave identically across Mach-O, ELF, PE, and LE.
- **vaddr → file offset mapping** is built in (`Target::vaddr_to_offset`),
  so disassembly works on virtual addresses, not raw file offsets.
- The MCP server is implemented directly against the JSON-RPC 2.0 +
  newline-delimited stdio wire protocol — no SDK dependency.

## Roadmap

- [x] .NET rows beyond Module, TypeRef, TypeDef, Field, MethodDef, Param, and MemberRef names, plus IL (`rea pe` reads Assembly and AssemblyRef rows with version numbers, cultures, and public-key (or public-key-token) blobs, ModuleRef names, each TypeDef's resolved InterfaceImpl names, Property names with their decoded signatures and Event names with their resolved EventType name, field and method signatures, MemberRef signatures and each entry's resolved parent, Param sequence numbers, at most 48 IL opcodes, and the FieldPtr, MethodPtr, and ParamPtr rows reordering the names they point at when each table holds one in-range index per row). Other metadata rows stay unread.
- [x] WASM module inspection — section ids, imports (including imported table and global details), exports, type signatures, defined function count, memory min/max with the shared flag, imported memories with their limits, table min/max with the shared flag, imported tables with their limits, data count, custom names and a capped payload, function-body opcodes with local groups, and element and data segments with their offsets (`rea wasm`). `--execute` runs one export with an i32 interpreter; a host import is named (`module.name`) and not called, and it does not touch memory. `--wat` prints a WAT-flavored readability listing of what is decoded. `--wat-full` prints a full WAT emission of the same decoded content: types with full param and result lists, imports with kind details, segment offsets with escaped data bytes, and bodies as `(func $i ...)` with locals and mnemonic instructions; unknown opcodes become inline `(; opcode 0xNN ;)` comments. Still not a writer for undecoded things. No WASI and no memory access. The loader recognizes a WASM file and `rea info` reports the identity counts; `rea funcs`/`disasm`/`decompile`/`xrefs` still error, and `rea wasm` reads the file itself.
- [x] Function boundary detection and cross-reference resolution — Capstone sweep (entry, direct calls, prologues on x86, x86_64, arm64, and Thumb) plus pointer-width data xrefs and PC-relative loads (arm64 ADRP, x86_64 RIP-relative, 32-bit x86, ARM/Thumb), exposed as `rea funcs`, `rea xrefs`, `rea callgraph`, and the MCP tools
- [x] SQLite header, including the application id, `sqlite_schema` objects, and capped rows of one named table (`rea sqlite`). `--wal` replays checksummed frames through the last valid commit.
- [x] Export as C/C++ headers from recovered definitions (`rea headers`). Itanium and MSVC names become declarations. A demangled path with `::` but no parameter list becomes a comment line. Other local and export names that are C identifiers become `extern void name();`. Imports are omitted.

## License

MIT — see [LICENSE](LICENSE).
