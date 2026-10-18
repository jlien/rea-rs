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

# C header of recovered names, plist and crash identity, artifact kind
rea headers /bin/ls
rea plist Info.plist
rea crash report.crash
rea artifact Example.app

# Functions, calls, and references
rea funcs /bin/ls
rea callgraph /bin/ls
rea xrefs /bin/ls 0x100003f80

# Format-specific facts
rea macho /bin/ls
rea wasm module.wasm
rea goinfo go-binary
rea pe program.exe
rea elf /path/to/elf
rea sqlite database.sqlite

# All commands emit JSON — pipe anywhere
rea strings /bin/ls | jq '.count'
```

## MCP server

`rea mcp` speaks JSON-RPC 2.0 over stdio and exposes fourteen tools:

- `rea_info` — format, architecture, entry point, section/symbol counts
- `rea_sections` — section names, virtual addresses, sizes, file offsets, and `rwx` permissions. Optional `arch` selects a Mach-O slice. The default is the host slice.
- `rea_symbols` — imports, exports, and locals, filterable by kind. Mach-O stab symbols are omitted. An Itanium C++ name is also returned demangled. The raw name stays.
- `rea_strings` — printable strings with file offsets; optional `xrefs` annotates code references
- `rea_disasm` — instruction-level disassembly at any virtual address. Optional `arch` selects a Mach-O slice. The default is the host slice.
- `rea_funcs` — function boundaries from the entry point, direct calls, and prologues
- `rea_xrefs` — code locations referencing an address (pointer-width absolutes, plus arm64 ADRP, x86_64 RIP-relative, 32-bit x86, and ARM/Thumb PC-relative loads)
- `rea_call_graph` — direct calls between discovered functions
- `rea_wasm` — WASM section ids, imports, exports, type count, defined function count, memory min/max, table min/max, data count, custom section names, and the start index. Function bodies, type signatures, element segments, data segments, and custom payloads are not decoded.
- `rea_go` — Go 1.18+ build info (version and module text)
- `rea_macho` — dylibs, UUID, build version, rpaths, code-directory identifier, hash type, team id, hash-slot digests, the CMS blob, an embedded Info.plist, an overlay, and fat architectures. Each architecture includes that slice's uuid, dylibs, rpaths, build version, code directory, CMS blob, plist, and overlay when the slice is present. A missing blob does not fail the parse. The signature is not verified.
- `rea_pe` — subsystem, image base, COFF timestamp, data directories, CLR runtime header, metadata version, stream directory, table row counts, Module/TypeRef/TypeDef names, Field and MethodDef names on each TypeDef, Param names on each method, MemberRef names, CodeView PDB path, root resource type ids, the name under each type, the language id under each name, the data-entry size and code page, the resource payload, and an overlay. A missing payload does not fail the parse. The timestamp is not a date.
- `rea_elf` — file type, machine, interpreter, needed libraries, soname, rpath, runpath, and GNU build-id. The paths are not searched.
- `rea_sqlite` — database header, including the application id, and `sqlite_schema` objects. No table rows and no WAL replay.

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
  the host-architecture slice before analysis. `rea sections` and
  `rea disasm` take `--arch` to read another slice. The default stays the host.
- **Uniform surface**: every format loads into the same `Target` struct, so
  tools behave identically across Mach-O, ELF, PE, and LE.
- **vaddr → file offset mapping** is built in (`Target::vaddr_to_offset`),
  so disassembly works on virtual addresses, not raw file offsets.
- The MCP server is implemented directly against the JSON-RPC 2.0 +
  newline-delimited stdio wire protocol — no SDK dependency.

## Roadmap

- [ ] .NET rows beyond Module, TypeRef, TypeDef, Field, MethodDef, Param, and MemberRef names, plus IL (`rea pe` reads the CLR header, stream directory, table row counts, those type names, each TypeDef's field and method names, each method's parameter names, and MemberRef names)
- [x] WASM module inspection — section ids, imports, exports, type count, defined function count, memory min/max, table min/max, data count, custom names, and the start index (`rea wasm`). No function-body decode, no type signatures, no element or data segments, no custom payloads, no WAT, and no execution
- [x] Function boundary detection and cross-reference resolution — Capstone sweep (entry, direct calls, prologues on x86, x86_64, arm64, and Thumb) plus pointer-width data xrefs and PC-relative loads (arm64 ADRP, x86_64 RIP-relative, 32-bit x86, ARM/Thumb), exposed as `rea funcs`, `rea xrefs`, `rea callgraph`, and the MCP tools
- [x] SQLite header, including the application id, and `sqlite_schema` objects (`rea sqlite`). No table-row reads and no WAL replay
- [x] Export as C/C++ headers from recovered definitions (`rea headers`). Itanium names become declarations. Other local and export names that are C identifiers become `extern void name();`. Imports are omitted.

## License

MIT — see [LICENSE](LICENSE).
