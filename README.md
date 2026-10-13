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
rea symbols /bin/ls exports
rea strings /bin/ls --min-length 6

# Disassemble from the entry point (or any address)
rea disasm /bin/ls --count 32
rea disasm /bin/ls --address 0x100003f80

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
- `rea_sections` — section names, virtual addresses, sizes, file offsets, and `rwx` permissions
- `rea_symbols` — imports, exports, and locals, filterable by kind
- `rea_strings` — printable strings with file offsets; optional `xrefs` annotates code references
- `rea_disasm` — instruction-level disassembly at any virtual address
- `rea_funcs` — function boundaries from the entry point, direct calls, and prologues
- `rea_xrefs` — code locations referencing an address (pointer-width absolutes, plus PC-relative loads in text)
- `rea_call_graph` — direct calls between discovered functions
- `rea_wasm` — WASM section ids, imports, and exports
- `rea_go` — Go 1.18+ build info (version and module text)
- `rea_macho` — dylibs, UUID, build version, code signature, and fat architectures
- `rea_pe` — data directories, CLR runtime header, metadata version, stream directory, CodeView PDB path, root resource type ids
- `rea_elf` — interpreter, needed libraries, soname, and GNU build-id
- `rea_sqlite` — database header and `sqlite_schema` objects. No table rows and no WAL replay.

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
  the host-architecture slice before analysis.
- **Uniform surface**: every format loads into the same `Target` struct, so
  tools behave identically across Mach-O, ELF, PE, and LE.
- **vaddr → file offset mapping** is built in (`Target::vaddr_to_offset`),
  so disassembly works on virtual addresses, not raw file offsets.
- The MCP server is implemented directly against the JSON-RPC 2.0 +
  newline-delimited stdio wire protocol — no SDK dependency.

## Roadmap

- [ ] .NET metadata tables and IL (`rea pe` reads the CLR header, the BSJB version, and stream names, offsets, and sizes)
- [x] WASM module inspection — section ids, imports, and exports (`rea wasm`). No decode to WAT and no execution
- [x] Function boundary detection and cross-reference resolution — Capstone sweep (entry, direct calls, prologues on x86, x86_64, arm64, and Thumb) plus pointer-width data xrefs, exposed as `rea funcs`, `rea xrefs`, `rea callgraph`, and the MCP tools
- [x] SQLite header and `sqlite_schema` objects (`rea sqlite`). No table-row reads and no WAL replay
- [ ] Export as C/C++ headers from recovered definitions

## License

MIT — see [LICENSE](LICENSE).
