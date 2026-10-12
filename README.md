# rea-rs

Reverse engineer anything — from the terminal, or through your agent.

A clean-room Rust implementation of the MCP reverse-engineering toolkit
concept (inspired by [morluto/rea](https://github.com/morluto/rea)): one
tool surface for inspecting native binaries across **Mach-O** (including
fat/universal binaries), **ELF**, and **PE** formats. All analysis runs
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

# All commands emit JSON — pipe anywhere
rea strings /bin/ls | jq '.count'
```

## MCP server

`rea mcp` speaks JSON-RPC 2.0 over stdio and exposes five tools:

- `rea_info` — format, architecture, entry point, section/symbol counts
- `rea_sections` — section names, virtual addresses, sizes, file offsets
- `rea_symbols` — imports, exports, and locals, filterable by kind
- `rea_strings` — printable strings with file offsets
- `rea_disasm` — instruction-level disassembly at any virtual address

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
  tools behave identically across Mach-O, ELF, and PE.
- **vaddr → file offset mapping** is built in (`Target::vaddr_to_offset`),
  so disassembly works on virtual addresses, not raw file offsets.
- The MCP server is implemented directly against the JSON-RPC 2.0 +
  newline-delimited stdio wire protocol — no SDK dependency.

## Roadmap

- [ ] .NET assembly inspection
- [ ] WASM module inspection
- [ ] Function boundary detection and cross-reference resolution
- [ ] Export as C/C++ headers from recovered definitions

## License

MIT — see [LICENSE](LICENSE).
