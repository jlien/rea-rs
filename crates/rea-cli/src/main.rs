//! `rea` — reverse-engineer anything from the terminal.
//!
//! Uniform inspection of Mach-O (incl. fat), ELF, and PE binaries, plus an
//! MCP stdio server (`rea mcp`) for agent integration.

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use rea_core::{analysis, disasm, loader, strings};
use std::io::BufReader;

#[derive(Parser)]
#[command(
    name = "rea",
    version,
    about = "Reverse engineer anything: inspect Mach-O, ELF, and PE binaries",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(ValueEnum, Clone, Copy)]
enum SymKind {
    All,
    Imports,
    Exports,
    Locals,
}

#[derive(Subcommand)]
enum Command {
    /// Identify the binary: format, arch, entry, counts.
    Info { path: String },
    /// List sections with addresses, sizes, and file offsets.
    Sections { path: String },
    /// List symbols, optionally filtered.
    Symbols {
        path: String,
        #[arg(value_enum, default_value_t = SymKind::All)]
        kind: SymKind,
    },
    /// Extract printable strings, optionally with code cross-references.
    Strings {
        path: String,
        #[arg(long, default_value_t = 4)]
        min_length: usize,
        /// Annotate each string with code references (data xref scan).
        #[arg(long)]
        xrefs: bool,
    },
    /// Disassemble instructions at a virtual address (default: entry point).
    Disasm {
        path: String,
        /// Virtual address, hex (0x…) or decimal. Defaults to entry point.
        #[arg(long)]
        address: Option<String>,
        #[arg(long, default_value_t = 32)]
        count: usize,
    },
    /// Discover functions (entry + prologue scan + call targets).
    Funcs { path: String },
    /// Find code locations referencing an address (data xrefs).
    Xrefs {
        path: String,
        /// Address, hex (0x…) or decimal.
        address: String,
    },
    /// Direct call graph over discovered functions.
    Callgraph { path: String },
    /// WASM imports, exports, and section ids. Does not execute the module.
    Wasm { path: String },
    /// Go 1.18+ build info embedded in a binary. Pre-1.18 pointer blobs error.
    Goinfo { path: String },
    /// Mach-O dylibs, UUID, build version, code signature, and architectures.
    Macho { path: String },
    /// PE data directories, CLR header, metadata streams, table row counts, type names, CodeView PDB path, and root resource type ids.
    Pe { path: String },
    /// ELF interpreter, needed libraries, soname, and GNU build-id.
    Elf { path: String },
    /// SQLite database header and schema objects. Does not read table rows.
    Sqlite { path: String },
    /// Run the MCP stdio server (for agent integration).
    Mcp,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Command::Mcp => {
            rea_mcp::serve(BufReader::new(std::io::stdin()), std::io::stdout())
                .context("mcp server terminated")?;
            Ok(())
        }
        Command::Wasm { path } => {
            let bytes = std::fs::read(path).context("failed to read target")?;
            let module = rea_core::wasm::inspect(&bytes).context("wasm")?;
            println!("{}", serde_json::to_string_pretty(&module).unwrap());
            Ok(())
        }
        Command::Sqlite { path } => {
            let bytes = std::fs::read(path).context("failed to read target")?;
            let header = rea_core::sqlite::header(&bytes).context("sqlite")?;
            let schema = rea_core::sqlite::schema(&bytes).context("sqlite")?;
            let mut value = serde_json::to_value(header)?;
            value["schema"] = serde_json::json!(schema);
            println!("{}", serde_json::to_string_pretty(&value).unwrap());
            Ok(())
        }
        Command::Goinfo { path } => {
            let bytes = std::fs::read(path).context("failed to read target")?;
            let found = rea_core::goinfo::find_build_info(&bytes).context("go buildinfo")?;
            let json = match found {
                Some(info) => serde_json::json!({
                    "found": true,
                    "version": info.version,
                    "modules": info.modules,
                }),
                None => serde_json::json!({ "found": false }),
            };
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
            Ok(())
        }
        _ => {
            let (path, _rest): (&String, ()) = match &cli.command {
                Command::Info { path }
                | Command::Sections { path }
                | Command::Symbols { path, .. }
                | Command::Strings { path, .. }
                | Command::Disasm { path, .. }
                | Command::Funcs { path }
                | Command::Xrefs { path, .. }
                | Command::Callgraph { path }
                | Command::Macho { path }
                | Command::Pe { path }
                | Command::Elf { path } => (path, ()),
                Command::Wasm { .. } | Command::Goinfo { .. } | Command::Sqlite { .. } => unreachable!(),
                Command::Mcp => unreachable!(),
            };
            let target = loader::load(path).context("failed to load target")?;
            let json = match &cli.command {
                Command::Info { .. } => serde_json::json!({
                    "path": target.path,
                    "format": target.format.as_str(),
                    "arch": target.arch.as_str(),
                    "bits": target.bits,
                    "little_endian": target.little_endian,
                    "entry": target.entry,
                    "sections": target.sections.len(),
                    "symbols": target.symbols.len(),
                }),
                Command::Sections { .. } => serde_json::json!(target.sections),
                Command::Symbols { kind, .. } => {
                    let want: &[&str] = match kind {
                        SymKind::All => &["Import", "Export", "Local"],
                        SymKind::Imports => &["Import"],
                        SymKind::Exports => &["Export"],
                        SymKind::Locals => &["Local"],
                    };
                    let syms: Vec<_> = target
                        .symbols
                        .iter()
                        .filter(|s| want.contains(&format!("{:?}", s.kind).as_str()))
                        .collect();
                    serde_json::json!({ "count": syms.len(), "symbols": syms })
                }
                Command::Strings { min_length, xrefs, .. } => {
                    if *xrefs {
                        let hits = analysis::strings_with_xrefs(&target, *min_length);
                        serde_json::json!({ "count": hits.len(), "strings": hits })
                    } else {
                        let hits = strings::extract(&target.bytes, *min_length);
                        serde_json::json!({ "count": hits.len(), "strings": hits })
                    }
                }
                Command::Disasm { address, count, .. } => {
                    let addr = match address.as_deref() {
                        Some(a) if a.starts_with("0x") => u64::from_str_radix(&a[2..], 16)?,
                        Some(a) => a.parse::<u64>()?,
                        None => target.entry,
                    };
                    let insns = disasm::disassemble(&target, addr, *count)
                        .context("disassembly failed")?;
                    serde_json::json!({ "address": addr, "count": insns.len(), "instructions": insns })
                }
                Command::Funcs { .. } => {
                    let funcs = analysis::discover_functions(&target);
                    serde_json::json!({ "count": funcs.len(), "functions": funcs })
                }
                Command::Xrefs { address, .. } => {
                    let addr = if let Some(h) = address.strip_prefix("0x") {
                        u64::from_str_radix(h, 16)?
                    } else {
                        address.parse::<u64>()?
                    };
                    let refs = analysis::data_xrefs(&target, addr);
                    serde_json::json!({ "address": addr, "count": refs.len(), "refs": refs })
                }
                Command::Callgraph { .. } => {
                    let functions = analysis::discover_functions(&target);
                    let graph = analysis::call_graph(&functions);
                    serde_json::json!({
                        "functions": functions.len(),
                        "edges": graph.edges.len(),
                        "graph": graph,
                    })
                }
                Command::Macho { .. } => {
                    let facts = rea_core::macho_meta::facts(&target.bytes)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    let file = std::fs::read(&target.path)?;
                    let architectures = rea_core::macho_meta::architectures(&file)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    let mut value = serde_json::to_value(facts)?;
                    value["architectures"] = serde_json::json!(architectures);
                    value
                }
                Command::Pe { .. } => {
                    let facts = rea_core::pe_meta::facts(&target.bytes)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    serde_json::json!(facts)
                }
                Command::Elf { .. } => {
                    let facts = rea_core::elf_meta::facts(&target.bytes)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    serde_json::json!(facts)
                }
                Command::Mcp | Command::Wasm { .. } | Command::Goinfo { .. } | Command::Sqlite { .. } => unreachable!(),
            };
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
            Ok(())
        }
    }
}
