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
        _ => {
            let (path, rest): (&String, ()) = match &cli.command {
                Command::Info { path }
                | Command::Sections { path }
                | Command::Symbols { path, .. }
                | Command::Strings { path, .. }
                | Command::Disasm { path, .. }
                | Command::Funcs { path }
                | Command::Xrefs { path, .. } => (path, ()),
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
                Command::Mcp => unreachable!(),
            };
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
            Ok(())
        }
    }
}
