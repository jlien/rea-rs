//! `rea` — reverse-engineer anything from the terminal.
//!
//! Uniform inspection of Mach-O (incl. fat), ELF, and PE binaries, plus an
//! MCP stdio server (`rea mcp`) for agent integration.

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use rea_core::{disasm, loader, strings};
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
    /// Extract printable strings.
    Strings {
        path: String,
        #[arg(long, default_value_t = 4)]
        min_length: usize,
    },
    /// Disassemble instructions at a virtual address (default: entry point).
    Disasm {
        path: String,
        /// Virtual address, hex (0x…) or decimal.
        #[arg(long)]
        address: Option<u64>,
        #[arg(long, default_value_t = 32)]
        count: usize,
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
                | Command::Disasm { path, .. } => (path, ()),
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
                Command::Strings { min_length, .. } => {
                    let hits = strings::extract(&target.bytes, *min_length);
                    serde_json::json!({ "count": hits.len(), "strings": hits })
                }
                Command::Disasm { address, count, .. } => {
                    let addr = address.unwrap_or(target.entry);
                    let insns = disasm::disassemble(&target, addr, *count)
                        .context("disassembly failed")?;
                    serde_json::json!({ "address": addr, "count": insns.len(), "instructions": insns })
                }
                Command::Mcp => unreachable!(),
            };
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
            Ok(())
        }
    }
}
