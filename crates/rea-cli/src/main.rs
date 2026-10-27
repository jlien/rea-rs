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
    /// List sections with addresses, sizes, and file offsets. `--arch` selects a Mach-O slice; the default stays the host slice.
    Sections {
        path: String,
        /// Mach-O slice: `arm64`, `x86_64`, `arm`, or `x86`. Other formats reject this.
        #[arg(long)]
        arch: Option<String>,
    },
    /// List symbols, optionally filtered. Mach-O stabs are omitted. Itanium, Rust v0, and MSVC names are also shown demangled; the raw name stays. A clang `__Z` or `__R` name drops one ABI underscore first. A Swift `_$s` name drops it too and reads two length-prefixed identifiers as `module.name`; a trailing `yyF` renders `module.name()`; other Swift stays raw.
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
    /// Disassemble instructions at a virtual address (default: entry point). `--arch` selects a Mach-O slice; the default stays the host slice.
    Disasm {
        path: String,
        /// Virtual address, hex (0x…) or decimal. Defaults to entry point.
        #[arg(long)]
        address: Option<String>,
        #[arg(long, default_value_t = 32)]
        count: usize,
        /// Mach-O slice: `arm64`, `x86_64`, `arm`, or `x86`. Other formats reject this.
        #[arg(long)]
        arch: Option<String>,
    },
    /// Discover functions (entry + prologue scan + call targets).
    Funcs { path: String },
    /// Find code locations referencing an address. Includes arm64 ADRP, x86_64 RIP-relative, 32-bit x86, and ARM/Thumb PC-relative loads.
    Xrefs {
        path: String,
        /// Address, hex (0x…) or decimal.
        address: String,
    },
    /// Direct call graph over discovered functions.
    Callgraph { path: String },
    /// Pseudo-C at a virtual address. Follows an unconditional branch to a direct target inside the enclosing function, and one forward conditional (`jcc` / `b.cond`) whose target is in the function and ahead of the branch: the fall-through block is listed and both paths join at the target. A target already listed, a backward branch, or a branch outside the function ends the walk as a `goto`. Assignments, calls, gotos, and returns. Width-based types on x86_64 and arm64: typed synthetic locals, casts at call arguments and returns; a type carries across a conditional join only when every incoming path agrees. `--arch` selects a Mach-O slice.
    Decompile {
        path: String,
        /// Virtual address, hex (0x…) or decimal. Defaults to the entry point.
        #[arg(long)]
        address: Option<String>,
        #[arg(long, default_value_t = 32)]
        count: usize,
        /// Mach-O slice: `arm64`, `x86_64`, `arm`, or `x86`. Other formats reject this.
        #[arg(long)]
        arch: Option<String>,
    },
    /// WASM section ids, imports, exports, type signatures, function bodies, element and data segments, and a capped custom payload. Memory limits carry the shared flag, and imported memories list their limits. `--wat` prints a WAT-flavored readability listing of what is decoded; it is not a full WAT writer. `--wat-full` prints a full WAT emission of the same decoded content, with unknown opcodes as inline comments. `--execute` runs one export with the i32 interpreter. No WASI, and `--execute` does not touch memory.
    Wasm {
        path: String,
        /// Exported function to run. Omit this to inspect only.
        #[arg(long)]
        execute: Option<String>,
        /// i32 argument for `--execute`. Repeat the flag for each argument.
        #[arg(long = "arg")]
        args: Vec<i32>,
        /// Print a WAT-flavored readability listing instead of JSON. Not a full WAT writer.
        #[arg(long, conflicts_with = "execute")]
        wat: bool,
        /// Print a full WAT emission of what is decoded instead of JSON: types with full param and result lists, imports with kind details, segment offsets, and function bodies with locals. Still not a writer for undecoded things.
        #[arg(long, conflicts_with_all = ["execute", "wat"])]
        wat_full: bool,
    },
    /// Go build info. Go 1.18+ inline blobs and pre-1.18 file offsets. A null or out-of-range offset is an error.
    Goinfo { path: String },
    /// Mach-O dylibs, UUID, build version, rpaths, code-directory identifier, hash type, team id, hash-slot digests, the CMS blob, whether a sha1 or sha256 of the code directory appears in that blob, an embedded Info.plist, entitlements (top-level XML keys with their immediate values, and the DER slot's byte size plus its top-level DER keys), exec-segment flags, an overlay, architectures, and rpath file hits. The digest check is not an Apple trust decision.
    Macho { path: String },
    /// PE subsystem, image base, raw COFF timestamp and its UTC date, data directories, CLR header, metadata streams, table row counts, type names, field names, method names, signatures, IL, parameter names, member-ref names, assembly names, property and event names, CodeView PDB path, resource names, payloads, and an overlay.
    Pe { path: String },
    /// ELF file type, machine, interpreter, needed libraries, soname, rpath, runpath, GNU build-id, notes (owner, type name, descriptor), GNU property bits, and rpath or runpath file hits.
    Elf { path: String },
    /// SQLite header, schema, and optional rows of one table. `--wal` replays committed frames before the read.
    Sqlite {
        path: String,
        /// Table whose rows are listed. Omit this to print the schema only.
        #[arg(long)]
        table: Option<String>,
        /// Maximum rows when `--table` is set.
        #[arg(long, default_value_t = 32)]
        limit: usize,
        /// WAL file to replay onto the database before reading.
        #[arg(long)]
        wal: Option<String>,
    },
    /// C header of recovered local and export names. An Itanium demangle becomes a declaration.
    Headers { path: String },
    /// Identifying fields of an XML or binary Info.plist. A file with none of the keys prints null.
    Plist { path: String },
    /// Identifying lines of a text crash report. A report with none of them prints null.
    Crash { path: String },
    /// Kind of an app bundle, a compiled nib, or an asset catalog. A fitting nib or catalog also lists keys, classes, or block names. Pixels are not decoded.
    Artifact { path: String },
    /// Evidence session JSON. `open` maps a loadable binary once for its identity summary; the file on disk stays the source of truth. `--dir` chooses where the files are written.
    Session {
        #[arg(long)]
        dir: String,
        #[command(subcommand)]
        action: SessionCmd,
    },
    /// Parse an export or report whether a tool is on PATH. Does not launch Hopper, Ghidra, IDA, JEB, Frida, or adb.
    Bridge {
        #[command(subcommand)]
        action: BridgeCmd,
    },
    /// Run the MCP stdio server (for agent integration).
    Mcp,
}

#[derive(Subcommand)]
enum SessionCmd {
    /// Create a session file for a path. A loadable binary is mapped once for its identity summary; a path that does not load still opens.
    Open { path: String },
    /// Append a record. `--tool` names a rea command (`info`, `sections`, `symbols`, `strings`, `funcs`, `disasm`) whose output is re-run against the session's binary and embedded, capped at 16 KiB. Optional `--arguments` text is stored with the record, capped at 1024 bytes; omitted, it stays null.
    Record {
        id: String,
        #[arg(long)]
        tool: Option<String>,
        #[arg(long)]
        arguments: Option<String>,
        summary: String,
    },
    /// Compare two session ids in `--dir`.
    Diff { left: String, right: String },
    /// Print a session file. `--format evidence` maps it to the upstream-morphic Evidence shape instead: per record the tool name, the stored arguments echo and unix-seconds timestamp (null when the record carries neither), the capped embedded output, and the session id. The upstream session handle and a live mapping stay explicit nulls. CLI-only; the MCP surface is unchanged.
    Export {
        id: String,
        #[arg(long, value_enum, default_value_t = ExportFormat::Native)]
        format: ExportFormat,
    },
}

#[derive(ValueEnum, Clone, Copy)]
enum ExportFormat {
    /// The native session file as stored.
    Native,
    /// The upstream-morphic Evidence shape.
    Evidence,
}

#[derive(Subcommand)]
enum BridgeCmd {
    /// Report PATH presence. The CDP parser is in-process and counts as present.
    Status,
    /// Parse an export file. Lines that do not match are skipped.
    Parse { provider: String, file: String },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Command::Mcp => {
            rea_mcp::serve(BufReader::new(std::io::stdin()), std::io::stdout())
                .context("mcp server terminated")?;
            Ok(())
        }
        Command::Wasm {
            path,
            execute,
            args,
            wat,
            wat_full,
        } => {
            let bytes = std::fs::read(path).context("failed to read target")?;
            if *wat_full {
                let module = rea_core::wasm::inspect(&bytes).context("wasm")?;
                println!("{}", rea_core::wasm::wat_full(&module));
                return Ok(());
            }
            if *wat {
                let module = rea_core::wasm::inspect(&bytes).context("wasm")?;
                println!("{}", rea_core::wasm::wat(&module));
                return Ok(());
            }
            if let Some(name) = execute {
                let result = rea_core::wasm::execute(&bytes, name, args)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({ "result": result })).unwrap()
                );
            } else {
                let module = rea_core::wasm::inspect(&bytes).context("wasm")?;
                println!("{}", serde_json::to_string_pretty(&module).unwrap());
            }
            Ok(())
        }
        Command::Sqlite {
            path,
            table,
            limit,
            wal,
        } => {
            let mut bytes = std::fs::read(path).context("failed to read target")?;
            if let Some(wal) = wal {
                let wal_bytes = std::fs::read(wal).context("failed to read wal")?;
                bytes = rea_core::sqlite::apply_wal(&bytes, &wal_bytes)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            }
            let header = rea_core::sqlite::header(&bytes).context("sqlite")?;
            let schema = rea_core::sqlite::schema(&bytes).context("sqlite")?;
            let mut value = serde_json::to_value(header)?;
            value["schema"] = serde_json::json!(schema);
            if let Some(table) = table {
                let rows = rea_core::sqlite::table_rows(&bytes, table, *limit)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                value["rows"] = serde_json::json!(rows);
            }
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
        Command::Headers { path } => {
            let target = loader::load(path).context("failed to load target")?;
            print!("{}", rea_core::headers::emit(&target));
            Ok(())
        }
        Command::Plist { path } => {
            let bytes = std::fs::read(path).context("failed to read target")?;
            let json = match rea_core::plist::identify(&bytes) {
                Some(info) => serde_json::to_value(info)?,
                None => serde_json::json!(null),
            };
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
            Ok(())
        }
        Command::Crash { path } => {
            let bytes = std::fs::read(path).context("failed to read target")?;
            let json = match rea_core::crash::identify(&bytes) {
                Some(report) => serde_json::to_value(report)?,
                None => serde_json::json!(null),
            };
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
            Ok(())
        }
        Command::Artifact { path } => {
            let file = std::path::Path::new(path);
            let kind = rea_core::artifact::identify(file).map_err(|e| anyhow::anyhow!("{e}"))?;
            let reconstruction = if file.is_file() {
                std::fs::read(file)
                    .ok()
                    .and_then(|bytes| rea_core::artifact::reconstruct(&bytes))
            } else {
                None
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "kind": kind,
                    "reconstruction": reconstruction,
                }))
                .unwrap()
            );
            Ok(())
        }
        Command::Session { dir, action } => {
            let dir = std::path::Path::new(dir);
            let value = match action {
                SessionCmd::Open { path } => serde_json::to_value(
                    rea_core::session::open(dir, path).map_err(|e| anyhow::anyhow!("{e}"))?,
                )?,
                SessionCmd::Record { id, tool, arguments, summary } => serde_json::to_value(
                    rea_core::session::record(dir, id, tool.as_deref(), summary, arguments.as_deref())
                        .map_err(|e| anyhow::anyhow!("{e}"))?,
                )?,
                SessionCmd::Diff { left, right } => {
                    let left = rea_core::session::load(dir, left).map_err(|e| anyhow::anyhow!("{e}"))?;
                    let right =
                        rea_core::session::load(dir, right).map_err(|e| anyhow::anyhow!("{e}"))?;
                    serde_json::to_value(rea_core::session::diff(&left, &right))?
                }
                SessionCmd::Export { id, format } => {
                    let session =
                        rea_core::session::load(dir, id).map_err(|e| anyhow::anyhow!("{e}"))?;
                    match format {
                        ExportFormat::Native => serde_json::to_value(&session)?,
                        ExportFormat::Evidence => {
                            serde_json::to_value(rea_core::session::export_evidence(&session))?
                        }
                    }
                }
            };
            println!("{}", serde_json::to_string_pretty(&value).unwrap());
            Ok(())
        }
        Command::Bridge { action } => {
            let value = match action {
                BridgeCmd::Status => serde_json::json!(rea_core::bridge::status()),
                BridgeCmd::Parse { provider, file } => {
                    let text = std::fs::read_to_string(file).context("failed to read export")?;
                    serde_json::json!(
                        rea_core::bridge::parse(provider, &text).map_err(|e| anyhow::anyhow!("{e}"))?
                    )
                }
            };
            println!("{}", serde_json::to_string_pretty(&value).unwrap());
            Ok(())
        }
        _ => {
            let (path, _rest): (&String, ()) = match &cli.command {
                Command::Info { path }
                | Command::Sections { path, .. }
                | Command::Symbols { path, .. }
                | Command::Strings { path, .. }
                | Command::Disasm { path, .. }
                | Command::Funcs { path }
                | Command::Xrefs { path, .. }
                | Command::Callgraph { path }
                | Command::Decompile { path, .. }
                | Command::Macho { path }
                | Command::Pe { path }
                | Command::Elf { path } => (path, ()),
                Command::Wasm { .. }
                | Command::Goinfo { .. }
                | Command::Sqlite { .. }
                | Command::Headers { .. }
                | Command::Plist { .. }
                | Command::Crash { .. }
                | Command::Artifact { .. }
                | Command::Session { .. }
                | Command::Bridge { .. } => unreachable!(),
                Command::Mcp => unreachable!(),
            };
            let arch = match &cli.command {
                Command::Sections { arch, .. }
                | Command::Disasm { arch, .. }
                | Command::Decompile { arch, .. } => arch.as_deref(),
                _ => None,
            };
            let target = loader::load_arch(path, arch).context("failed to load target")?;
            // Native-code commands do not read a WASM target; the deep view
            // is `rea wasm`.
            if matches!(
                cli.command,
                Command::Disasm { .. }
                    | Command::Funcs { .. }
                    | Command::Xrefs { .. }
                    | Command::Decompile { .. }
            ) {
                target
                    .require_native()
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            }
            let json = match &cli.command {
                Command::Info { .. } => {
                    let mut value = serde_json::json!({
                        "path": target.path,
                        "format": target.format.as_str(),
                        "arch": target.arch.as_str(),
                        "bits": target.bits,
                        "little_endian": target.little_endian,
                        "entry": target.entry,
                        "sections": target.sections.len(),
                        "symbols": target.symbols.len(),
                    });
                    if target.format == rea_core::Format::Wasm {
                        let module = rea_core::wasm::inspect(&target.bytes)
                            .map_err(|e| anyhow::anyhow!("{e}"))?;
                        value["wasm"] = serde_json::json!({
                            "sections": module.sections.len(),
                            "functions": module.functions,
                            "exports": module.exports.len(),
                        });
                    }
                    if target.format == rea_core::Format::Sqlite {
                        let hdr = rea_core::sqlite::header(&target.bytes)
                            .map_err(|e| anyhow::anyhow!("{e}"))?;
                        let objects = rea_core::sqlite::schema(&target.bytes)
                            .map_err(|e| anyhow::anyhow!("{e}"))?;
                        value["sqlite"] = serde_json::json!({
                            "application_id": hdr.application_id,
                            "schema_objects": objects.len(),
                        });
                    }
                    value
                }
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
                Command::Decompile { address, count, .. } => {
                    let addr = match address.as_deref() {
                        Some(a) if a.starts_with("0x") => u64::from_str_radix(&a[2..], 16)?,
                        Some(a) => a.parse::<u64>()?,
                        None => target.entry,
                    };
                    let text = rea_core::decompile::decompile(&target, addr, *count)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    serde_json::json!({ "address": addr, "text": text })
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
                    let hits = rea_core::paths::search(
                        &facts.rpaths,
                        &facts.dylibs,
                        Some(std::path::Path::new(&target.path)),
                    );
                    let file = std::fs::read(&target.path)?;
                    let architectures = rea_core::macho_meta::architectures(&file)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    let mut value = serde_json::to_value(facts)?;
                    value["architectures"] = serde_json::json!(architectures);
                    value["path_hits"] = serde_json::json!(hits);
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
                    let mut dirs = facts.rpath.clone();
                    dirs.extend(facts.runpath.iter().cloned());
                    let hits = rea_core::paths::search(
                        &dirs,
                        &facts.needed,
                        Some(std::path::Path::new(&target.path)),
                    );
                    let mut value = serde_json::to_value(facts)?;
                    value["path_hits"] = serde_json::json!(hits);
                    value
                }
                Command::Mcp
                | Command::Wasm { .. }
                | Command::Goinfo { .. }
                | Command::Sqlite { .. }
                | Command::Headers { .. }
                | Command::Plist { .. }
                | Command::Crash { .. }
                | Command::Artifact { .. }
                | Command::Session { .. }
                | Command::Bridge { .. } => unreachable!(),
            };
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
            Ok(())
        }
    }
}
