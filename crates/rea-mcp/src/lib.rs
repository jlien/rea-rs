//! MCP stdio server: JSON-RPC 2.0 over newline-delimited messages.
//!
//! Exposes rea's analysis commands as MCP tools so any MCP-capable agent
//! can inspect binaries. Run via `rea mcp`.

use rea_core::{analysis, loader, strings};
#[cfg(feature = "disasm")]
use rea_core::disasm;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

const PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "rea-rs";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Serve MCP over stdio until EOF. Returns the number of requests handled.
pub fn serve(input: impl BufRead, output: impl Write) -> std::io::Result<usize> {
    serve_internal(input, output)
}

fn serve_internal(input: impl BufRead, mut output: impl Write) -> std::io::Result<usize> {
    let mut handled = 0usize;
    for line in input.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(trimmed) else {
            write_error(&mut output, None, -32700, "parse error")?;
            continue;
        };

        let id = msg.get("id").cloned().filter(|v| !v.is_null());
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");

        // Notifications (no id) get no response.
        let is_notification = id.is_none();
        if is_notification {
            continue;
        }

        let result = match method {
            "initialize" => Ok(json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
            })),
            "tools/list" => Ok(json!({ "tools": tool_definitions() })),
            "tools/call" => handle_tool_call(&msg),
            _ => Err(format!("method not found: {method}")),
        };

        match result {
            Ok(result) => {
                let resp = json!({ "jsonrpc": "2.0", "id": id, "result": result });
                writeln!(output, "{resp}")?;
            }
            Err(err) => write_error(&mut output, id, -32601, &err)?,
        }
        handled += 1;
    }
    Ok(handled)
}

fn write_error(
    output: &mut impl Write,
    id: Option<Value>,
    code: i64,
    message: &str,
) -> std::io::Result<()> {
    let resp = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    });
    writeln!(output, "{resp}")
}

fn text_result(text: impl Into<String>) -> Value {
    json!({ "content": [ { "type": "text", "text": text.into() } ] })
}

fn handle_tool_call(msg: &Value) -> Result<Value, String> {
    let params = msg.get("params").cloned().unwrap_or(json!({}));
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    if name == "rea_session" {
        return session_call(&args);
    }
    if name == "rea_bridge" {
        return bridge_call(&args);
    }

    let path = args
        .get("path")
        .and_then(Value::as_str)
        .ok_or("missing required argument: path")?;

    if name == "rea_wasm" || name == "rea_go" || name == "rea_sqlite" {
        let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
        let value = if name == "rea_wasm" {
            if let Some(export) = args.get("execute").and_then(Value::as_str) {
                let argv = i32_args(&args);
                json!({
                    "result": rea_core::wasm::execute(&bytes, export, &argv).map_err(|e| e.to_string())?
                })
            } else {
                json!(rea_core::wasm::inspect(&bytes).map_err(|e| e.to_string())?)
            }
        } else if name == "rea_sqlite" {
            let mut db = bytes;
            if let Some(wal) = args.get("wal").and_then(Value::as_str) {
                let wal_bytes = std::fs::read(wal).map_err(|e| e.to_string())?;
                db = rea_core::sqlite::apply_wal(&db, &wal_bytes).map_err(|e| e.to_string())?;
            }
            let header = rea_core::sqlite::header(&db).map_err(|e| e.to_string())?;
            let schema = rea_core::sqlite::schema(&db).map_err(|e| e.to_string())?;
            let mut value = serde_json::to_value(header).map_err(|e| e.to_string())?;
            value["schema"] = json!(schema);
            if let Some(table) = args.get("table").and_then(Value::as_str) {
                let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(32) as usize;
                value["rows"] = json!(
                    rea_core::sqlite::table_rows(&db, table, limit).map_err(|e| e.to_string())?
                );
            }
            value
        } else {
            match rea_core::goinfo::find_build_info(&bytes).map_err(|e| e.to_string())? {
                Some(info) => json!({
                    "found": true,
                    "version": info.version,
                    "modules": info.modules,
                }),
                None => json!({ "found": false }),
            }
        };
        return Ok(text_result(value.to_string()));
    }

    if name == "rea_headers" {
        return Ok(match loader::load(path) {
            Ok(target) => text_result(rea_core::headers::emit(&target)),
            Err(e) => text_result(format!("error: {e}")),
        });
    }

    let arch = args
        .get("arch")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty());
    let result: Result<Value, String> = (|| {
        let target = if matches!(name, "rea_sections" | "rea_disasm" | "rea_decompile") {
            loader::load_arch(path, arch).map_err(|e| e.to_string())?
        } else {
            loader::load(path).map_err(|e| e.to_string())?
        };
        // Native-code commands do not read a WASM target; the deep view is
        // `rea_wasm`.
        if matches!(
            name,
            "rea_disasm" | "rea_funcs" | "rea_xrefs" | "rea_decompile"
        ) {
            target.require_native().map_err(|e| e.to_string())?;
        }
        Ok(match name {
            "rea_info" => {
                let mut value = json!({
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
                    let module =
                        rea_core::wasm::inspect(&target.bytes).map_err(|e| e.to_string())?;
                    value["wasm"] = json!({
                        "sections": module.sections.len(),
                        "functions": module.functions,
                        "exports": module.exports.len(),
                    });
                }
                if target.format == rea_core::Format::Sqlite {
                    let hdr =
                        rea_core::sqlite::header(&target.bytes).map_err(|e| e.to_string())?;
                    let objects =
                        rea_core::sqlite::schema(&target.bytes).map_err(|e| e.to_string())?;
                    value["sqlite"] = json!({
                        "application_id": hdr.application_id,
                        "schema_objects": objects.len(),
                    });
                }
                value
            }
            "rea_sections" => json!(target.sections),
            "rea_symbols" => {
                let filter = args.get("kind").and_then(Value::as_str).unwrap_or("all");
                let kinds: &[&str] = match filter {
                    "imports" => &["Import"],
                    "exports" => &["Export"],
                    "locals" => &["Local"],
                    _ => &["Import", "Export", "Local"],
                };
                let syms: Vec<&rea_core::Symbol> = target
                    .symbols
                    .iter()
                    .filter(|s| {
                        let k = format!("{:?}", s.kind);
                        kinds.contains(&k.as_str())
                    })
                    .collect();
                json!({ "count": syms.len(), "symbols": syms })
            }
            "rea_strings" => {
                let min = args
                    .get("min_length")
                    .and_then(Value::as_u64)
                    .unwrap_or(4) as usize;
                let with_xrefs = args.get("xrefs").and_then(Value::as_bool).unwrap_or(false);
                if with_xrefs {
                    let hits = analysis::strings_with_xrefs(&target, min);
                    json!({ "count": hits.len(), "strings": hits })
                } else {
                    let hits = strings::extract(&target.bytes, min);
                    json!({ "count": hits.len(), "strings": hits })
                }
            }
            "rea_decompile" => {
                let addr = args
                    .get("address")
                    .and_then(Value::as_u64)
                    .unwrap_or(target.entry);
                let count = args.get("count").and_then(Value::as_u64).unwrap_or(32) as usize;
                let text = rea_core::decompile::decompile(&target, addr, count)
                    .map_err(|e| e.to_string())?;
                json!({ "address": addr, "text": text })
            }
            "rea_disasm" => {
                #[cfg(feature = "disasm")]
                {
                    let addr = args
                        .get("address")
                        .and_then(Value::as_u64)
                        .unwrap_or(target.entry);
                    let count = args
                        .get("count")
                        .and_then(Value::as_u64)
                        .unwrap_or(32) as usize;
                    let insns = disasm::disassemble(&target, addr, count)
                        .map_err(|e| e.to_string())?;
                    json!({ "address": addr, "count": insns.len(), "instructions": insns })
                }
                #[cfg(not(feature = "disasm"))]
                {
                    json!({ "error": "built without disasm feature" })
                }
            }
            "rea_funcs" => {
                let funcs = analysis::discover_functions(&target);
                json!({ "count": funcs.len(), "functions": funcs })
            }
            "rea_xrefs" => {
                let addr = args
                    .get("address")
                    .and_then(Value::as_u64)
                    .ok_or("missing required argument: address")?;
                let refs = analysis::data_xrefs(&target, addr);
                json!({ "address": addr, "count": refs.len(), "refs": refs })
            }
            "rea_call_graph" => {
                let functions = analysis::discover_functions(&target);
                let graph = analysis::call_graph(&functions);
                json!({
                    "functions": functions.len(),
                    "edges": graph.edges.len(),
                    "graph": graph,
                })
            }
            "rea_macho" => {
                let facts = rea_core::macho_meta::facts(&target.bytes).map_err(|e| e.to_string())?;
                let hits = rea_core::paths::search(
                    &facts.rpaths,
                    &facts.dylibs,
                    Some(std::path::Path::new(path)),
                );
                let file = std::fs::read(path).map_err(|e| e.to_string())?;
                let architectures =
                    rea_core::macho_meta::architectures(&file).map_err(|e| e.to_string())?;
                let mut value = serde_json::to_value(facts).map_err(|e| e.to_string())?;
                value["architectures"] = json!(architectures);
                value["path_hits"] = json!(hits);
                value
            }
            "rea_pe" => {
                json!(rea_core::pe_meta::facts(&target.bytes).map_err(|e| e.to_string())?)
            }
            "rea_elf" => {
                let facts = rea_core::elf_meta::facts(&target.bytes).map_err(|e| e.to_string())?;
                let mut dirs = facts.rpath.clone();
                dirs.extend(facts.runpath.iter().cloned());
                let hits = rea_core::paths::search(&dirs, &facts.needed, Some(std::path::Path::new(path)));
                let mut value = serde_json::to_value(facts).map_err(|e| e.to_string())?;
                value["path_hits"] = json!(hits);
                value
            }
            other => return Err(format!("unknown tool: {other}")),
        })
    })();

    match result {
        Ok(v) => Ok(text_result(v.to_string())),
        Err(e) => Ok(text_result(format!("error: {e}"))),
    }
}

fn i32_args(args: &Value) -> Vec<i32> {
    args.get("args")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_i64().map(|n| n as i32))
                .collect()
        })
        .unwrap_or_default()
}

fn session_call(args: &Value) -> Result<Value, String> {
    let action = args.get("action").and_then(Value::as_str).unwrap_or("");
    let dir = args
        .get("dir")
        .and_then(Value::as_str)
        .ok_or("missing required argument: dir")?;
    let dir = std::path::Path::new(dir);
    let value = match action {
        "open" => {
            let path = args.get("path").and_then(Value::as_str).unwrap_or("");
            serde_json::to_value(rea_core::session::open(dir, path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?
        }
        "record" => {
            let id = args.get("id").and_then(Value::as_str).unwrap_or("");
            let tool = args.get("tool").and_then(Value::as_str);
            let summary = args.get("summary").and_then(Value::as_str).unwrap_or("");
            serde_json::to_value(
                rea_core::session::record(dir, id, tool, summary).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?
        }
        "diff" => {
            let left = args.get("left").and_then(Value::as_str).unwrap_or("");
            let right = args.get("right").and_then(Value::as_str).unwrap_or("");
            let left = rea_core::session::load(dir, left).map_err(|e| e.to_string())?;
            let right = rea_core::session::load(dir, right).map_err(|e| e.to_string())?;
            serde_json::to_value(rea_core::session::diff(&left, &right)).map_err(|e| e.to_string())?
        }
        _ => return Ok(text_result(format!("error: session: unknown action {action}"))),
    };
    Ok(text_result(value.to_string()))
}

fn bridge_call(args: &Value) -> Result<Value, String> {
    let action = args.get("action").and_then(Value::as_str).unwrap_or("status");
    let value = match action {
        "status" => json!(rea_core::bridge::status()),
        "parse" => {
            let provider = args.get("provider").and_then(Value::as_str).unwrap_or("");
            let text = if let Some(text) = args.get("text").and_then(Value::as_str) {
                text.to_string()
            } else if let Some(file) = args.get("file").and_then(Value::as_str) {
                std::fs::read_to_string(file).map_err(|e| e.to_string())?
            } else {
                return Ok(text_result("error: bridge: missing text"));
            };
            json!(rea_core::bridge::parse(provider, &text).map_err(|e| e.to_string())?)
        }
        _ => return Ok(text_result(format!("error: bridge: unknown action {action}"))),
    };
    Ok(text_result(value.to_string()))
}

fn tool_definitions() -> Vec<Value> {
    fn schema(path_only: bool, extra: Value, extra_required: &[&str]) -> Value {
        let mut props = json!({
            "path": { "type": "string", "description": "Filesystem path to the binary" }
        });
        if !path_only {
            if let (Value::Object(p), Value::Object(e)) = (&mut props, extra) {
                for (k, v) in e {
                    p.insert(k, v);
                }
            }
        }
        let mut required = vec![json!("path")];
        for name in extra_required {
            required.push(json!(*name));
        }
        json!({ "type": "object", "properties": props, "required": required })
    }

    vec![
        json!({
            "name": "rea_info",
            "description": "Identify a binary: format, architecture, bits, endianness, entry point, and section/symbol counts.",
            "inputSchema": schema(true, json!({}), &[]),
        }),
        json!({
            "name": "rea_sections",
            "description": "List sections of a binary with names, virtual addresses, sizes, file offsets, and rwx permissions. ELF sections also carry the sh_type name (PROGBITS, NOBITS, ...) and SHF_ flags beyond the rwx bits. Optional arch selects a Mach-O slice (arm64, x86_64, arm, x86). The default is the host slice.",
            "inputSchema": schema(false, json!({
                "arch": { "type": "string", "description": "Mach-O slice. Default is the host slice." }
            }), &[]),
        }),
        json!({
            "name": "rea_symbols",
            "description": "List symbols; optionally filter by kind: imports, exports, or locals. Mach-O stab symbols are omitted. Itanium, Rust v0, and MSVC names are also returned demangled. The raw name stays. A clang __Z or __R name drops one ABI underscore first. Swift stays raw.",
            "inputSchema": schema(false, json!({
                "kind": { "type": "string", "enum": ["all", "imports", "exports", "locals"] }
            }), &[]),
        }),
        json!({
            "name": "rea_strings",
            "description": "Extract printable ASCII strings with file offsets. Set xrefs to annotate each string with code references.",
            "inputSchema": schema(false, json!({
                "min_length": { "type": "integer", "description": "Minimum string length (default 4)" },
                "xrefs": { "type": "boolean", "description": "Annotate each string with code references (default false)" }
            }), &[]),
        }),
        json!({
            "name": "rea_disasm",
            "description": "Disassemble code at a virtual address (defaults to the entry point). Optional arch selects a Mach-O slice. The default is the host slice.",
            "inputSchema": schema(false, json!({
                "address": { "type": "integer", "description": "Virtual address (hex or decimal)" },
                "count": { "type": "integer", "description": "Max instructions (default 32)" },
                "arch": { "type": "string", "description": "Mach-O slice. Default is the host slice." }
            }), &[]),
        }),
        json!({
            "name": "rea_funcs",
            "description": "Discover functions from the entry point, direct call targets, and prologue scan.",
            "inputSchema": schema(true, json!({}), &[]),
        }),
        json!({
            "name": "rea_xrefs",
            "description": "Find code locations referencing an address. Absolute pointers use the target pointer width. Text also includes arm64 ADRP, x86_64 RIP-relative, 32-bit x86, and ARM/Thumb PC-relative loads.",
            "inputSchema": schema(false, json!({
                "address": { "type": "integer", "description": "Address to find references to" }
            }), &["address"]),
        }),
        json!({
            "name": "rea_call_graph",
            "description": "Direct call graph over discovered functions. Calls to unknown addresses are dropped.",
            "inputSchema": schema(true, json!({}), &[]),
        }),
        json!({
            "name": "rea_wasm",
            "description": "WASM section ids, imports, exports, type signatures, function-body opcodes, element and data segments, a capped custom payload, memory limits with the shared flag, imported memories with their limits, table limits, the data count, and the start index. Optional execute runs one export with an i32 interpreter. No WASI, and execute does not touch memory.",
            "inputSchema": schema(false, json!({
                "execute": { "type": "string", "description": "Export name to run. Omit to inspect only." },
                "args": { "type": "array", "items": { "type": "integer" }, "description": "i32 arguments for execute." }
            }), &[]),
        }),
        json!({
            "name": "rea_go",
            "description": "Go build info. Go 1.18+ inline blobs and pre-1.18 file offsets. A null or out-of-range offset is an error. Host pointers are not dereferenced.",
            "inputSchema": schema(true, json!({}), &[]),
        }),
        json!({
            "name": "rea_macho",
            "description": "Mach-O dylibs, UUID, build version, rpaths, code-directory identifier, hash type, team id, hash-slot digests, the special-slot count, exec-segment offset, size, and flags, the CMS blob, cms_verified when the hash type is sha1 or sha256, entitlements keys and capped XML, the DER entitlements slot size, an embedded Info.plist, an overlay, fat architectures, and rpath file hits. cms_verified is a digest window, not an Apple trust decision. A missing blob does not fail the parse.",
            "inputSchema": schema(true, json!({}), &[]),
        }),
        json!({
            "name": "rea_pe",
            "description": "PE subsystem, image base, raw COFF timestamp and its UTC date, data directories, CLR runtime header, metadata version, stream names, table row counts, type and member names, method signatures, a bounded IL listing, assembly and assembly-ref names, property and event names, CodeView PDB path, resource names, payloads, and an overlay. A missing payload does not fail the parse.",
            "inputSchema": schema(true, json!({}), &[]),
        }),
        json!({
            "name": "rea_sqlite",
            "description": "SQLite database header, including the application id, and sqlite_schema objects. Optional table lists capped rows. Optional wal replays committed frames before the read.",
            "inputSchema": schema(false, json!({
                "table": { "type": "string", "description": "Table name whose rows are listed." },
                "limit": { "type": "integer", "description": "Maximum rows (default 32)." },
                "wal": { "type": "string", "description": "WAL file to replay before reading." }
            }), &[]),
        }),
        json!({
            "name": "rea_elf",
            "description": "ELF file type, machine, interpreter, needed libraries, soname, rpath, runpath, GNU build-id, notes from PT_NOTE segments and SHT_NOTE sections, decoded GNU property bits, and rpath or runpath file hits.",
            "inputSchema": schema(true, json!({}), &[]),
        }),
        json!({
            "name": "rea_headers",
            "description": "A C header of recovered local and export names. An Itanium or MSVC demangle becomes a declaration, keeping its return type. A demangled path with :: but no parameter list (a Rust path) becomes a comment line, never a declaration. Imports are omitted, as are Swift names.",
            "inputSchema": schema(true, json!({}), &[]),
        }),
        json!({
            "name": "rea_decompile",
            "description": "Bounded pseudo-C at a virtual address: assignments, calls, gotos, and returns, following unconditional jumps and one forward conditional (jcc / b.cond) inside the enclosing function (up to 64 instructions, 8 hops). Width-based types on x86_64 and arm64: typed synthetic locals, casts at call arguments and returns; types cross a followed join only when every incoming path agrees. No memory-object or struct types, no cross-function dataflow. Optional arch selects a Mach-O slice.",
            "inputSchema": schema(false, json!({
                "address": { "type": "integer", "description": "Virtual address. Default is the entry point." },
                "count": { "type": "integer", "description": "Maximum instructions (default 32, cap 64)." },
                "arch": { "type": "string", "description": "Mach-O slice. Default is the host slice." }
            }), &[]),
        }),
        json!({
            "name": "rea_session",
            "description": "Evidence session JSON: open, record a tool and summary, or diff two sessions. open maps a loadable binary once for its identity summary; the file on disk stays the source of truth. record with tool embeds that command's output, capped at 16 KiB. dir is the directory of the session files.",
            "inputSchema": json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["open", "record", "diff"] },
                    "dir": { "type": "string", "description": "Directory of session JSON files." },
                    "path": { "type": "string", "description": "Path recorded by open." },
                    "id": { "type": "string" },
                    "tool": { "type": "string", "description": "Optional rea command to re-run against the session's binary: info, sections, symbols, strings, funcs, or disasm." },
                    "summary": { "type": "string" },
                    "left": { "type": "string" },
                    "right": { "type": "string" }
                },
                "required": ["action", "dir"]
            }),
        }),
        json!({
            "name": "rea_bridge",
            "description": "PATH presence and export parsers for Hopper, Ghidra, IDA, JEB, Frida, CDP, and adb. Does not launch those programs and does not attach to a process.",
            "inputSchema": json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["status", "parse"] },
                    "provider": { "type": "string" },
                    "text": { "type": "string", "description": "Export text to parse." },
                    "file": { "type": "string", "description": "Export file to parse when text is omitted." }
                },
                "required": ["action"]
            }),
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    fn exchange(input: &str) -> (Vec<String>, usize) {
        let mut out = Vec::new();
        let n = serve_internal(BufReader::new(input.as_bytes()), &mut out).unwrap();
        (String::from_utf8_lossy(&out).lines().map(String::from).collect(), n)
    }

    #[test]
    fn initialize_handshake() {
        let (lines, _) = exchange(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        );
        let v: Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(v["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(v["result"]["serverInfo"]["name"], SERVER_NAME);
    }

    #[test]
    fn tools_list_returns_eighteen_tools() {
        let (lines, _) = exchange(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
        let v: Value = serde_json::from_str(&lines[0]).unwrap();
        let tools = v["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 18);
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&"rea_sqlite"));
        assert!(names.contains(&"rea_decompile"));
        assert!(names.contains(&"rea_headers"));
        assert!(names.contains(&"rea_session"));
        assert!(names.contains(&"rea_bridge"));
        let session = tools.iter().find(|t| t["name"] == "rea_session").unwrap();
        let required = session["inputSchema"]["required"].as_array().unwrap();
        assert!(required.iter().all(|item| item != "path"));
        let headers = tools.iter().find(|t| t["name"] == "rea_headers").unwrap();
        let required = headers["inputSchema"]["required"].as_array().unwrap();
        assert!(required.iter().any(|r| r == "path"));
    }

    #[test]
    fn rea_headers_call_returns_the_header_text() {
        let exe = std::env::current_exe().unwrap();
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "rea_headers",
                "arguments": { "path": exe.to_str().unwrap() }
            }
        });
        let result = handle_tool_call(&msg).unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("#ifndef REA_RECOVERED_H\n"), "{text}");
        assert!(text.ends_with("#endif\n"), "{text}");
    }

    #[test]
    fn tools_list_includes_funcs_and_xrefs() {
        let (lines, _) = exchange(r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#);
        let v: Value = serde_json::from_str(&lines[0]).unwrap();
        let tools = v["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&"rea_funcs"));
        assert!(names.contains(&"rea_xrefs"));

        let xrefs = tools.iter().find(|t| t["name"] == "rea_xrefs").unwrap();
        let required = xrefs["inputSchema"]["required"].as_array().unwrap();
        assert!(required.iter().any(|r| r == "path"));
        assert!(required.iter().any(|r| r == "address"));
    }

    #[test]
    fn notifications_are_silent() {
        let (lines, _) = exchange(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        assert!(lines.is_empty());
    }

    #[test]
    fn unknown_method_is_jsonrpc_error() {
        let (lines, _) = exchange(r#"{"jsonrpc":"2.0","id":9,"method":"nope"}"#);
        let v: Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(v["error"]["code"], -32601);
    }

    /// Type, function, export, and code sections: one defined function with
    /// body `end`, exported as `f` func 0.
    fn wasm_module() -> Vec<u8> {
        let mut bytes = b"\0asm\x01\x00\x00\x00".to_vec();
        bytes.extend_from_slice(&[1, 4, 1, 0x60, 0, 0]);
        bytes.extend_from_slice(&[3, 2, 1, 0]);
        bytes.extend_from_slice(&[7, 5, 1, 1, b'f', 0, 0]);
        bytes.extend_from_slice(&[10, 4, 1, 2, 0, 0x0b]);
        bytes
    }

    #[test]
    fn rea_info_reports_wasm_identity_counts() {
        let path =
            std::env::temp_dir().join(format!("rea-mcp-wasm-info-{}.wasm", std::process::id()));
        std::fs::write(&path, wasm_module()).unwrap();
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "rea_info",
                "arguments": { "path": path.to_str().unwrap() }
            }
        });
        let result = handle_tool_call(&msg).unwrap();
        let v: Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(v["format"], "wasm");
        assert_eq!(v["arch"], "unknown");
        assert_eq!(v["wasm"]["sections"], 4);
        assert_eq!(v["wasm"]["functions"], 1);
        assert_eq!(v["wasm"]["exports"], 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rea_funcs_rejects_a_wasm_target() {
        let path =
            std::env::temp_dir().join(format!("rea-mcp-wasm-funcs-{}.wasm", std::process::id()));
        std::fs::write(&path, wasm_module()).unwrap();
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "rea_funcs",
                "arguments": { "path": path.to_str().unwrap() }
            }
        });
        let result = handle_tool_call(&msg).unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("no native code view"), "{text}");
        let _ = std::fs::remove_file(&path);
    }

    /// One 512-byte page: application id `0x01020304`, and a leaf schema
    /// b-tree with one row — table `notes`, root page 2, NULL SQL.
    fn sqlite_db() -> Vec<u8> {
        let mut db = vec![0u8; 512];
        db[..16].copy_from_slice(b"SQLite format 3\0");
        db[16..18].copy_from_slice(&512u16.to_be_bytes());
        db[18] = 1;
        db[19] = 1;
        db[21] = 64;
        db[22] = 32;
        db[23] = 32;
        db[28..32].copy_from_slice(&1u32.to_be_bytes());
        db[44..48].copy_from_slice(&4u32.to_be_bytes());
        db[56..60].copy_from_slice(&1u32.to_be_bytes());
        db[68..72].copy_from_slice(&0x0102_0304u32.to_be_bytes());
        let mut payload: Vec<u8> = vec![6, 23, 23, 23, 1, 0];
        payload.extend_from_slice(b"tablenotesnotes");
        payload.push(2);
        let mut cell = vec![payload.len() as u8, 1];
        cell.extend_from_slice(&payload);
        let at = 512 - cell.len();
        db[at..at + cell.len()].copy_from_slice(&cell);
        db[100] = 0x0d;
        db[103..105].copy_from_slice(&1u16.to_be_bytes());
        db[105..107].copy_from_slice(&(at as u16).to_be_bytes());
        db[108..110].copy_from_slice(&(at as u16).to_be_bytes());
        db
    }

    #[test]
    fn rea_info_reports_sqlite_identity_counts() {
        let path =
            std::env::temp_dir().join(format!("rea-mcp-sqlite-info-{}.db", std::process::id()));
        std::fs::write(&path, sqlite_db()).unwrap();
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": {
                "name": "rea_info",
                "arguments": { "path": path.to_str().unwrap() }
            }
        });
        let result = handle_tool_call(&msg).unwrap();
        let v: Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(v["format"], "sqlite");
        assert_eq!(v["arch"], "unknown");
        assert_eq!(v["sqlite"]["application_id"], 16909060);
        assert_eq!(v["sqlite"]["schema_objects"], 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rea_funcs_rejects_a_sqlite_target() {
        let path =
            std::env::temp_dir().join(format!("rea-mcp-sqlite-funcs-{}.db", std::process::id()));
        std::fs::write(&path, sqlite_db()).unwrap();
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 22,
            "method": "tools/call",
            "params": {
                "name": "rea_funcs",
                "arguments": { "path": path.to_str().unwrap() }
            }
        });
        let result = handle_tool_call(&msg).unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("no native code view"), "{text}");
        let _ = std::fs::remove_file(&path);
    }
}
