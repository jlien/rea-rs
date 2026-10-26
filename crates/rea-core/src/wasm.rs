//! WebAssembly binary inspector. Parses imports, exports, type signatures, function
//! bodies as opcode names, element and data segments, and a capped custom payload.
//! Memory limits carry the shared flag, and imported memories keep their limits.
//! `execute` runs an exported function that stays inside i32 locals, with a step cap.
//! It does not provide WASI, and `execute` does not touch memory.

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WasmImport {
    pub module: String,
    pub name: String,
    pub kind: String,
    pub index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WasmExport {
    pub name: String,
    pub kind: String,
    pub index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WasmMemory {
    pub min: u32,
    pub max: Option<u32>,
    /// True when the limits carry the shared flag.
    pub shared: bool,
}

/// A memory import: module, name, and the imported limits.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WasmMemoryImport {
    pub module: String,
    pub name: String,
    pub memory: WasmMemory,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WasmTable {
    /// `funcref`, `externref`, or `ref-{n}`.
    pub kind: String,
    pub min: u32,
    pub max: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WasmFuncType {
    pub params: Vec<String>,
    pub results: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WasmBody {
    /// Opcode names, at most 64. `i32.const` includes its immediate.
    pub ops: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WasmElem {
    pub functions: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WasmData {
    /// Segment bytes, at most 256.
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WasmModule {
    pub version: u32,
    pub sections: Vec<u8>, // section ids in order
    pub imports: Vec<WasmImport>,
    pub exports: Vec<WasmExport>,
    /// Count of entries in the type section.
    pub types: u32,
    /// Function types from the type section. The count stays in `types`.
    pub signatures: Vec<WasmFuncType>,
    /// Type index of each defined function.
    pub func_types: Vec<u32>,
    /// Count of type indexes in the function section.
    pub functions: u32,
    /// Opcode listing of each code-section body. A body that does not fit is omitted.
    pub bodies: Vec<WasmBody>,
    /// Active element segments whose offset is `i32.const`. A segment that does not fit is omitted.
    pub elements: Vec<WasmElem>,
    /// Active data segments. Bytes are capped. A segment that does not fit is omitted.
    pub data: Vec<WasmData>,
    /// Memories declared in the memory section. Imported memories stay on `imports`
    /// and `imported_memories`.
    pub memories: Vec<WasmMemory>,
    /// Memories imported from the import section, in import order.
    pub imported_memories: Vec<WasmMemoryImport>,
    /// Tables declared in the table section. Imported tables stay on `imports`.
    pub tables: Vec<WasmTable>,
    /// Start function index, when the start section is present.
    pub start: Option<u32>,
    /// Value from the data-count section. Data segment bytes are on `data`.
    pub data_count: Option<u32>,
    /// Names of custom sections, in order.
    pub customs: Vec<String>,
    /// Bytes after each custom name, capped at 64. Aligned with `customs`.
    pub custom_payloads: Vec<Vec<u8>>,
}

/// Inspect a WebAssembly binary. Rejects a bad magic, a truncated section,
/// and an unsigned LEB128 that overflows `u32` or never terminates.
pub fn inspect(bytes: &[u8]) -> Result<WasmModule> {
    let mut r = Reader::new(bytes);
    let magic = r.read_bytes(4)?;
    if magic != b"\0asm" {
        return Err(Error::Parse("bad wasm magic".into()));
    }
    let ver = r.read_bytes(4)?;
    let version = u32::from_le_bytes([ver[0], ver[1], ver[2], ver[3]]);

    let mut sections = Vec::new();
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut types = 0;
    let mut signatures = Vec::new();
    let mut func_types = Vec::new();
    let mut functions = 0;
    let mut bodies = Vec::new();
    let mut elements = Vec::new();
    let mut data = Vec::new();
    let mut memories = Vec::new();
    let mut imported_memories = Vec::new();
    let mut tables = Vec::new();
    let mut start = None;
    let mut data_count = None;
    let mut customs = Vec::new();
    let mut custom_payloads = Vec::new();
    let mut saw_types = false;
    let mut saw_functions = false;
    let mut saw_memories = false;
    let mut saw_tables = false;
    let mut saw_start = false;
    let mut saw_data_count = false;

    while !r.eof() {
        let id = r.read_u8()?;
        let size = r.read_u32_leb()? as usize;
        let payload = r.read_bytes(size)?;
        sections.push(id);
        match id {
            0 => {
                let (name, payload) = decode_custom(payload)?;
                customs.push(name);
                custom_payloads.push(payload);
            }
            1 => {
                if saw_types {
                    return Err(Error::Parse("duplicate wasm type section".into()));
                }
                saw_types = true;
                let (count, sigs) = decode_types(payload)?;
                types = count;
                signatures = sigs;
            }
            2 => {
                let (imp, mem_imports) = decode_imports(payload)?;
                imports.extend(imp);
                imported_memories.extend(mem_imports);
            }
            3 => {
                if saw_functions {
                    return Err(Error::Parse("duplicate wasm function section".into()));
                }
                saw_functions = true;
                func_types = decode_func_types(payload)?;
                functions = func_types.len() as u32;
            }
            4 => {
                if saw_tables {
                    return Err(Error::Parse("duplicate wasm table section".into()));
                }
                saw_tables = true;
                tables = decode_tables(payload)?;
            }
            5 => {
                if saw_memories {
                    return Err(Error::Parse("duplicate wasm memory section".into()));
                }
                saw_memories = true;
                memories = decode_memories(payload)?;
            }
            7 => exports.extend(decode_exports(payload)?),
            9 => {
                if elements.is_empty() {
                    elements = decode_elements(payload).unwrap_or_default();
                }
            }
            10 => {
                if bodies.is_empty() {
                    bodies = decode_bodies(payload)?;
                }
            }
            11 => {
                if data.is_empty() {
                    data = decode_data(payload).unwrap_or_default();
                }
            }
            8 => {
                if saw_start {
                    return Err(Error::Parse("duplicate wasm start section".into()));
                }
                saw_start = true;
                start = Some(decode_start(payload)?);
            }
            12 => {
                if saw_data_count {
                    return Err(Error::Parse("duplicate wasm data count section".into()));
                }
                saw_data_count = true;
                data_count = Some(decode_data_count(payload)?);
            }
            _ => {}
        }
    }

    Ok(WasmModule {
        version,
        sections,
        imports,
        exports,
        types,
        signatures,
        func_types,
        functions,
        bodies,
        elements,
        data,
        memories,
        imported_memories,
        tables,
        start,
        data_count,
        customs,
        custom_payloads,
    })
}

/// Run one exported function. Only i32 locals and `i32.const`, `i32.add`,
/// `i32.sub`, `i32.mul`, `local.get`, `local.set`, `drop`, `call`, and `end`
/// are executed. The step cap is 4096. A host import or any other opcode is an error.
pub fn execute(bytes: &[u8], name: &str, args: &[i32]) -> Result<Vec<i32>> {
    let module = inspect(bytes)?;
    let export = module
        .exports
        .iter()
        .find(|item| item.name == name && item.kind == "func")
        .ok_or_else(|| Error::Parse(format!("wasm: export {name} is missing")))?;
    let imports = module
        .imports
        .iter()
        .filter(|item| item.kind == "func")
        .count() as u32;
    if export.index < imports {
        return Err(Error::Parse("wasm: imported function is not executed".into()));
    }
    let index = (export.index - imports) as usize;
    let ops = function_ops(bytes)?;
    let body = ops
        .get(index)
        .ok_or_else(|| Error::Parse("wasm: function body is missing".into()))?;
    interpret(body, args, &ops)
}

/// A WAT-flavored readability listing of what `inspect` decoded. Sections are
/// emitted in section order. It is not a full WAT writer: bodies are the same
/// capped opcode strings as `bodies`, an unknown opcode prints as `opcode 0xNN`,
/// and details that stay undecoded (element offsets, data offsets, global
/// valtypes) are not recovered.
pub fn wat(module: &WasmModule) -> String {
    let mut out = String::from("(module\n");
    let imported_funcs = module
        .imports
        .iter()
        .filter(|i| i.kind == "func")
        .count() as u32;
    let mut custom_i = 0usize;
    let mut mem_i = 0usize;
    for &id in &module.sections {
        match id {
            0 => {
                if let Some(name) = module.customs.get(custom_i) {
                    out.push_str(&format!("  ;; custom \"{name}\"\n"));
                }
                custom_i += 1;
            }
            1 => {
                for sig in &module.signatures {
                    out.push_str("  (type (func");
                    if !sig.params.is_empty() {
                        out.push_str(&format!(" (param {})", sig.params.join(" ")));
                    }
                    if !sig.results.is_empty() {
                        out.push_str(&format!(" (result {})", sig.results.join(" ")));
                    }
                    out.push_str("))\n");
                }
            }
            2 => {
                for imp in &module.imports {
                    let desc = match imp.kind.as_str() {
                        "func" => format!("(func (type {}))", imp.index),
                        "mem" => {
                            let limits = module.imported_memories.get(mem_i);
                            mem_i += 1;
                            format!(
                                "(memory {})",
                                limits
                                    .map(|m| limit_text(&m.memory))
                                    .unwrap_or_else(|| imp.index.to_string())
                            )
                        }
                        "table" => format!("(table {})", imp.index),
                        _ => "(global)".to_string(),
                    };
                    out.push_str(&format!(
                        "  (import \"{}\" \"{}\" {})\n",
                        imp.module, imp.name, desc
                    ));
                }
            }
            4 => {
                for table in &module.tables {
                    out.push_str(&format!("  (table {})\n", table_limits(table)));
                }
            }
            5 => {
                for memory in &module.memories {
                    out.push_str(&format!("  (memory {})\n", limit_text(memory)));
                }
            }
            7 => {
                for export in &module.exports {
                    out.push_str(&format!(
                        "  (export \"{}\" ({} {}))\n",
                        export.name, export.kind, export.index
                    ));
                }
            }
            8 => {
                if let Some(start) = module.start {
                    out.push_str(&format!("  (start {start})\n"));
                }
            }
            9 => {
                for elem in &module.elements {
                    let funcs: Vec<String> = elem.functions.iter().map(|f| f.to_string()).collect();
                    out.push_str(&format!("  (elem func {})\n", funcs.join(" ")));
                }
            }
            10 => {
                for (i, ty) in module.func_types.iter().enumerate() {
                    let index = imported_funcs + i as u32;
                    match module.bodies.get(i) {
                        Some(body) => {
                            out.push_str(&format!("  (func (;{index};) (type {ty})\n"));
                            for op in &body.ops {
                                let spelled = match op.strip_prefix("op-") {
                                    Some(hex) => format!("opcode 0x{hex}"),
                                    None => op.clone(),
                                };
                                out.push_str(&format!("    {spelled}\n"));
                            }
                            out.push_str("  )\n");
                        }
                        None => out.push_str(&format!("  (func (;{index};) (type {ty}))\n")),
                    }
                }
            }
            11 => {
                for segment in &module.data {
                    let bytes: Vec<String> =
                        segment.bytes.iter().map(|b| format!("{b:02x}")).collect();
                    out.push_str(&format!("  (data \"{}\")\n", bytes.join(" ")));
                }
            }
            _ => {}
        }
    }
    out.push(')');
    out
}

fn limit_text(memory: &WasmMemory) -> String {
    let mut text = match memory.max {
        Some(max) => format!("{} {max}", memory.min),
        None => memory.min.to_string(),
    };
    if memory.shared {
        text.push_str(" shared");
    }
    text
}

fn table_limits(table: &WasmTable) -> String {
    match table.max {
        Some(max) => format!("{} {max} {}", table.min, table.kind),
        None => format!("{} {}", table.min, table.kind),
    }
}

fn decode_types(payload: &[u8]) -> Result<(u32, Vec<WasmFuncType>)> {
    let mut r = Reader::new(payload);
    let count = r.read_u32_leb()?;
    let mut sigs = Vec::new();
    for _ in 0..count {
        let form = r.read_u8()?;
        let params = r.read_u32_leb()?;
        let mut param_names = Vec::new();
        for _ in 0..params {
            param_names.push(val_name(r.read_u8()?));
        }
        let results = r.read_u32_leb()?;
        let mut result_names = Vec::new();
        for _ in 0..results {
            result_names.push(val_name(r.read_u8()?));
        }
        if form == 0x60 {
            sigs.push(WasmFuncType {
                params: param_names,
                results: result_names,
            });
        }
    }
    if !r.eof() {
        return Err(Error::Parse("trailing bytes in wasm type section".into()));
    }
    Ok((count, sigs))
}

fn val_name(byte: u8) -> String {
    match byte {
        0x7f => "i32".to_string(),
        0x7e => "i64".to_string(),
        0x7d => "f32".to_string(),
        0x7c => "f64".to_string(),
        n => format!("val-{n}"),
    }
}

fn decode_data_count(payload: &[u8]) -> Result<u32> {
    let mut r = Reader::new(payload);
    let count = r.read_u32_leb()?;
    if !r.eof() {
        return Err(Error::Parse(
            "trailing bytes in wasm data count section".into(),
        ));
    }
    Ok(count)
}

fn decode_custom(payload: &[u8]) -> Result<(String, Vec<u8>)> {
    let mut r = Reader::new(payload);
    let len = r.read_u32_leb()? as usize;
    if len > 256 {
        return Err(Error::Parse("wasm custom name is too long".into()));
    }
    let bytes = r.read_bytes(len)?;
    let name = String::from_utf8(bytes.to_vec()).map_err(|_| Error::Parse("invalid utf-8 name".into()))?;
    let rest = payload.get(r.pos..).unwrap_or(&[]);
    let cap = rest.len().min(64);
    Ok((name, rest[..cap].to_vec()))
}

fn decode_tables(payload: &[u8]) -> Result<Vec<WasmTable>> {
    let mut r = Reader::new(payload);
    let count = r.read_u32_leb()?;
    let mut out = Vec::new();
    for _ in 0..count {
        let kind = ref_name(r.read_u8()?);
        let flags = r.read_u8()?;
        let min = r.read_u32_leb()?;
        let max = if flags & 1 != 0 {
            Some(r.read_u32_leb()?)
        } else {
            None
        };
        out.push(WasmTable { kind, min, max });
    }
    if !r.eof() {
        return Err(Error::Parse("trailing bytes in wasm table section".into()));
    }
    Ok(out)
}

fn ref_name(byte: u8) -> String {
    match byte {
        0x70 => "funcref".to_string(),
        0x6f => "externref".to_string(),
        n => format!("ref-{n}"),
    }
}

fn decode_func_types(payload: &[u8]) -> Result<Vec<u32>> {
    let mut r = Reader::new(payload);
    let count = r.read_u32_leb()?;
    let mut out = Vec::new();
    for _ in 0..count {
        out.push(r.read_u32_leb()?);
    }
    if !r.eof() {
        return Err(Error::Parse("trailing bytes in wasm function section".into()));
    }
    Ok(out)
}

#[derive(Clone)]
enum Op {
    Const(i32),
    Add,
    Sub,
    Mul,
    LocalGet(u32),
    LocalSet(u32),
    Drop,
    Call(u32),
    End,
    Other(u8),
}

fn decode_bodies(payload: &[u8]) -> Result<Vec<WasmBody>> {
    Ok(function_ops_from(payload)?
        .into_iter()
        .map(|ops| WasmBody {
            ops: ops.iter().take(64).map(op_text).collect(),
        })
        .collect())
}

fn function_ops(bytes: &[u8]) -> Result<Vec<Vec<Op>>> {
    let mut r = Reader::new(bytes);
    let magic = r.read_bytes(4)?;
    if magic != b"\0asm" {
        return Err(Error::Parse("bad wasm magic".into()));
    }
    let _ver = r.read_bytes(4)?;
    while !r.eof() {
        let id = r.read_u8()?;
        let size = r.read_u32_leb()? as usize;
        let payload = r.read_bytes(size)?;
        if id == 10 {
            return function_ops_from(payload);
        }
    }
    Ok(Vec::new())
}

fn function_ops_from(payload: &[u8]) -> Result<Vec<Vec<Op>>> {
    let mut r = Reader::new(payload);
    let count = r.read_u32_leb()?;
    let mut out = Vec::new();
    for _ in 0..count {
        let size = r.read_u32_leb()? as usize;
        let body = r.read_bytes(size)?;
        out.push(decode_one_body(body)?);
    }
    if !r.eof() {
        return Err(Error::Parse("trailing bytes in wasm code section".into()));
    }
    Ok(out)
}

fn decode_one_body(body: &[u8]) -> Result<Vec<Op>> {
    let mut r = Reader::new(body);
    let groups = r.read_u32_leb()?;
    for _ in 0..groups {
        let _n = r.read_u32_leb()?;
        let _ty = r.read_u8()?;
    }
    let mut ops = Vec::new();
    while !r.eof() && ops.len() < 64 {
        let op = r.read_u8()?;
        let decoded = match op {
            0x0b => Op::End,
            0x1a => Op::Drop,
            0x10 => Op::Call(r.read_u32_leb()?),
            0x20 => Op::LocalGet(r.read_u32_leb()?),
            0x21 => Op::LocalSet(r.read_u32_leb()?),
            0x41 => Op::Const(r.read_i32_leb()?),
            0x6a => Op::Add,
            0x6b => Op::Sub,
            0x6c => Op::Mul,
            other => Op::Other(other),
        };
        let done = matches!(decoded, Op::End);
        ops.push(decoded);
        if done {
            break;
        }
    }
    Ok(ops)
}

fn op_text(op: &Op) -> String {
    match op {
        Op::Const(n) => format!("i32.const {n}"),
        Op::Add => "i32.add".into(),
        Op::Sub => "i32.sub".into(),
        Op::Mul => "i32.mul".into(),
        Op::LocalGet(n) => format!("local.get {n}"),
        Op::LocalSet(n) => format!("local.set {n}"),
        Op::Drop => "drop".into(),
        Op::Call(n) => format!("call {n}"),
        Op::End => "end".into(),
        Op::Other(n) => format!("op-{n:02x}"),
    }
}

fn decode_elements(payload: &[u8]) -> Result<Vec<WasmElem>> {
    let mut r = Reader::new(payload);
    let count = r.read_u32_leb()?;
    let mut out = Vec::new();
    for _ in 0..count {
        let flags = r.read_u32_leb()?;
        if flags != 0 {
            return Err(Error::Parse("wasm element flags are unread".into()));
        }
        skip_i32_offset(&mut r)?;
        let n = r.read_u32_leb()?;
        let mut functions = Vec::new();
        for _ in 0..n {
            functions.push(r.read_u32_leb()?);
        }
        out.push(WasmElem { functions });
    }
    if !r.eof() {
        return Err(Error::Parse("trailing bytes in wasm element section".into()));
    }
    Ok(out)
}

fn decode_data(payload: &[u8]) -> Result<Vec<WasmData>> {
    let mut r = Reader::new(payload);
    let count = r.read_u32_leb()?;
    let mut out = Vec::new();
    for _ in 0..count {
        let flags = r.read_u32_leb()?;
        if flags != 0 {
            return Err(Error::Parse("wasm data flags are unread".into()));
        }
        skip_i32_offset(&mut r)?;
        let n = r.read_u32_leb()? as usize;
        let bytes = r.read_bytes(n)?;
        let cap = bytes.len().min(256);
        out.push(WasmData {
            bytes: bytes[..cap].to_vec(),
        });
    }
    if !r.eof() {
        return Err(Error::Parse("trailing bytes in wasm data section".into()));
    }
    Ok(out)
}

fn skip_i32_offset(r: &mut Reader<'_>) -> Result<()> {
    let op = r.read_u8()?;
    if op != 0x41 {
        return Err(Error::Parse("wasm offset is not i32.const".into()));
    }
    let _value = r.read_i32_leb()?;
    let end = r.read_u8()?;
    if end != 0x0b {
        return Err(Error::Parse("wasm offset expression does not end".into()));
    }
    Ok(())
}

fn interpret(ops: &[Op], args: &[i32], all: &[Vec<Op>]) -> Result<Vec<i32>> {
    interpret_depth(ops, args, all, 0)
}

fn interpret_depth(ops: &[Op], args: &[i32], all: &[Vec<Op>], depth: u32) -> Result<Vec<i32>> {
    if depth > 8 {
        return Err(Error::Parse("wasm: call depth exceeded".into()));
    }
    let mut locals = args.to_vec();
    let mut stack = Vec::new();
    let mut steps = 0u32;
    for op in ops {
        steps += 1;
        if steps > 4096 {
            return Err(Error::Parse("wasm: step cap exceeded".into()));
        }
        match op {
            Op::Const(n) => stack.push(*n),
            Op::Add => {
                let b = pop(&mut stack)?;
                let a = pop(&mut stack)?;
                stack.push(a.wrapping_add(b));
            }
            Op::Sub => {
                let b = pop(&mut stack)?;
                let a = pop(&mut stack)?;
                stack.push(a.wrapping_sub(b));
            }
            Op::Mul => {
                let b = pop(&mut stack)?;
                let a = pop(&mut stack)?;
                stack.push(a.wrapping_mul(b));
            }
            Op::LocalGet(n) => {
                let value = locals.get(*n as usize).copied().ok_or_else(|| {
                    Error::Parse("wasm: local is missing".into())
                })?;
                stack.push(value);
            }
            Op::LocalSet(n) => {
                let value = pop(&mut stack)?;
                let index = *n as usize;
                if index >= locals.len() {
                    locals.resize(index + 1, 0);
                }
                locals[index] = value;
            }
            Op::Drop => {
                pop(&mut stack)?;
            }
            Op::Call(n) => {
                let callee = all.get(*n as usize).ok_or_else(|| {
                    Error::Parse("wasm: call target is missing".into())
                })?;
                let arity = 0;
                let _ = arity;
                let returned = interpret_depth(callee, &[], all, depth + 1)?;
                stack.extend(returned);
            }
            Op::End => break,
            Op::Other(n) => {
                return Err(Error::Parse(format!("wasm: opcode {n:#x} is not executed")));
            }
        }
    }
    Ok(stack)
}

fn pop(stack: &mut Vec<i32>) -> Result<i32> {
    stack
        .pop()
        .ok_or_else(|| Error::Parse("wasm: stack is empty".into()))
}

fn decode_memories(payload: &[u8]) -> Result<Vec<WasmMemory>> {
    let mut r = Reader::new(payload);
    let count = r.read_u32_leb()?;
    let mut out = Vec::new();
    for _ in 0..count {
        let flags = r.read_u8()?;
        let min = r.read_u32_leb()?;
        let max = if flags & 1 != 0 {
            Some(r.read_u32_leb()?)
        } else {
            None
        };
        let shared = flags & 2 != 0;
        out.push(WasmMemory { min, max, shared });
    }
    if !r.eof() {
        return Err(Error::Parse("trailing bytes in wasm memory section".into()));
    }
    Ok(out)
}

fn decode_start(payload: &[u8]) -> Result<u32> {
    let mut r = Reader::new(payload);
    let index = r.read_u32_leb()?;
    if !r.eof() {
        return Err(Error::Parse("trailing bytes in wasm start section".into()));
    }
    Ok(index)
}

fn decode_imports(payload: &[u8]) -> Result<(Vec<WasmImport>, Vec<WasmMemoryImport>)> {
    let mut r = Reader::new(payload);
    let count = r.read_u32_leb()?;
    let mut out = Vec::new();
    let mut memories = Vec::new();
    for _ in 0..count {
        let module = r.read_name()?;
        let name = r.read_name()?;
        let kind_byte = r.read_u8()?;
        let (kind, index) = match kind_byte {
            0 => ("func", r.read_u32_leb()?),
            1 => {
                let _elemtype = r.read_u8()?;
                ("table", r.read_limits()?)
            }
            2 => {
                let (min, max, shared) = r.read_limits_full()?;
                memories.push(WasmMemoryImport {
                    module: module.clone(),
                    name: name.clone(),
                    memory: WasmMemory { min, max, shared },
                });
                ("mem", min)
            }
            3 => {
                let _valtype = r.read_u8()?;
                let _mutable = r.read_u8()?;
                ("global", 0)
            }
            other => {
                return Err(Error::Parse(format!("unknown wasm import kind {other}")));
            }
        };
        out.push(WasmImport {
            module,
            name,
            kind: kind.to_string(),
            index,
        });
    }
    if !r.eof() {
        return Err(Error::Parse("trailing bytes in wasm import section".into()));
    }
    Ok((out, memories))
}

fn decode_exports(payload: &[u8]) -> Result<Vec<WasmExport>> {
    let mut r = Reader::new(payload);
    let count = r.read_u32_leb()?;
    let mut out = Vec::new();
    for _ in 0..count {
        let name = r.read_name()?;
        let kind_byte = r.read_u8()?;
        let kind = match kind_byte {
            0 => "func",
            1 => "table",
            2 => "mem",
            3 => "global",
            other => {
                return Err(Error::Parse(format!("unknown wasm export kind {other}")));
            }
        };
        let index = r.read_u32_leb()?;
        out.push(WasmExport {
            name,
            kind: kind.to_string(),
            index,
        });
    }
    if !r.eof() {
        return Err(Error::Parse("trailing bytes in wasm export section".into()));
    }
    Ok(out)
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn eof(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(Error::Parse("truncated wasm".into()));
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| Error::Parse("truncated wasm".into()))?;
        if end > self.data.len() {
            return Err(Error::Parse("truncated wasm".into()));
        }
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// Unsigned LEB128 limited to `u32`. A continuation past 5 bytes, or a
    /// value that does not fit in `u32`, is overflow. EOF mid-sequence is
    /// an unterminated encoding.
    fn read_u32_leb(&mut self) -> Result<u32> {
        let mut value: u64 = 0;
        let mut shift = 0;
        for _ in 0..5 {
            let byte = self
                .read_u8()
                .map_err(|_| Error::Parse("unterminated leb128".into()))?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                if value > u64::from(u32::MAX) {
                    return Err(Error::Parse("leb128 overflow".into()));
                }
                return Ok(value as u32);
            }
            shift += 7;
        }
        Err(Error::Parse("leb128 overflow".into()))
    }

    /// Signed LEB128 limited to `i32`. A continuation past 5 bytes is overflow.
    fn read_i32_leb(&mut self) -> Result<i32> {
        let mut result: i64 = 0;
        let mut shift = 0;
        for _ in 0..5 {
            let byte = self
                .read_u8()
                .map_err(|_| Error::Parse("unterminated leb128".into()))?;
            result |= i64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 32 && byte & 0x40 != 0 {
                    result |= !0i64 << shift;
                }
                if result < i64::from(i32::MIN) || result > i64::from(i32::MAX) {
                    return Err(Error::Parse("leb128 overflow".into()));
                }
                return Ok(result as i32);
            }
        }
        Err(Error::Parse("leb128 overflow".into()))
    }

    fn read_name(&mut self) -> Result<String> {
        let len = self.read_u32_leb()? as usize;
        let bytes = self.read_bytes(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| Error::Parse("invalid utf-8 name".into()))
    }

    /// `flags`, `min`, and `max` when `flags & 1 != 0`; `flags & 2` is the
    /// shared flag. Returns `(min, max, shared)`.
    fn read_limits_full(&mut self) -> Result<(u32, Option<u32>, bool)> {
        let flags = self.read_u8()?;
        let min = self.read_u32_leb()?;
        let max = if flags & 1 != 0 {
            Some(self.read_u32_leb()?)
        } else {
            None
        };
        Ok((min, max, flags & 2 != 0))
    }

    /// `flags`, `min`, and `max` when `flags & 1 != 0`. Returns `min`.
    fn read_limits(&mut self) -> Result<u32> {
        let (min, _max, _shared) = self.read_limits_full()?;
        Ok(min)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "odd hex length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn empty_module_is_version_one() {
        let m = inspect(&hex("0061736d01000000")).unwrap();
        assert_eq!(m.version, 1);
        assert!(m.sections.is_empty());
        assert!(m.imports.is_empty());
        assert!(m.exports.is_empty());
        assert_eq!(m.types, 0);
        assert_eq!(m.functions, 0);
        assert!(m.memories.is_empty());
        assert!(m.tables.is_empty());
        assert_eq!(m.start, None);
        assert_eq!(m.data_count, None);
        assert!(m.customs.is_empty());
    }

    #[test]
    fn export_func_and_section_ids() {
        let m = inspect(&hex(
            "0061736d0100000001040160000003020100070501016600000a040102000b",
        ))
        .unwrap();
        assert_eq!(m.version, 1);
        assert_eq!(m.sections, vec![1, 3, 7, 10]);
        assert_eq!(m.types, 1);
        assert_eq!(m.functions, 1);
        assert_eq!(m.bodies.len(), 1);
        assert_eq!(m.bodies[0].ops, vec!["end".to_string()]);
        assert_eq!(m.data_count, None);
        assert!(m.customs.is_empty());
        assert!(m.imports.is_empty());
        assert_eq!(
            m.exports,
            vec![WasmExport {
                name: "f".into(),
                kind: "func".into(),
                index: 0,
            }]
        );
    }

    #[test]
    fn import_func_env_m() {
        let m = inspect(&hex("0061736d0100000002090103656e76016d0000")).unwrap();
        assert_eq!(m.sections, vec![2]);
        assert!(m.exports.is_empty());
        assert_eq!(
            m.imports,
            vec![WasmImport {
                module: "env".into(),
                name: "m".into(),
                kind: "func".into(),
                index: 0,
            }]
        );
    }

    #[test]
    fn import_table_mem_global_consume_desc() {
        // Two imports: memory with a max limit, then a function. Missing the
        // max would desync the second import.
        let mem_then_func = hex("0061736d01000000020f020165016d02010102016501660007");
        let m = inspect(&mem_then_func).unwrap();
        assert_eq!(
            m.imports,
            vec![
                WasmImport {
                    module: "e".into(),
                    name: "m".into(),
                    kind: "mem".into(),
                    index: 1,
                },
                WasmImport {
                    module: "e".into(),
                    name: "f".into(),
                    kind: "func".into(),
                    index: 7,
                },
            ]
        );

        // Table: elemtype + limits (min only). Index is the min limit.
        let table = inspect(&hex("0061736d010000000209010165017401700001")).unwrap();
        assert_eq!(table.imports[0].kind, "table");
        assert_eq!(table.imports[0].index, 1);
        assert!(table.tables.is_empty());

        // Global: consume valtype and mut, record index 0.
        let global = inspect(&hex("0061736d01000000020e0201650167037f01016501660005")).unwrap();
        assert_eq!(global.imports[0].kind, "global");
        assert_eq!(global.imports[0].index, 0);
        assert_eq!(global.imports[1].kind, "func");
        assert_eq!(global.imports[1].index, 5);
    }

    #[test]
    fn export_kinds() {
        // name "t", kind table, index 3
        let m = inspect(&hex("0061736d0100000007050101740103")).unwrap();
        assert_eq!(
            m.exports,
            vec![WasmExport {
                name: "t".into(),
                kind: "table".into(),
                index: 3,
            }]
        );
    }

    #[test]
    fn memory_limits_and_start_index() {
        let m = inspect(&hex("0061736d01000000050401010102080103")).unwrap();
        assert_eq!(m.sections, vec![5, 8]);
        assert_eq!(
            m.memories,
            vec![WasmMemory {
                min: 1,
                max: Some(2),
                shared: false,
            }]
        );
        assert_eq!(m.start, Some(3));
        assert_eq!(m.functions, 0);
    }

    #[test]
    fn memory_shared_flag_and_imported_memory() {
        // One shared memory: flags 0x03 = has-max + shared.
        let m = inspect(&hex("0061736d01000000050401030102")).unwrap();
        assert_eq!(
            m.memories,
            vec![WasmMemory {
                min: 1,
                max: Some(2),
                shared: true,
            }]
        );

        // Min-only memory is not shared.
        let plain = inspect(&hex("0061736d010000000503010005")).unwrap();
        assert_eq!(plain.memories[0].shared, false);
        assert_eq!(plain.memories[0].max, None);

        // An imported memory keeps module, name, and its limits with the shared flag.
        let imported = inspect(&hex("0061736d010000000209010165016d02030204")).unwrap();
        assert_eq!(imported.imports[0].kind, "mem");
        assert_eq!(imported.imports[0].index, 2);
        assert!(imported.memories.is_empty());
        assert_eq!(
            imported.imported_memories,
            vec![WasmMemoryImport {
                module: "e".into(),
                name: "m".into(),
                memory: WasmMemory {
                    min: 2,
                    max: Some(4),
                    shared: true,
                },
            }]
        );
    }

    #[test]
    fn wat_lists_types_functions_and_exports() {
        let bytes = hex("0061736d010000000105016000017f03020100070501016600000a06010400412a0b");
        let text = wat(&inspect(&bytes).unwrap());
        assert!(text.starts_with("(module\n"));
        assert!(text.contains("  (type (func (result i32)))\n"));
        assert!(text.contains("  (func (;0;) (type 0)\n    i32.const 42\n    end\n  )\n"));
        assert!(text.contains("  (export \"f\" (func 0))\n"));
        assert!(text.ends_with(")"));
    }

    #[test]
    fn wat_lists_imported_shared_memory() {
        let m = inspect(&hex("0061736d010000000209010165016d02030204")).unwrap();
        let text = wat(&m);
        assert!(text.contains("  (import \"e\" \"m\" (memory 2 4 shared))\n"));
    }

    #[test]
    fn wat_passes_unknown_opcodes_through() {
        // Body: local group count 0, i32.const 42, opcode 0x28, end. The unknown
        // opcode carries no decoded immediate, so the next byte is its own opcode.
        let m = inspect(&hex("0061736d01000000010401600000030201000a07010500412a280b")).unwrap();
        assert_eq!(m.bodies[0].ops[1], "op-28");
        let text = wat(&m);
        assert!(text.contains("    opcode 0x28\n"));
    }

    #[test]
    fn table_limits_leave_the_element_section_unread() {
        // Section 4: funcref min 1 max 4, externref min 2. Section 9 is present and ignored.
        let m = inspect(&hex("0061736d01000000040802700101046f00020903010000")).unwrap();
        assert_eq!(m.sections, vec![4, 9]);
        assert_eq!(
            m.tables,
            vec![
                WasmTable {
                    kind: "funcref".into(),
                    min: 1,
                    max: Some(4),
                },
                WasmTable {
                    kind: "externref".into(),
                    min: 2,
                    max: None,
                },
            ]
        );
        let elem = inspect(&hex("0061736d010000000903010000")).unwrap();
        assert_eq!(elem.sections, vec![9]);
        assert!(elem.tables.is_empty());
    }

    #[test]
    fn type_count_consumes_the_signature() {
        // One function type: one i32 parameter and one i32 result. The raw byte is not stored.
        let m = inspect(&hex("0061736d0100000001060160017f017f")).unwrap();
        assert_eq!(m.sections, vec![1]);
        assert_eq!(m.types, 1);
        assert_eq!(m.signatures[0].params, vec!["i32".to_string()]);
        assert_eq!(m.signatures[0].results, vec!["i32".to_string()]);
        assert!(!format!("{m:?}").contains("7f"));
    }

    #[test]
    fn execute_returns_an_i32_constant() {
        let bytes = hex("0061736d010000000105016000017f03020100070501016600000a06010400412a0b");
        let module = inspect(&bytes).unwrap();
        assert_eq!(module.bodies[0].ops, vec!["i32.const 42".to_string(), "end".to_string()]);
        assert_eq!(execute(&bytes, "f", &[]).unwrap(), vec![42]);
    }

    #[test]
    fn element_and_data_segments_keep_their_payloads() {
        let elements = inspect(&hex("0061736d010000000907010041000b0102")).unwrap();
        assert_eq!(elements.elements[0].functions, vec![2]);
        let data = inspect(&hex("0061736d010000000b08010041000b02abcd")).unwrap();
        assert_eq!(data.data[0].bytes, vec![0xab, 0xcd]);
        let ignored = inspect(&hex("0061736d010000000903010000")).unwrap();
        assert!(ignored.elements.is_empty());
    }

    #[test]
    fn duplicate_type_is_an_error() {
        let err = inspect(&hex("0061736d01000000010401600000010401600000")).unwrap_err();
        assert!(matches!(err, Error::Parse(ref msg) if msg == "duplicate wasm type section"));
    }

    #[test]
    fn data_count_ignores_the_data_section() {
        let m = inspect(&hex("0061736d010000000b01000c0104")).unwrap();
        assert_eq!(m.sections, vec![11, 12]);
        assert_eq!(m.data_count, Some(4));
    }

    #[test]
    fn duplicate_data_count_is_an_error() {
        let err = inspect(&hex("0061736d010000000c01010c0102")).unwrap_err();
        assert!(matches!(err, Error::Parse(ref msg) if msg == "duplicate wasm data count section"));
    }

    #[test]
    fn custom_names_leave_the_payload_unread() {
        let m = inspect(&hex("0061736d010000000006046e616d659900020178")).unwrap();
        assert_eq!(m.sections, vec![0, 0]);
        assert_eq!(m.customs, vec!["name".to_string(), "x".to_string()]);
        assert_eq!(m.custom_payloads[0], vec![0x99]);
        assert!(!format!("{m:?}").contains("99"));
    }

    #[test]
    fn custom_name_too_long_is_an_error() {
        let err = inspect(&hex("0061736d0100000000028102")).unwrap_err();
        assert!(matches!(err, Error::Parse(ref msg) if msg == "wasm custom name is too long"));
    }

    #[test]
    fn duplicate_table_is_an_error() {
        let err = inspect(&hex("0061736d01000000040401700000040401700001")).unwrap_err();
        assert!(matches!(err, Error::Parse(ref msg) if msg == "duplicate wasm table section"));
    }

    #[test]
    fn duplicate_start_is_an_error() {
        let err = inspect(&hex("0061736d01000000080103080104")).unwrap_err();
        assert!(matches!(err, Error::Parse(ref msg) if msg == "duplicate wasm start section"));
    }

    #[test]
    fn rejects_bad_magic_truncated_and_bad_leb() {
        assert!(inspect(&hex("0061736e01000000")).is_err());
        assert!(inspect(&[]).is_err());
        // section id 1, declared size 5, no payload
        assert!(inspect(&hex("0061736d010000000105")).is_err());
        // section size LEB continues and the buffer ends
        assert!(inspect(&hex("0061736d010000000180")).is_err());
        // fifth LEB byte does not fit in u32
        assert!(inspect(&hex("0061736d01000000018080808010")).is_err());
        // version other than 1 is still accepted
        let m = inspect(&hex("0061736d02000000")).unwrap();
        assert_eq!(m.version, 2);
    }
}
