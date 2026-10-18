//! WebAssembly binary inspector. Parses imports, exports, the type count, function count, memory limits, table limits, data count, custom section names, and the start index. Does not decode function bodies, type signatures, element segments, data segments, custom payloads, or execute.

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
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WasmTable {
    /// `funcref`, `externref`, or `ref-{n}`.
    pub kind: String,
    pub min: u32,
    pub max: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WasmModule {
    pub version: u32,
    pub sections: Vec<u8>, // section ids in order
    pub imports: Vec<WasmImport>,
    pub exports: Vec<WasmExport>,
    /// Count of entries in the type section. Each signature is consumed and not stored.
    pub types: u32,
    /// Count of type indexes in the function section. The code section is not decoded.
    pub functions: u32,
    /// Memories declared in the memory section. Imported memories stay on `imports`.
    pub memories: Vec<WasmMemory>,
    /// Tables declared in the table section. Imported tables stay on `imports`.
    pub tables: Vec<WasmTable>,
    /// Start function index, when the start section is present.
    pub start: Option<u32>,
    /// Value from the data-count section. Data segments are not read.
    pub data_count: Option<u32>,
    /// Names of custom sections, in order. Bytes after each name are not read.
    pub customs: Vec<String>,
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
    let mut functions = 0;
    let mut memories = Vec::new();
    let mut tables = Vec::new();
    let mut start = None;
    let mut data_count = None;
    let mut customs = Vec::new();
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
            0 => customs.push(decode_custom_name(payload)?),
            1 => {
                if saw_types {
                    return Err(Error::Parse("duplicate wasm type section".into()));
                }
                saw_types = true;
                types = decode_type_count(payload)?;
            }
            2 => imports.extend(decode_imports(payload)?),
            3 => {
                if saw_functions {
                    return Err(Error::Parse("duplicate wasm function section".into()));
                }
                saw_functions = true;
                functions = decode_function_count(payload)?;
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
        functions,
        memories,
        tables,
        start,
        data_count,
        customs,
    })
}

fn decode_type_count(payload: &[u8]) -> Result<u32> {
    let mut r = Reader::new(payload);
    let count = r.read_u32_leb()?;
    for _ in 0..count {
        let _form = r.read_u8()?;
        let params = r.read_u32_leb()?;
        for _ in 0..params {
            let _valtype = r.read_u8()?;
        }
        let results = r.read_u32_leb()?;
        for _ in 0..results {
            let _valtype = r.read_u8()?;
        }
    }
    if !r.eof() {
        return Err(Error::Parse("trailing bytes in wasm type section".into()));
    }
    Ok(count)
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

fn decode_custom_name(payload: &[u8]) -> Result<String> {
    let mut r = Reader::new(payload);
    let len = r.read_u32_leb()? as usize;
    if len > 256 {
        return Err(Error::Parse("wasm custom name is too long".into()));
    }
    let bytes = r.read_bytes(len)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| Error::Parse("invalid utf-8 name".into()))
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

fn decode_function_count(payload: &[u8]) -> Result<u32> {
    let mut r = Reader::new(payload);
    let count = r.read_u32_leb()?;
    for _ in 0..count {
        let _type_index = r.read_u32_leb()?;
    }
    if !r.eof() {
        return Err(Error::Parse("trailing bytes in wasm function section".into()));
    }
    Ok(count)
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
        out.push(WasmMemory { min, max });
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

fn decode_imports(payload: &[u8]) -> Result<Vec<WasmImport>> {
    let mut r = Reader::new(payload);
    let count = r.read_u32_leb()?;
    let mut out = Vec::new();
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
            2 => ("mem", r.read_limits()?),
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
    Ok(out)
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

    fn read_name(&mut self) -> Result<String> {
        let len = self.read_u32_leb()? as usize;
        let bytes = self.read_bytes(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| Error::Parse("invalid utf-8 name".into()))
    }

    /// `flags`, `min`, and `max` when `flags & 1 != 0`. Returns `min`.
    fn read_limits(&mut self) -> Result<u32> {
        let flags = self.read_u8()?;
        let min = self.read_u32_leb()?;
        if flags & 1 != 0 {
            let _max = self.read_u32_leb()?;
        }
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
            }]
        );
        assert_eq!(m.start, Some(3));
        assert_eq!(m.functions, 0);
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
        // One function type: one i32 parameter and one i32 result. The signature is not stored.
        let m = inspect(&hex("0061736d0100000001060160017f017f")).unwrap();
        assert_eq!(m.sections, vec![1]);
        assert_eq!(m.types, 1);
        assert!(!format!("{m:?}").contains("7f"));
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
