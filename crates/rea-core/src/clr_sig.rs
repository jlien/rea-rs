//! ECMA-335 method signatures and a capped IL opcode listing.
//!
//! A blob that does not fit this grammar is omitted. It does not fail the PE parse.

/// Bytes of one `#Blob` entry. Index 0 is empty. The entry starts with a compressed length.
pub fn blob_bytes(heap: &[u8], index: u32) -> Option<&[u8]> {
    if index == 0 {
        return None;
    }
    let start = index as usize;
    if start >= heap.len() {
        return None;
    }
    let (len, n) = compressed(heap, start)?;
    let body = start + n;
    let end = body.checked_add(len as usize)?;
    heap.get(body..end)
}

/// `ret(params)` for a MethodDef or MemberRef signature. A field signature (`0x06`) is `field type`.
pub fn method_sig(heap: &[u8], index: u32) -> Option<String> {
    let bytes = blob_bytes(heap, index)?;
    let mut at = 0;
    let conv = *bytes.get(at)?;
    at += 1;
    if conv == 0x06 {
        let (ty, _) = sig_type(bytes, at, 0)?;
        return Some(format!("field {ty}"));
    }
    if conv & 0x10 != 0 {
        let (_, n) = compressed(bytes, at)?;
        at += n;
    }
    let (count, n) = compressed(bytes, at)?;
    at += n;
    let (ret, n) = sig_type(bytes, at, 0)?;
    at += n;
    let mut params = Vec::new();
    for _ in 0..count {
        let (ty, n) = sig_type(bytes, at, 0)?;
        at += n;
        params.push(ty);
    }
    Some(format!("{ret}({})", params.join(", ")))
}

/// `type(index-params)` for a Property signature per ECMA-335 II.23.2.5:
/// `PROPERTY HASTHIS? ParamCount Type Param*` — `ParamCount` is the number of
/// index parameters. Both `0x08` (static) and `0x28` (instance) decode.
pub fn property_sig(heap: &[u8], index: u32) -> Option<String> {
    let bytes = blob_bytes(heap, index)?;
    let conv = *bytes.first()?;
    // PROPERTY (0x08) or PROPERTY|HASTHIS (0x28) only; 0x18 (PROPERTY|GENERIC)
    // is not a property convention (GENERIC is 0x10).
    if conv & 0x0f != 0x08 || conv & 0x10 != 0 {
        return None;
    }
    let (count, n) = compressed(bytes, 1)?;
    let mut at = 1 + n;
    let (ty, n) = sig_type(bytes, at, 0)?;
    at += n;
    let mut indexes = Vec::new();
    for _ in 0..count {
        let (param, n) = sig_type(bytes, at, 0)?;
        at += n;
        indexes.push(param);
    }
    Some(format!("{ty}({})", indexes.join(", ")))
}

/// Opcode names from a tiny or fat method body. At most 48 instructions.
/// An unmapped or truncated body is empty.
pub fn il_ops(bytes: &[u8]) -> Vec<String> {
    let Some((code, _size)) = il_code(bytes) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut at = 0;
    while at < code.len() && out.len() < 48 {
        let op = code[at];
        at += 1;
        let Some(name) = opcode(op) else {
            out.push(format!("op-{op:02x}"));
            break;
        };
        if name == "ldc.i4" {
            if at + 4 > code.len() {
                break;
            }
            let value = i32::from_le_bytes([code[at], code[at + 1], code[at + 2], code[at + 3]]);
            at += 4;
            out.push(format!("ldc.i4 {value}"));
            continue;
        }
        if matches!(name, "ldc.i4.s" | "ldarg.s" | "ldloc.s" | "stloc.s") {
            let Some(imm) = code.get(at).copied() else {
                break;
            };
            at += 1;
            out.push(format!("{name} {imm}"));
            continue;
        }
        out.push(name.to_string());
        if name == "ret" {
            break;
        }
    }
    out
}

fn il_code(bytes: &[u8]) -> Option<(&[u8], usize)> {
    let b0 = *bytes.first()?;
    if b0 & 0x3 == 0x2 {
        let size = (b0 >> 2) as usize;
        let code = bytes.get(1..1 + size)?;
        return Some((code, size));
    }
    if b0 & 0x3 == 0x3 && bytes.len() >= 12 {
        let header_dwords = (bytes[1] >> 4) as usize;
        let header = header_dwords.saturating_mul(4).max(12);
        let size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let code = bytes.get(header..header + size)?;
        return Some((code, size));
    }
    None
}

fn opcode(op: u8) -> Option<&'static str> {
    Some(match op {
        0x00 => "nop",
        0x02 => "ldarg.0",
        0x03 => "ldarg.1",
        0x04 => "ldarg.2",
        0x05 => "ldarg.3",
        0x06 => "ldloc.0",
        0x07 => "ldloc.1",
        0x08 => "ldloc.2",
        0x09 => "ldloc.3",
        0x0a => "stloc.0",
        0x0b => "stloc.1",
        0x0e => "ldarg.s",
        0x11 => "ldloc.s",
        0x13 => "stloc.s",
        0x14 => "ldnull",
        0x16 => "ldc.i4.0",
        0x17 => "ldc.i4.1",
        0x18 => "ldc.i4.2",
        0x19 => "ldc.i4.3",
        0x1a => "ldc.i4.4",
        0x1b => "ldc.i4.5",
        0x1c => "ldc.i4.6",
        0x1d => "ldc.i4.7",
        0x1e => "ldc.i4.8",
        0x1f => "ldc.i4.m1",
        0x20 => "ldc.i4.s",
        0x21 => "ldc.i4",
        0x2a => "ret",
        0x58 => "add",
        0x59 => "sub",
        0x5a => "mul",
        0x5b => "div",
        0x5f => "and",
        0x60 => "or",
        0x61 => "xor",
        _ => return None,
    })
}

fn compressed(bytes: &[u8], at: usize) -> Option<(u32, usize)> {
    let b0 = *bytes.get(at)?;
    if b0 & 0x80 == 0 {
        return Some((u32::from(b0), 1));
    }
    if b0 & 0xc0 == 0x80 {
        let b1 = *bytes.get(at + 1)?;
        return Some(((u32::from(b0 & 0x3f) << 8) | u32::from(b1), 2));
    }
    if b0 & 0xe0 == 0xc0 {
        let raw = bytes.get(at..at + 4)?;
        let value = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) & 0x1fff_ffff;
        return Some((value, 4));
    }
    None
}

fn sig_type(bytes: &[u8], at: usize, depth: u32) -> Option<(String, usize)> {
    // Nested ptr/byref/szarray wrappers recurse; cap the depth so a hostile
    // blob of thousands of `0x0f` bytes cannot overflow the stack.
    if depth > 64 {
        return None;
    }
    let tag = *bytes.get(at)?;
    let name = match tag {
        0x01 => "void",
        0x02 => "bool",
        0x03 => "char",
        0x04 => "int8",
        0x05 => "uint8",
        0x06 => "int16",
        0x07 => "uint16",
        0x08 => "int32",
        0x09 => "uint32",
        0x0a => "int64",
        0x0b => "uint64",
        0x0c => "float32",
        0x0d => "float64",
        0x0e => "string",
        0x18 => "intptr",
        0x19 => "uintptr",
        0x1c => "object",
        0x0f | 0x10 => {
            let (inner, n) = sig_type(bytes, at + 1, depth + 1)?;
            let prefix = if tag == 0x0f { "ptr" } else { "byref" };
            return Some((format!("{prefix} {inner}"), 1 + n));
        }
        0x1d => {
            let (inner, n) = sig_type(bytes, at + 1, depth + 1)?;
            return Some((format!("{inner}[]"), 1 + n));
        }
        0x11 | 0x12 => {
            let (coded, n) = compressed(bytes, at + 1)?;
            let row = coded >> 2;
            let kind = match coded & 0x3 {
                0 => "typedef",
                1 => "typeref",
                _ => "typespec",
            };
            let prefix = if tag == 0x11 { "valuetype" } else { "class" };
            return Some((format!("{prefix} {kind}-{row}"), 1 + n));
        }
        _ => return None,
    };
    Some((name.to_string(), 1))
}

#[cfg(test)]
mod tests {
    use super::{il_ops, method_sig, property_sig};

    #[test]
    fn method_signature_is_return_and_params() {
        // index 1: length 4, default call, one int32 param, void return
        let heap = [0x00, 0x04, 0x00, 0x01, 0x01, 0x08];
        assert_eq!(method_sig(&heap, 1).as_deref(), Some("void(int32)"));
        assert_eq!(method_sig(&heap, 0), None);
    }

    #[test]
    fn tiny_body_lists_ldarg_and_ret() {
        // codesize 2, ldarg.0, ret
        assert_eq!(il_ops(&[0x0a, 0x02, 0x2a]), vec!["ldarg.0".to_string(), "ret".to_string()]);
        assert!(il_ops(&[0x00]).is_empty());
    }

    #[test]
    fn property_signature_is_type_and_index_params() {
        // ECMA-335 II.23.2.5: PROPERTY HASTHIS? ParamCount Type Param*.
        // length 3, static property, count 0 index params, int32.
        let heap = [0x00, 0x03, 0x08, 0x00, 0x08];
        assert_eq!(property_sig(&heap, 1).as_deref(), Some("int32()"));
        // The same blob with HASTHIS (instance property) decodes identically.
        let heap = [0x00, 0x03, 0x28, 0x00, 0x08];
        assert_eq!(property_sig(&heap, 1).as_deref(), Some("int32()"));
        // count 1: static int32 this[int16].
        let heap = [0x00, 0x04, 0x08, 0x01, 0x08, 0x06];
        assert_eq!(property_sig(&heap, 1).as_deref(), Some("int32(int16)"));
        // Instance indexer decodes the same way.
        let heap = [0x00, 0x04, 0x28, 0x01, 0x08, 0x06];
        assert_eq!(property_sig(&heap, 1).as_deref(), Some("int32(int16)"));
        // A method convention or blob index 0 is not a property signature.
        let method = [0x00, 0x04, 0x00, 0x01, 0x01, 0x08];
        assert_eq!(property_sig(&method, 1), None);
        assert_eq!(property_sig(&heap, 0), None);
    }

    #[test]
    fn a_deeply_nested_signature_does_not_overflow_the_stack() {
        // Heap: empty index 0, then a property blob of 7000 nested ptr
        // wrappers around int32. Before the depth cap this aborted with a
        // stack overflow (exit 134); now it is simply unread past 64.
        let mut blob = vec![0x08u8, 0x00]; // PROPERTY, index-param count 0
        for _ in 0..7000 {
            blob.push(0x0f);
        }
        blob.push(0x08); // int32
        let mut heap = vec![0x00u8]; // blob index 0 is empty
        let len = blob.len();
        if len < 0x80 {
            heap.push(len as u8);
        } else {
            heap.push(0x80 | (len >> 8) as u8);
            heap.push(len as u8);
        }
        heap.extend_from_slice(&blob);
        assert_eq!(property_sig(&heap, 1), None);

        // Just under the cap still decodes: 60 nested ptr around int32.
        let mut blob = vec![0x08u8, 0x00];
        for _ in 0..60 {
            blob.push(0x0f);
        }
        blob.push(0x08);
        let mut heap = vec![0x00u8, blob.len() as u8];
        heap.extend_from_slice(&blob);
        assert!(property_sig(&heap, 1).is_some());
    }
}
