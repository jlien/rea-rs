//! C header text for names already recovered on a [`Target`](crate::Target).
//!
//! An Itanium demangle becomes a declaration. Any other local or export with
//! a C identifier is `extern void name();`. Imports are omitted.

use crate::{SymbolKind, Target};

pub fn emit(target: &Target) -> String {
    let mut out = String::from("#ifndef REA_RECOVERED_H\n#define REA_RECOVERED_H\n");
    for sym in &target.symbols {
        if !matches!(sym.kind, SymbolKind::Local | SymbolKind::Export) {
            continue;
        }
        if let Some(demangled) = &sym.demangled {
            if let Some(line) = decl_from_demangled(demangled) {
                out.push_str("/* ");
                out.push_str(demangled);
                out.push_str(" */\n");
                out.push_str(&line);
                out.push('\n');
                continue;
            }
        }
        if let Some(name) = c_ident(&sym.name) {
            out.push_str("extern void ");
            out.push_str(name);
            out.push_str("();\n");
        }
    }
    out.push_str("#endif\n");
    out
}

fn decl_from_demangled(demangled: &str) -> Option<String> {
    let (qual, params) = demangled.split_once('(')?;
    let params = params.strip_suffix(')')?;
    let func = qual.rsplit("::").next().unwrap_or(qual);
    if c_ident(func).is_none() {
        return None;
    }
    let args = if params.is_empty() {
        "void".to_string()
    } else {
        params.to_string()
    };
    if qual.contains("::") {
        Some(format!("extern void {qual}({args});"))
    } else {
        Some(format!("extern void {func}({args});"))
    }
}

fn c_ident(name: &str) -> Option<&str> {
    let mut chars = name.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    if chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        Some(name)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::emit;
    use crate::{Symbol, SymbolKind, Target};

    fn target_with(symbols: Vec<Symbol>) -> Target {
        Target {
            path: "fixture".into(),
            format: crate::Format::MachO,
            arch: crate::Arch::X86_64,
            bits: 64,
            little_endian: true,
            entry: 0,
            sections: Vec::new(),
            symbols,
            bytes: Vec::new(),
            page_map: None,
        }
    }

    #[test]
    fn header_contains_a_recovered_name_and_a_demangled_declaration() {
        let header = emit(&target_with(vec![
            Symbol::new(0x1000, 0, "widget", SymbolKind::Export),
            Symbol::new(0x1100, 0, "_Z3fooi", SymbolKind::Local),
            Symbol::new(0, 0, "printf", SymbolKind::Import),
        ]));
        assert!(header.contains("widget"), "{header}");
        assert!(header.contains("foo(int)"), "{header}");
        assert!(!header.contains("printf"), "{header}");
    }
}
