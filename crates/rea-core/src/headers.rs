//! C header text for names already recovered on a [`Target`](crate::Target).
//!
//! An Itanium or MSVC demangle becomes a declaration. A demangled path with
//! `::` but no parameter list becomes a comment, as does a Swift demangle
//! (`module.name`). Any other local or
//! export with a C identifier is `extern void name();`. Imports are omitted.

use crate::{SymbolKind, Target};

pub fn emit(target: &Target) -> String {
    let mut out = String::from("#ifndef REA_RECOVERED_H\n#define REA_RECOVERED_H\n");
    for sym in &target.symbols {
        if !matches!(sym.kind, SymbolKind::Local | SymbolKind::Export) {
            continue;
        }
        if let Some(demangled) = &sym.demangled {
            if !demangled.contains('(') {
                // A Swift demangle (`module.name`) is a path with `.`, which
                // is not callable C syntax, so it is a comment only. No
                // parameter list is invented and no declaration is emitted
                // for a path containing `.`.
                if crate::demangle::swift(&sym.name).is_some() {
                    out.push_str("/* ");
                    out.push_str(demangled);
                    out.push_str(" */\n");
                }
                // A demangled path with no parameter list (a Rust path, for
                // example) is not callable syntax, so it is a comment only.
                if demangled.contains("::") {
                    out.push_str("/* ");
                    out.push_str(demangled);
                    out.push_str(" */\n");
                }
            } else if let Some(line) = decl_from_demangled(demangled) {
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
    // An MSVC demangle carries a return type before the name path
    // (`int foo(int)`); an Itanium or Rust demangle does not. A name path in
    // this subset never contains a space, so the return type is whatever
    // precedes the last one. The return type is not parsed again from the raw
    // `?` mangling — the demangled string is the only input.
    let (ret, path) = match qual.rsplit_once(' ') {
        Some((ret, path)) => (Some(ret), path),
        None => (None, qual),
    };
    let func = path.rsplit("::").next().unwrap_or(path);
    if c_ident(func).is_none() {
        return None;
    }
    let args = if params.is_empty() {
        "void".to_string()
    } else {
        params.to_string()
    };
    let ret = ret.unwrap_or("void");
    if path.contains("::") {
        Some(format!("extern {ret} {path}({args});"))
    } else {
        Some(format!("extern {ret} {func}({args});"))
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

    #[test]
    fn msvc_names_become_declarations_with_their_return_type() {
        let header = emit(&target_with(vec![
            Symbol::new(0x1200, 0, "?foo@@YAHH@Z", SymbolKind::Local),
            Symbol::new(0x1300, 0, "?bar@Foo@@YAXH@Z", SymbolKind::Export),
        ]));
        assert!(header.contains("extern int foo(int);"), "{header}");
        assert!(header.contains("extern void Foo::bar(int);"), "{header}");
        assert!(header.contains("/* void Foo::bar(int) */"), "{header}");
    }

    #[test]
    fn a_rust_path_becomes_a_comment_but_not_a_declaration() {
        let header = emit(&target_with(vec![
            Symbol::new(0x1400, 0, "_RNvC3_foo3_bar", SymbolKind::Local),
            Symbol::new(0x1500, 0, "?foo@@YA", SymbolKind::Local),
        ]));
        // `foo::bar` has no parameter list, so it is a comment, never a
        // declaration; the raw name's C-identifier line stays. The truncated
        // `?` name is not even a C identifier.
        assert!(header.contains("/* foo::bar */"), "{header}");
        assert!(header.contains("extern void _RNvC3_foo3_bar();"), "{header}");
        assert!(!header.contains("foo::bar("), "{header}");
        assert!(!header.contains("?foo@@YA"), "{header}");
    }

    #[test]
    fn a_swift_demangle_becomes_a_comment_but_not_a_declaration() {
        let header = emit(&target_with(vec![
            Symbol::new(0x1600, 0, "$s4main3fooyyF", SymbolKind::Local),
            Symbol::new(0x1700, 0, "$s4main9", SymbolKind::Export),
        ]));
        // `main.foo` is a path with `.`, so it is a comment in the 4.2 form,
        // never a declaration; the failed demangle stays absent and the raw
        // `$s` names are not C identifiers, so no fallback line appears.
        assert!(header.contains("/* main.foo */"), "{header}");
        assert!(!header.contains("main.foo("), "{header}");
        assert!(!header.contains("extern void main"), "{header}");
        assert!(!header.contains("$s4main9"), "{header}");
        assert!(!header.contains("/* main. */"), "{header}");
    }
}
