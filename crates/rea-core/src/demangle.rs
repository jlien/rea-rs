//! Demanglers for names this tree already stores.
//!
//! Itanium C++, Rust v0, a subset of MSVC, and a Swift subset (`module.name`
//! only). A name that does not fit returns `None` and does not fail symbol
//! listing.

/// Itanium, then Rust v0 (`_R`), then MSVC (`?`), then Swift (`$s`). The
/// first match wins.
pub fn any(name: &str) -> Option<String> {
    if name.starts_with("_Z") {
        itanium(name)
    } else if name.starts_with("_R") {
        rust_v0(name)
    } else if name.starts_with('?') {
        msvc(name)
    } else if name.starts_with("$s") || name.starts_with("_$s") {
        swift(name)
    } else {
        None
    }
}

/// Rust v0. `_RNvC3_foo3_bar` is `foo::bar`. A disambiguator is skipped.
///
/// Identifiers are a decimal length, an underscore, and that many bytes.
/// Backrefs and other path tags return `None`.
pub fn rust_v0(name: &str) -> Option<String> {
    let rest = name.strip_prefix("_R")?;
    let rest = skip_disambiguator(rest)?;
    let (path, rest) = parse_rust_path(rest)?;
    if rest.is_empty() {
        return Some(path);
    }
    let (_, rest) = parse_rust_path(rest)?;
    if rest.is_empty() {
        Some(path)
    } else {
        None
    }
}

/// Swift subset. `$s4main3fooyyF` is `main.foo`. Two length-prefixed
/// identifiers (module, then name) are read: a decimal length, then that many
/// bytes. Bytes after the second identifier (a type suffix, a generic
/// signature) stay unread and do not reject the match, and the demangled text
/// does not include them — except an unread tail of exactly `yyF`, the
/// empty-parameter-list function marker, which renders `module.name()`. Any
/// other tail keeps `module.name`. Punycode, a length that does not fit, and a
/// first byte that is not a digit return `None`.
pub fn swift(name: &str) -> Option<String> {
    let rest = name.strip_prefix('_').unwrap_or(name);
    let rest = rest.strip_prefix("$s")?;
    let (module, rest) = parse_swift_ident(rest)?;
    let (item, rest) = parse_swift_ident(rest)?;
    if rest == "yyF" {
        return Some(format!("{module}.{item}()"));
    }
    Some(format!("{module}.{item}"))
}

/// The two-identifier `module.name` result of [`swift`], without the `()` a
/// trailing `yyF` adds — the form the header comment and the ObjC section
/// strings print.
pub fn swift_path(name: &str) -> Option<String> {
    swift(name).map(|demangled| match demangled.strip_suffix("()") {
        Some(path) => path.to_string(),
        None => demangled,
    })
}

/// A Swift identifier: a decimal length, then that many bytes. A byte that is
/// not ASCII alphanumeric or `_` (for example the `-` in a punycode encoding)
/// returns `None`. A leading `00` is the punycode marker — a marker, then a
/// length, then the punycode text — and returns `None` rather than reading
/// the marker digits as the length.
fn parse_swift_ident(input: &str) -> Option<(String, &str)> {
    if input.starts_with("00") {
        return None;
    }
    let digits = input.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let len: usize = input[..digits].parse().ok()?;
    let rest = input.get(digits..)?;
    let name = rest.get(..len)?;
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some((name.to_string(), &rest[len..]))
}

/// MSVC subset. `?foo@@YAHH@Z` is `int foo(int)`. `?bar@Foo@@YAXH@Z` is `void Foo::bar(int)`.
pub fn msvc(name: &str) -> Option<String> {
    let rest = name.strip_prefix('?')?;
    let (qual, rest) = msvc_qual(rest)?;
    let rest = rest.strip_prefix('Y')?;
    let mut chars = rest.chars();
    let conv = chars.next()?;
    if !conv.is_ascii_uppercase() {
        return None;
    }
    let mut rest = chars.as_str();
    let (ret, next) = msvc_type(rest)?;
    rest = next;
    let mut params = Vec::new();
    while !rest.starts_with('@') {
        let (ty, next) = msvc_type(rest)?;
        params.push(ty);
        rest = next;
    }
    if rest != "@Z" {
        return None;
    }
    Some(format!("{ret} {qual}({})", params.join(", ")))
}

fn skip_disambiguator(input: &str) -> Option<&str> {
    let Some(after) = input.strip_prefix('s') else {
        return Some(input);
    };
    let end = after.find('_')?;
    if !after[..end].chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(&after[end + 1..])
}

fn parse_rust_path(input: &str) -> Option<(String, &str)> {
    let mut chars = input.chars();
    let tag = chars.next()?;
    let rest = chars.as_str();
    match tag {
        'C' => parse_rust_ident(rest),
        'N' => {
            let mut chars = rest.chars();
            chars.next()?;
            let rest = chars.as_str();
            let (parent, rest) = parse_rust_path(rest)?;
            let (ident, rest) = parse_rust_ident(rest)?;
            Some((format!("{parent}::{ident}"), rest))
        }
        'I' => {
            let (parent, mut rest) = parse_rust_path(rest)?;
            let mut args = Vec::new();
            while !rest.starts_with('E') {
                let (ty, next) = rust_type(rest)?;
                args.push(ty);
                rest = next;
            }
            let rest = rest.strip_prefix('E')?;
            Some((format!("{parent}<{}>", args.join(", ")), rest))
        }
        _ => None,
    }
}

fn parse_rust_ident(input: &str) -> Option<(String, &str)> {
    let rest = skip_disambiguator(input)?;
    let rest = if let Some(puny) = rest.strip_prefix('u') {
        if puny.starts_with(|c: char| c.is_ascii_digit()) {
            puny
        } else {
            rest
        }
    } else {
        rest
    };
    let digits = rest.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let len: usize = rest[..digits].parse().ok()?;
    let rest = rest.get(digits..)?.strip_prefix('_')?;
    let name = rest.get(..len)?;
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    Some((name.to_string(), &rest[len..]))
}

fn rust_type(input: &str) -> Option<(String, &str)> {
    let mut chars = input.chars();
    let tag = chars.next()?;
    let name = match tag {
        'a' => "i8",
        'b' => "bool",
        'c' => "char",
        'd' => "f64",
        'e' => "str",
        'f' => "f32",
        'h' => "u8",
        'i' => "isize",
        'j' => "usize",
        'l' => "i32",
        'm' => "u32",
        'n' => "i128",
        'o' => "u128",
        's' => "i16",
        't' => "u16",
        'u' => "()",
        'x' => "i64",
        'y' => "u64",
        'z' => "!",
        'p' => "_",
        _ => return None,
    };
    Some((name.to_string(), chars.as_str()))
}

fn msvc_qual(input: &str) -> Option<(String, &str)> {
    let mut parts = Vec::new();
    let mut rest = input;
    loop {
        let end = rest.find('@')?;
        if end == 0 {
            return None;
        }
        let part = &rest[..end];
        if !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return None;
        }
        parts.push(part.to_string());
        rest = &rest[end + 1..];
        if let Some(next) = rest.strip_prefix('@') {
            parts.reverse();
            return Some((parts.join("::"), next));
        }
    }
}

fn msvc_type(input: &str) -> Option<(&'static str, &str)> {
    let mut chars = input.chars();
    let tag = chars.next()?;
    let name = match tag {
        'C' => "signed char",
        'D' => "char",
        'E' => "unsigned char",
        'F' => "short",
        'G' => "unsigned short",
        'H' => "int",
        'I' => "unsigned int",
        'J' => "long",
        'K' => "unsigned long",
        'M' => "float",
        'N' => "double",
        'X' => "void",
        _ => return None,
    };
    Some((name, chars.as_str()))
}

/// Demangle `_Z` Itanium names such as `_Z3fooi` and `_ZN3Foo3barEi`.
///
/// A single trailing `v` parameter is the empty parameter list. Other names,
/// including a truncated `_Z` prefix, return `None`.
pub fn itanium(name: &str) -> Option<String> {
    let rest = name.strip_prefix("_Z")?;
    let (qual, rest) = parse_name(rest)?;
    let params = parse_params(rest)?;
    Some(format!("{qual}({params})"))
}

fn parse_name(input: &str) -> Option<(String, &str)> {
    if let Some(rest) = input.strip_prefix('N') {
        let mut parts = Vec::new();
        let mut rest = rest;
        while !rest.starts_with('E') {
            let (part, next) = parse_source_name(rest)?;
            parts.push(part);
            rest = next;
        }
        if parts.is_empty() {
            return None;
        }
        return Some((parts.join("::"), &rest[1..]));
    }
    parse_source_name(input)
}

fn parse_source_name(input: &str) -> Option<(String, &str)> {
    let digits = input.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let len: usize = input[..digits].parse().ok()?;
    let rest = input.get(digits..)?;
    let name = rest.get(..len)?;
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    Some((name.to_string(), &rest[len..]))
}

fn parse_params(input: &str) -> Option<String> {
    // `v` is the empty parameter list. A missing suffix is a truncated name.
    if input == "v" {
        return Some(String::new());
    }
    if input.is_empty() {
        return None;
    }
    let mut params = Vec::new();
    let mut rest = input;
    while !rest.is_empty() {
        let (ty, next) = parse_type(rest)?;
        params.push(ty);
        rest = next;
    }
    Some(params.join(", "))
}

fn parse_type(input: &str) -> Option<(&'static str, &str)> {
    let mut chars = input.chars();
    let head = chars.next()?.to_string();
    let rest = chars.as_str();
    let name = match head.as_str() {
        "v" => "void",
        "b" => "bool",
        "c" => "char",
        "a" => "signed char",
        "h" => "unsigned char",
        "s" => "short",
        "t" => "unsigned short",
        "i" => "int",
        "j" => "unsigned int",
        "l" => "long",
        "m" => "unsigned long",
        "x" => "long long",
        "y" => "unsigned long long",
        "f" => "float",
        "d" => "double",
        "w" => "wchar_t",
        _ => return None,
    };
    Some((name, rest))
}

#[cfg(test)]
mod tests {
    use super::{any, itanium, msvc, rust_v0, swift, swift_path};

    #[test]
    fn swift_reads_two_identifiers_and_stops() {
        assert_eq!(swift("$s4main3fooyyF").as_deref(), Some("main.foo()"));
        assert_eq!(swift("_$s4main3fooyyF").as_deref(), Some("main.foo()"));
        assert_eq!(any("$s4main3fooyyF").as_deref(), Some("main.foo()"));
        assert_eq!(any("_$s4main3fooyyF").as_deref(), Some("main.foo()"));
        // A generic signature or type suffix after the second identifier stays
        // unread and does not reject the match.
        assert_eq!(swift("$s4main3fooS2i_S2itSfE").as_deref(), Some("main.foo"));
        assert_eq!(swift("$s4main3foo3barVyXEfU_").as_deref(), Some("main.foo"));
    }

    #[test]
    fn a_trailing_yyf_makes_an_empty_parameter_list() {
        // An unread tail of exactly `yyF` renders `module.name()`.
        assert_eq!(swift("$s4main3fooyyF").as_deref(), Some("main.foo()"));
        assert_eq!(any("$s4main3fooyyF").as_deref(), Some("main.foo()"));
        // Any other tail — even one beginning with `yyF` — keeps
        // `module.name`, and the two-identifier path never carries `()`.
        assert_eq!(swift("$s4main3fooyyFy").as_deref(), Some("main.foo"));
        assert_eq!(swift_path("$s4main3fooyyF").as_deref(), Some("main.foo"));
        assert_eq!(swift_path("$s4main3fooS2i_S2itSfE").as_deref(), Some("main.foo"));
        assert_eq!(swift_path("$s4main9"), None);
    }

    #[test]
    fn swift_rejects_malformed_and_punycode() {
        // First byte not a digit.
        assert_eq!(swift("$s4main"), None);
        assert_eq!(swift("$sXmain3foo"), None);
        // A length that does not fit.
        assert_eq!(swift("$s4main9"), None);
        assert_eq!(swift("$s99999999999999main3foo"), None);
        // Punycode keeps its `-` separator and is not decoded.
        assert_eq!(swift("$s4main3x-abc"), None);
        // The punycode marker `00` before a length is not read as a length.
        assert_eq!(swift("$s8mangling0022egbpdajGbuEbxfgehfvwxnyyF"), None);
        // Truncated before the second identifier.
        assert_eq!(swift("$s4main"), None);
        assert_eq!(swift("$s"), None);
        assert_eq!(any("printf"), None);
    }

    #[test]
    fn demangles_a_function_and_a_nested_name() {
        assert_eq!(itanium("_Z3fooi").as_deref(), Some("foo(int)"));
        assert_eq!(itanium("_Z3foov").as_deref(), Some("foo()"));
        assert_eq!(itanium("_ZN3Foo3barEi").as_deref(), Some("Foo::bar(int)"));
    }

    #[test]
    fn leaves_plain_and_truncated_names_alone() {
        assert_eq!(itanium("printf"), None);
        assert_eq!(itanium("_Z"), None);
        assert_eq!(itanium("_Z3"), None);
        assert_eq!(itanium("_Z3foo"), None);
    }

    #[test]
    fn rust_v0_and_msvc_keep_the_raw_name_available_to_the_caller() {
        assert_eq!(rust_v0("_RNvC3_foo3_bar").as_deref(), Some("foo::bar"));
        assert_eq!(
            rust_v0("_RINvC3_foo3_barlE").as_deref(),
            Some("foo::bar<i32>")
        );
        assert_eq!(rust_v0("_RNvC3foo3bar"), None);
        assert_eq!(msvc("?foo@@YAHH@Z").as_deref(), Some("int foo(int)"));
        assert_eq!(
            msvc("?bar@Foo@@YAXH@Z").as_deref(),
            Some("void Foo::bar(int)")
        );
        assert_eq!(msvc("?foo@@YA"), None);
        assert_eq!(any("printf"), None);
        assert_eq!(any("_RNvC3_foo3_bar").as_deref(), Some("foo::bar"));
        assert_eq!(any("?foo@@YAHH@Z").as_deref(), Some("int foo(int)"));
    }
}
