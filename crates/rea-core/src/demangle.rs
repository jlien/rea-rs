//! A small Itanium C++ demangler for names this tree already stores.
//!
//! Swift, Rust, and MSVC schemes are left as the raw name. A name that does
//! not fit this grammar returns `None` and does not fail symbol listing.

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
    use super::itanium;

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
}
