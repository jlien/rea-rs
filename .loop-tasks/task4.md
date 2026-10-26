# A Swift mangling subset

**Where:** `crates/rea-core/src/demangle.rs`, and the Mach-O symbol path in `crates/rea-core/src/loader.rs` only if `$s` names do not already reach `demangle::any`

**Retires:** `rea symbols` Stops before: "Swift demangling." Also "Swift stays raw" on that row and in the "Out of this tree" paragraph, for this subset. A demangle failure still does not fail the listing.

After the existing one-underscore strip, a stored name starting with `$s` or `_$s` can demangle. Parse two length-prefixed identifiers (a decimal length, then that many bytes, the same shape as the Rust v0 ident parser). Render `module.name`. Bytes after the second identifier stay unread and do not reject the match, so a type suffix does not have to be decoded. The demangled text does not include that suffix. Punycode, a length that does not fit, and a first byte that is not a digit return `None`. The stored raw name stays. Objective-C thunks and generic signatures stay raw. Headers still omit Swift names until task 6.1.

**Difficulty:** medium

**Commit:** `rea-rs: a swift mangling subset`
