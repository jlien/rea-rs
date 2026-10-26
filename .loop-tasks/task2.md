# ObjC class-name strings

**Where:** `crates/rea-core/src/macho_meta.rs` (surfaced on `rea macho` / `rea_macho`)

**Retires:** gaps cell "Enhanced native (overview, ObjC, Swift, value and UI trace)", whose rea-rs column is "local call graph on x86, x86_64, arm64, Thumb." This task covers the ObjC word only. There is no command-table Stops-before sentence that names ObjC.

List NUL-terminated C strings from Mach-O sections whose names contain `objc`, capped at 128, with a `... more` marker. A binary with no such section stores an empty list and does not fail the parse. Do not walk `class_ro_t`, method lists, or protocols. Do not demangle Swift.

**Speculative:** the review names ObjC as a gap area and does not name a section layout. A section that holds pointers rather than C strings yields an empty or useless list; if a fixture shows that, leave the gaps cell honest instead of parsing the pointer structure in this task.

**Difficulty:** medium

**Commit:** `rea-rs: objc class-name strings`
