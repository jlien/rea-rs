Read .loop-tasks/00-common.md first and follow it.

# Task 9 — ELF: notes and section detail

crates/rea-core/src/elf_meta.rs. Today rea_elf reads file type, machine, interpreter, needed libs, soname, rpath/runpath (+file hits), GNU build-id. The doc says layout/note inspection lives inside upstream's native file tools.

1. Parse ELF NOTE sections (SHT_NOTE segments and sections): render each note as (name owner, type id, descriptor hex capped at e.g. 128 bytes with a marker). Known types get names: NT_GNU_BUILD_ID, NT_GNU_HWCAP, NT_GNU_PROPERTY, NT_PRPSINFO etc. — a table you own in-code; unknown types stay numeric.
2. Add section-type detail: for each section in `rea sections` ELF path (or a new field on rea_elf), report sh_type name (PROGBITS, NOBITS, DYNAMIC...) and SHF_ flags beyond the existing rwx string.
3. GNU property notes: parse the x86 ISA/IBT/SHSTK property bits when present into a readable list; unknown property types stay hex.
4. Fixture tests using the in-crate ELF64 fixture pattern (the machine has no system ELF — /bin/ls is Mach-O; tests must be synthetic).
5. Update README.md `rea elf` / `rea_elf` bullets + review doc ELF row.
6. Commit: `rea-rs: elf notes and section types`.
