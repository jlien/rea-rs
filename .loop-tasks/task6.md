Read .loop-tasks/00-common.md first and follow it.

# Task 12 — Mach-O: entitlements and code-signature detail

crates/rea-core/src/macho_meta.rs. The CMS blob and cms_verified digest window exist; entitlements are not parsed. Read-only, still no Apple trust decision:

1. When a code signature blob (CMS superblob) is present, parse the entitlements slot: the XML entitlements payload — render bundle-key/plist-style top-level keys and their immediate values (string/bool). Cap rendered XML at 8 KiB with a marker; a payload that is not XML stays hex-capped.
2. Parse the entitlements DER slot (0x... CMS-embedded) only if it costs little — if the DER path is heavy, record its presence/size only and leave the doc clause honest.
3. Also surface the code-directory's exec-segment flags (offset/size/flags) and the special slot count when present.
4. Per-slice: each fat slice reports its own entitlements when present (the per-slice pattern already exists for uuid/dylibs/...).
5. Fixture tests: synthetic superblob with entitlements XML (existing fixtures show the blob layout), a non-XML payload, per-slice difference.
6. Update README.md `rea macho` / `rea_macho` bullets + review doc Mach-O rows.
7. Commit: `rea-rs: entitlements and exec-segment facts`.
