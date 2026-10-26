Read .loop-tasks/00-common.md first and follow it.

# Task 7 — CLR: Property/Event signatures and the skipped alignment tables

crates/rea-core/src/pe_meta.rs and clr_sig.rs. Property and Event names are already read via PropertyMap/EventMap, but their SIGNATURES are not. Also, InterfaceImpl, and other small tables were deliberately skipped so names stayed aligned — now read them WITHOUT breaking alignment:

1. Decode Property and Event signatures from the blob heap, attached beside their names (same style as MemberRef signatures — decode what the blob allows, empty on blob index 0, no parse failure).
2. Read InterfaceImpl: each TypeDef's implemented interface list (TypeRef/TypeDef/TypeSpec coded index). Render resolved names where the target row exists.
3. Any other small table you can read safely (e.g. Constant, CustomAttribute presence counts) — read COUNTS/names only, do not attempt full blob decoding beyond your signature decoder.
4. Preserve the existing alignment invariants: a skip must remain skip-or-consume consistently, verified by tests that check name lists stay aligned when intermediate tables have rows.
5. Update README.md `rea pe` / `rea_pe` bullets + review doc CLR table and "stops before" cells.
6. Commit: `rea-rs: property and event signatures and interfaceimpl`.
