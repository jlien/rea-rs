Read .loop-tasks/00-common.md first and follow it.

# Task 11 — Session: upstream Evidence-record export

crates/rea-core/src/session.rs. The session store is native; the doc honestly says "Not an upstream Evidence record". Add a compatibility EXPORT, not a rewrite:

1. `rea session ... export --format evidence` (or `--evidence` flag on `diff`/`show` — your call, keep it CLI-consistent): emits an upstream-morphic Evidence JSON shape: tool name, arguments echo, bounded output payload, timestamp, and a session identifier — mapped FROM the native session file records recorded so far (including the identity summary and embedded tool outputs from iteration 1).
2. Fields the native store does not capture (e.g. upstream's session handle types, live mapping) are emitted as explicit `null` fields, never fabricated.
3. The MCP surface stays unchanged (17 tools); this export is CLI-only — say so in the docs.
4. Fixture tests: export of a session with identity + one recorded tool; assert shape keys and null-for-unknown, cap/truncation marker preserved.
5. Update README.md session bullet + review doc session row (relax "Not an upstream Evidence record" to name the export path and what fields stay null).
6. Commit: `rea-rs: evidence-format session export`.
