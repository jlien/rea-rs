# Common constraints (all tasks, read every time)

- No new external crates. Allowed: goblin, serde, serde_json, anyhow, thiserror, clap, capstone.
- Offline only: `cargo build --offline`, `cargo test --workspace --offline`.
- One task = one commit, subject exactly `rea-rs: <what it added>` (lowercase, as given).
- Never push. The human merges after review.
- Every task ends with: fixture tests, a README.md update, and a docs/rea-rs-review.html update
  (newest commit id in the #now meta line, a Done-table row, and relaxed Stops-before/gaps cells
  that name what became readable and what remains). Terse declarative voice.
- "stays unread" / "stops before" phrases define the remaining work. Never delete a clause you did
  not honestly retire. If a sub-item is infeasible, say so in the doc instead of faking it.
- Work from the brief below exactly. If a prior task already landed part of it (check git log),
  build on what landed; do not redo or revert it.
- Read docs/iterations-3plus-plan.md in the repo root for the full context of this task in the
  overall iteration plan.

---

