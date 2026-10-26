# Common constraints (apply to every task)

- Repo: rea-rs — clean-room Rust rewrite of an MCP reverse-engineering toolkit. Crates: rea-core (loading/analysis/disasm), rea-mcp (hand-rolled JSON-RPC stdio server), rea-cli (the `rea` binary). Workspace deps allowed: goblin, serde, serde_json, anyhow, thiserror, clap, capstone. Do NOT add new external crates.
- All builds/tests run OFFLINE: `cargo test --workspace --offline`. No network.
- Commit style: subject exactly `rea-rs: <what it added>` (see `git log --oneline`). One commit per task. Never push.
- Every task ends with: code + fixture tests (follow existing test patterns in the crate), `cargo test --workspace --offline` passing, README.md MCP-tool/roadmap text updated if the tool surface changed, and docs/rea-rs-review.html updated: newest commit id in the `#now` meta line, a Done-table row, and the touched "Stops before" / gaps cells relaxed to match what now reads. Match the doc's terse declarative voice.
- The review doc's repeated phrase "stays unread" / "stops before" is the definition of remaining work — your task is to make one of those clauses false, then rewrite it.
- Honest reporting: if a sub-item proves infeasible, implement the feasible part, leave the doc clause accurate, and say so in the commit body.
- NOTE: iteration 1 (commits 3a413a8..ef27480) already landed field signatures, Param sequence numbers, WASM memory entries, --wat listing, session binary mapping, NIB values, rendition facts, and width-based decompile types. Build on that state; do not redo it.
