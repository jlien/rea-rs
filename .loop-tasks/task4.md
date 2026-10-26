Read .loop-tasks/00-common.md first and follow it.

# Task 10 — WAT writer upgrade

crates/rea-core/src/wasm.rs. The `--wat` listing from iteration 1 is a readability listing; upgrade it toward full WAT emission for what the parser has already decoded — still NOT a full WAT writer for undecoded things, and still no WASI:

1. Emit proper s-expression WAT for: module header, type section (full param/result lists), import entries with their kinds, memory/table declarations with limits and shared flag, exports, start, element segments (offset + func indices), data segments (offset + escaped bytes), and function bodies as `(func $i ...)` with locals and decoded instructions in WAT mnemonic form where the opcode map covers them.
2. Unknown opcodes degrade to `(; opcode N ;)` comments inline — the output must remain syntactically parseable-looking text, never invalid nesting.
3. Keep the old readability mode available (previous flag semantics) and add `--wat-full` if a mode split is cleaner than changing `--wat`; your call, document it either way.
4. Fixture tests: round-trip shape checks on existing fixtures (balanced parens count, known mnemonics present, escaped data bytes).
5. Update README.md `rea wasm` bullets + review doc WASM rows.
6. Commit: `rea-rs: full wat emission for decoded wasm`.
