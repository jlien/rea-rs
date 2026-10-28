# Iteration 9 review

Commits `3ca1d94`..`08767cb` on `tasks-loop-9`. A clean rebuild (`cargo clean -p rea-core -p rea-cli -p rea-mcp`, then `cargo test --workspace --offline`) printed no rustc warnings and passed: rea-core 311, rea-mcp 15, rea-cli 5. Those counts match `docs/rea-rs-review.html` line 157. `rea strings /bin/ls --xrefs --min-length 6` is 20 and `rea callgraph /bin/ls` is 143 functions / 499 edges, matching the `561efd3` row. A 2466-input probe of short global sections, tiny IL bodies, Swift names, and hostile xref windows did not panic.

Task 1. `demangle::swift` renders `module.name()` only when the tail is exactly `yyF` (`demangle.rs:55`). `$s4main3fooyyFy` stays `main.foo`, so a prefix check would fail the test. `swift_path` strips the parentheses; headers print `/* main.foo */` and ObjC `module_name` stays `main.foo` (`macho_meta.rs:305`, `headers.rs:17`).

Task 2. `0xFE` `0x09`–`0x0E` take a little-endian `u16` and the walk continues (`clr_sig.rs:114`). `il_ops(&[0x0a, 0xfe, 0x0c])` is a codesize-2 tiny body that reaches `at + 2 > code.len()`; deleting the guard panics. `ldftn` stays `op-fe-06`. The 48-opcode cap is unchanged.

Task 3. Defined `i32` / `i32.const N end` globals are stored with section index, and `--wat-full` prints `(global $n …)` (`wasm.rs:557`). A skipped non-`i32` still occupies its index (`a_skipped_global_still_occupies_its_wasm_index`). An opcode other than `0x41`, and a wrong end byte, stop the section (`wasm.rs:789`, `wasm.rs:796`). The unknown-opcode fixture `02 7f 00 23 7f 00 41 05 0b` ends in a real `i32.const` global, so continuing past `0x23` would store init 5 and fail the empty assertion. A truncated initializer keeps the globals already parsed. A second global section is `duplicate wasm global section`. `execute` does not read the global.

Task 4. `der_slot_is_a_size_only` feeds `30 82 04 10 02 01 01`, a SEQUENCE around an INTEGER, not UTF8String pairs. The speculative stop applies. `macho_meta.rs:370` stores only `entitlements_der_size`. The `rea macho` Reads cell, Stops-before cell, measured row, and coverage cell say the payload stays unparsed.

Task 5. On a 64-bit target, `data_xrefs` adds a 4-byte aligned low-32 hit when `addr` fits in a `u32` and that `from` is not already an 8-byte hit (`analysis.rs:733`). The aligned fixture `08 10 00 00 ff ff ff ff` at VA `0x1000` fails if the low-32 path is removed. The unaligned fixture has `08 10 00 00` at VA `0x1001` and fails if `from % 4 == 0` is removed. `0x1_0000_0001` fails if the `u32` guard is removed. The 8-byte, 32-bit, and PC-relative paths are unchanged.

No blocking findings.

VERDICT: PASS
