# Iteration 10 review

`cargo test --workspace --offline` exited 0: rea-core 322 passed, rea-mcp 15 passed, rea-cli 5 passed (2+1+1+1), 0 ignored. A clean `cargo build -p rea-core --offline --tests` printed no warnings. The banner and the Done rows match the `#[test]` counts at those commits: `6ba1dbe` 317, `e0de3aa` 319, `354a128` 321, `43d943e` 322. Base was 311.

No blocking findings.

- Task 1. `parse_gnu_properties` names `0xc0000000` as `aarch64 feature 1` with bit 0 `BTI` and bit 1 `PAC`, joined `" and "` the same way as `IBT and SHSTK` (`elf_meta.rs:219-237`). Zero named bits are skipped; other types stay hex. `aarch64_feature_1_names_bti_and_pac` and the standing ELF fixture fail if that arm is removed. Slices use `get`.
- Task 2. `read_i32_offset` accepts `i32.const` and `global.get` (`wasm.rs:1056-1067`). A third opcode, or flags other than 0, still errors and `inspect` drops the section (`wasm.rs:256-269`). `--wat-full` prints `(global.get N)` only when `offset_is_global` is set. `execute` does not read the segment. `a_global_get_offset_stores_the_global_index_and_wat_full_prints_it` indexes `elements[0]` and fails if the section is dropped.
- Task 3. `call`, `callvirt`, `ldstr`, and `newobj` print a 4-byte little-endian token as `0x{token:08x}` and keep walking; `at + 4 > code.len()` stops with no partial operand (`clr_sig.rs:149-156`). `calli` (`0x29`) and `ldftn` (`FE 06`) still stop. The 48-opcode cap is unchanged (`clr_sig.rs:84`). Tokens are not resolved.
- Task 4. Table 27 stays `blob_w` (`pe_meta.rs:1190`). Each row stores `sig_type` text or `None` (`pe_meta.rs:1320-1328`); index 0, a short blob, and `0x15` stay empty and do not fail the parse. `InterfaceImpl` / `MemberRef` labels stay `typespec-N` / `TypeSpec#N`. Generic inst is not added. `heap_blob` and `sig_type` use `get`; depth still caps at 64.
- Task 5. `expand_zero_filled` runs after iterated expansion and before fixups (`loader.rs:114-116`). Flag 3 fills only the object's remainder (`le.rs:533-546`); flag 0, flag 1, page 0, and any other flag are not filled. `translate` serves a flag-3 page only after the slot is marked (`le.rs:91-93`). `zero_filled_expansion_stops_at_the_object_remainder` fails if the fill uses the page size: the object is 16 bytes at `0x140` and `b[0x150]` is `0xAA`. The loader test fails if the load path skips the fill or the fixup. No decompressor and no `rea funcs` seed.

README and `docs/rea-rs-review.html` name the same limits: four token opcodes as unresolved hex, one `sig_type` string per TypeSpec row, `global.get` offsets only, `aarch64 feature 1` for this property type, and zero-filled pages with other flags still refused.

VERDICT: PASS
