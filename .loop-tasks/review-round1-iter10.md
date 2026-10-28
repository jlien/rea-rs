# Iteration 10 review

`cargo test --workspace --offline` exited 0: rea-core 321 passed, rea-mcp 15 passed, rea-cli 5 passed, 0 ignored, no warnings. The banner and the `354a128` row match those counts. Tasks 1 and 2 (AArch64 feature-1, `global.get` offsets) have discriminating tests and match the code. No new panic on a small truncated fixture in the five diffs: the new IL token read is gated by `at + 4 > code.len()` (`clr_sig.rs:149-156`), GNU-property slices are length-checked (`elf_meta.rs:189-195`), WASM LEB reads return `Err`, and TypeSpec goes through `heap_blob` / `sig_type` which use `get`.

## Blocking

- `crates/rea-core/src/le.rs:1257` and `crates/rea-core/src/loader.rs:969`. The flag-3 tests do not pin "the last page fills only the object's remainder." The synthetic object is 16 bytes in a 4096-byte page, and both tests only assert `0x140..0x150` is zero (and that a fixup at +8 sticks). Bytes past the remainder are already zero, and `with_fixup_records_on` (`le.rs:1063`) keeps fixup records below the data page, so replacing `target` with `pagesize` in `expand_zero_filled` (`le.rs:533-546`) still passes `a_zero_filled_page_expands_to_zeros_and_then_translates`, `zero_filled_pages_expand_through_the_real_load_path`, and `identity_pages_stay_untouched_by_the_zero_expansion`. The remainder clamp is a required part of task 5 and is untested.

- `README.md:141`. The roadmap item still ends "Other metadata rows stay unread" and never lists TypeSpec. `e0de3aa` stores one `sig_type` string per TypeSpec row on `ClrHeader::typespec_signatures` (`pe_meta.rs:98`, `pe_meta.rs:1320-1328`). The `rea_pe` bullet at `README.md:95` describes that; this checkbox contradicts it.

- `docs/rea-rs-review.html:592`. The .NET gaps cell still ends "Other row bodies stay unread" and does not name TypeSpec element text. Standing rules require the gaps cell to say what became readable. TypeSpec blobs are read; this sentence says they are not.

- `docs/rea-rs-review.html:427`. The PE/CLR measured row was edited to claim "one element text per TypeSpec row" (`:426`) while the result cell still says "No other table rows, no signatures, and no IL." Signatures, IL, and TypeSpec text are read. That result is not what the code does.

- `docs/rea-rs-review.html:658`. Present tense: flag values past identity and iterated, "invalid, zero-filled", "are refused by `translate`, never expanded." Task 5 retired the zero-filled half. `expand_zero_filled` fills flag 3 and `translate` serves it after that (`le.rs:88-93`, `le.rs:512-548`). "Out of this tree" (`:361`) was updated; this copy of the same clause was not.

- `docs/rea-rs-review.html:314` and `:167`, `crates/rea-core/src/clr_sig.rs:470`. Both living claims call `ldc.i8` (`0x22`) a token-taking opcode that stops at `op-XX`. `0x22` takes an int64, not a metadata token. The fixture `il_ops(&[0x0a, 0x22, 0x01])` therefore does not pin "any other token opcode still stops." `calli` (`0x29`), `ldfld` (`0x7B`), or `box` (`0x8C`) could start printing a token and this test would still pass. The four named opcodes and the `ldftn` stop are pinned; this one is not.

VERDICT: FAIL
