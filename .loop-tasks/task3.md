# LE entry-bundle addresses

**Where:** `crates/rea-core/src/le.rs`

**Retires:** "Entry bundles and iterated pages are not handled" (overlap row and the "Out of this tree" paragraph), the entry-bundle half. The module comment says the same thing.

The walker already reads a fixed set of header fields (object table, page map, data page). Add the entry table beside that set, using the header fields that point at it. Report each entry's object index and offset. A bundle flag this task does not recognize is counted and skipped, and the review names that flag. Do not guess a second on-disk layout if the first fixture disagrees with the header; keep the clause in that case. Iterated pages stay unread until task 6.5. Do not seed `rea funcs` from these addresses in this task.

**Difficulty:** medium

**Commit:** `rea-rs: le entry bundle addresses`
