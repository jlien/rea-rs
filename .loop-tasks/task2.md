Read .loop-tasks/00-common.md first and follow it.

# Task 8 — Decompile: bounded cross-block flow

crates/rea-core/src/decompile.rs. Today the pseudo-C window is straight-line only (at most 64 instructions from the start address), and the doc honestly says "no dataflow across basic blocks".

Scope a BOUNDED improvement:

1. Follow unconditional control flow WITHIN the discovered function (use rea-core's existing function-boundary data if reachable, else the forward-jmp heuristic): after an unconditional `jmp`/`b` whose target is still inside the same function, continue the listing at the target instead of stopping — bounded to the same 64-instruction cap and a depth cap of 8 hops.
2. Skip-over for short conditional branches is NOT required — only unconditional flow. A branch out of the function bounds ends the listing with a `goto <hex>` line as today.
3. Loop protection: keep a visited-target set; a repeated target terminates the walk with a `goto` line. Never exceed the 64-instruction cap.
4. Width-based types from the previous iteration must keep flowing through the joined blocks where the register state is trivially carried (same physical register, no intervening writes) — if carrying state is unsound at a join, drop to untyped at that point rather than guess.
5. Fixture tests: same-function jmp chain on x86_64 and arm64, a loop that trips the visited guard, a jmp out of bounds.
6. Update README.md decompile bullets + review doc row (relax "straight-line" and "no dataflow across basic blocks" clauses to name what IS now done: same-function unconditional flow with carried register width, and what stays: memory-object types, struct recovery, cross-function dataflow).
7. Commit: `rea-rs: same-function flow in the pseudo-c window`.
