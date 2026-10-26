# Short conditional flow in the pseudo-C window

**Where:** `crates/rea-core/src/decompile.rs`

**Retires:** the conditional half of `rea decompile` Stops before: "no dataflow across basic blocks". Iteration 2 retires the unconditional half and, by its own task text, leaves short conditional branches undone. Memory-object types, struct recovery, and cross-function dataflow stay unread (task 6.4 takes stack slots only).

After iteration 2's same-function unconditional walk, also follow one forward conditional (`jcc` on x86_64, `b.cond` on arm64) whose target is inside the same function and ahead of the branch. The 64-instruction cap and the depth cap of 8 stay. The visited-target set stays. A backward branch or a target outside the function is still a `goto` line and stops that path. Width types carry across the join only when every incoming path wrote the same type to the same register; otherwise the register becomes untyped at the join. An empty window is still `decompile: no instructions`.

**Difficulty:** hard

**Why last:** it changes the window shape the width-type tests lock down. A bad join rewrites `int v1` / `(void*)v1` fixtures from iteration 1.

**Commit:** `rea-rs: conditional flow in the pseudo-c window`
