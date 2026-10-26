# A32 function seeds

**Where:** `crates/rea-core/src/analysis.rs`

**Retires:** "Out of this tree": "A32 function seeds".

`Arch::Arm` prologue scan is Thumb only (`push {r7, lr}`, bytes `80 b5`). The PC-relative xref pass already disassembles A32 in a second Capstone handle. Also seed 4-byte-aligned `push {r11, lr}` / `stmfd sp!, {..., lr}` words, and disassemble those bodies in ARM mode, ending at `bx lr`. Thumb seeds stay in Thumb mode. Do not switch mode in the middle of a section. The funcs row "A ground-truth procedure list. Counts are a heuristic." stays. Update the `/bin/ls` call-graph numbers only if they move; `/bin/ls` on this machine is arm64, so the fixture is synthetic.

**Difficulty:** medium

**Commit:** `rea-rs: a32 function seeds`
