# Adversarial review of iteration 5

You are reviewing iteration 5 of rea-rs in THIS worktree before it merges to main.
The iteration is the commits `git log --oneline $(git merge-base main HEAD)..HEAD`.
The briefs are .loop-tasks/task1.md .. task6.md; the standing rules are .loop-tasks/00-common.md.

For each task, check:
1. Tests assert real behavior — no tautologies (assert true, assert eq of a constant with itself),
   no test that passes whether or not the feature works. Flag any test that only re-derives its
   input.
2. Parsing is panic-safe on malformed input. Hunt for unwrap/expect/indexing on untrusted bytes
   that a truncated or adversarial fixture would crash. Every panic you can trigger with a small
   synthetic input is a blocking finding.
3. Documentation is honest. Read the README.md and docs/rea-rs-review.html changes in the diff:
   every claim must match what the code actually does. Overclaims ("X is now supported" when only
   a subset is) are blocking. Clauses must be relaxed only as far as the work went.
4. Scope stayed inside the brief. Flag scope creep and flag missing required sub-items.
5. Run `cargo test --workspace --offline`. Any failure is blocking. No new warnings allowed.

Write your findings to .loop-tasks/review.md (create/overwrite it), terse and specific
(file:line, what is wrong, why it blocks). Then end the file with exactly one line:

VERDICT: PASS

if the iteration is merge-ready, or:

VERDICT: FAIL

with the blocking findings listed above it. Fix nothing yourself — you are a reviewer, not a
patch author. Do not push, do not commit, do not modify any source file.
