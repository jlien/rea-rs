#!/bin/bash
# Iteration-2 task loop: one omp -p run per task, test gate between tasks.
cd /Users/jimmylien/Eng/wt-rea-rs-tasks-2 || exit 1
export PATH="$HOME/.bun/bin:$PATH"
mkdir -p .loop-tasks
: > .loop-tasks/loop.log
echo "LOOP START $(date)" >> .loop-tasks/loop.log
for i in 1 2 3 4 5 6; do
  if [ -f ".loop-tasks/task$i.done" ]; then echo "task $i already done, skip" >> .loop-tasks/loop.log; continue; fi
  echo "=== task $i START $(date) ===" >> .loop-tasks/loop.log
  omp -p "Read .loop-tasks/task$i.md and .loop-tasks/00-common.md, then execute the task fully, including its verification and doc-update steps. Work only inside this repository. Never push." >> .loop-tasks/loop.log 2>&1
  rc=$?
  echo "=== task $i omp rc=$rc $(date) ===" >> .loop-tasks/loop.log
  cargo test --workspace --offline >> .loop-tasks/loop.log 2>&1
  ok=$?
  echo "=== task $i test rc=$ok $(date) ===" >> .loop-tasks/loop.log
  if [ $ok -ne 0 ]; then
    echo "STOP: tests failed after task $i — leaving tree for human review" >> .loop-tasks/loop.log
    break
  fi
  touch ".loop-tasks/task$i.done"
done
echo "LOOP COMPLETE $(date)" >> .loop-tasks/loop.log
