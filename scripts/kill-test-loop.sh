#!/usr/bin/env bash
# Stability gate for the sandbox interrupt path.
#
# The kill tests were the flake central to the "5s timer-starvation" debugging:
# the old code could let the kill timer never fire (the kernel's NOTIF_RECV
# blocks on an empty queue even with O_NONBLOCK, freezing the single-threaded
# runtime inside the ioctl). Run them repeatedly to catch any regression that
# re-introduces an intermittently starved reactor.
#
# These live in `seccomp`, not in the tokio readiness adapter that used to hold
# them: the shipped design drives a sandbox cooperatively as a Lua coroutine
# (see `src/lua.rs`, `ToolRun`), so the timer the starvation hit is the loop's.
#
# Usage: scripts/kill-test-loop.sh [N]      (default N=5)
set -euo pipefail

N="${1:-5}"
TESTS=(
  seccomp::tests::a_handle_stops_its_own_run_and_the_result_says_so
  seccomp::tests::a_request_reaches_only_the_run_whose_handle_it_came_from
  seccomp::tests::a_later_run_cannot_see_an_earlier_runs_request
)

for i in $(seq 1 "$N"); do
  echo "== iteration $i/$N =="
  if ! cargo test --lib -- "${TESTS[@]}" 2>&1 | tee /tmp/opencode/kill-loop.out | grep -q "test result: ok"; then
    echo "FAILED on iteration $i (full output in /tmp/opencode/kill-loop.out)" >&2
    exit 1
  fi
done

echo "kill tests: $N/$N passed"