#!/usr/bin/env bash
# Stability gate for the sandbox interrupt path.
#
# The kill tests were the flake central to the "5s timer-starvation" debugging:
# the old code could let the kill timer never fire (the kernel's NOTIF_RECV
# blocks on an empty queue even with O_NONBLOCK, freezing the single-threaded
# runtime inside the ioctl). Run them repeatedly to catch any regression that
# re-introduces an intermittently starved reactor.
#
# Usage: scripts/kill-test-loop.sh [N]      (default N=5)
set -euo pipefail

N="${1:-5}"
TESTS=(
  async_sandbox::tests::kill_handle_interrupts_a_running_tree_promptly
  async_sandbox::tests::kill_during_a_frozen_ask_terminates_promptly
)

for i in $(seq 1 "$N"); do
  echo "== iteration $i/$N =="
  if ! cargo test --lib -- "${TESTS[@]}" 2>&1 | tee /tmp/opencode/kill-loop.out | grep -q "test result: ok"; then
    echo "FAILED on iteration $i (full output in /tmp/opencode/kill-loop.out)" >&2
    exit 1
  fi
done

echo "kill tests: $N/$N passed"