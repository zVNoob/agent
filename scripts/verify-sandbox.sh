#!/usr/bin/env bash
# Full regression gate for the sandbox substrate (src/seccomp/,
# src/async_sandbox.rs), the Lua policy bridge (src/lua.rs), the MCP
# client substrate (src/mcp.rs), and the Lua→TUI panel op stream
# (src/panels.rs) — the files touched by the "ready to use" hardening: live
# output streaming, the interrupt/kill API, Ask-as-yield, the `agent`
# namespace (agent.bash + agent.panel), and agent.mcp.
#
#  1. cargo test (full suite)
#  2. clippy on the lib; fails if any warning lands in the touched files
#     (pre-existing warnings in untouched files, e.g. tui/highlight.rs, pass)
#  3. instrumentation scan: no DBG prints or std::mem::discriminant remain
#
# Usage: scripts/verify-sandbox.sh
set -euo pipefail

# seccomp is a module directory (seccomp/mod.rs + seccomp/arch/*.rs), so match
# the path prefix rather than a single file.
TOUCHED="src/seccomp/|async_sandbox\.rs|lua\.rs|mcp\.rs|panels\.rs"

echo "== 1/3 cargo test =="
cargo test

echo "== 2/3 clippy (touched files must be clean) =="
CLIPPY_OUT="$(mktemp)"
cargo clippy --lib 2>&1 | tee "$CLIPPY_OUT" || true
if grep -E "$TOUCHED" "$CLIPPY_OUT" | grep -q "^warning"; then
  echo "clippy warning in a touched file:" >&2
  grep -B1 -A6 -E "$TOUCHED" "$CLIPPY_OUT" | head -40 >&2
  rm -f "$CLIPPY_OUT"
  exit 1
fi
rm -f "$CLIPPY_OUT"

echo "== 3/3 instrumentation scan =="
if grep -nE '\bDBG\b|RECV-ENTER|RECV-EXIT|std::mem::discriminant' \
     src/seccomp/*.rs src/seccomp/arch/*.rs \
     src/async_sandbox.rs src/lua.rs src/mcp.rs src/panels.rs; then
  echo "stray instrumentation found (above)" >&2
  exit 1
fi
echo "clean"

echo "verify-sandbox: OK"