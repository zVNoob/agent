# agent

> **Work in progress.** The architecture is settled and the test suite is green,
> but several things are known to be wrong or unfinished. They are listed under
> [Status](#status) rather than left for you to discover.

A coding agent in a terminal. A TUI over any OpenAI-compatible chat endpoint,
with a seccomp-sandboxed shell, file tools, and every layer above the API written
in Lua — including the tools, the sandbox policy, the permission prompts and the
modes.

## Status

Working, and covered by tests:

- A streaming TUI: turn stream, streamed tool panels, an ask overlay on the
  shell's result panel, and `/reload`.
- A Lua surface for all of it: 33 locked bridge primitives, auto-required
  library modules, a mode system, an ask protocol with three answers, and the
  sandbox policy.
- A single-threaded process. One OS thread, a current-thread tokio runtime, no
  worker pool; tool calls, event handlers and HTTP all run as coroutines the
  event loop steps.
- A seccomp user-notify sandbox: `openat`, `connect`, `bind` and `sendto` are
  intercepted and *asked* about, with the syscall's arguments decoded out of the
  frozen process.

Not finished, in rough order of how much they matter:

1. **The sandbox asks; it does not confine.** It is a bare `fork()` with no
   `unshare`, so a command keeps the host's mount view and network namespace.
   Gating `connect` means the user is asked about each destination — it does not
   make the destination unreachable. See
   [What the sandbox does not do](#what-the-sandbox-does-not-do).
2. **The agent's own network access is ungated.** `agent.http` and `agent.mcp`
   run in the agent process, not in the sandboxed tracee, so nothing asks about
   them. A tool can reach the network through `agent.http` while the shell is
   asked about every `connect`. Closing this means gating the bridge primitives,
   not the syscalls.
3. **The first run asks about every shared library.** Gating every read means a
   command's own `.so` files are questions: one `cat` is roughly twenty of them.
   The working directory is trusted at startup (`lua/init.lua`), which does not
   help, since they live in `/usr/lib` and `~/.rustup`. Answering `always` once
   per program is the current answer; a default trust for the runtime
   directories would be better.
4. **Trust lives for the process, not for the machine.** A path trusted with
   `always` is remembered on the agent's own VM, so it survives every later tool
   call and `/reload`, but not a restart. A permission system probably wants a
   file under `~/.config/agent/`.
5. `lua/policy.lua` traps `sendto` as well as the three syscalls it was asked
   for. UDP has no handshake, so a datagram leaves without the peer ever
   answering; leaving it out would make the `connect` gate trivially bypassable.
   It is a judgement call, not a requirement.
6. The `"all"` mode sentinel has no shipped user, since `coding` names its
   registry instead.

## Running it

```sh
cargo run                              # the TUI
cargo run --bin agent_probe            # one headless turn, sandbox smoke test
cargo run --bin agent_probe -- "…"     # …or ask it something
./scripts/verify-sandbox.sh            # the gate
```

The probe with no argument runs `echo hello-from-sandbox` through the shell, which
is the quickest end-to-end check that the sandbox, the ask path and the panel
plumbing are all still wired together.

The TUI wants a chat endpoint. `agent.lua` ships pointed at a local llama.cpp on
`localhost:8080`; point it anywhere with `agent.llm.base_url` and `.model`, or
with the `AGENT_*` environment variables, which still override.

Configuration is `./agent.lua`, then `~/.config/agent/agent.lua`. `agent.lua` is
a slate: the endpoint, the prompt, the tools, the modes, and nothing else. The
reference material for everything else is in `lua/init.lua`, which runs just
before it.

## The gate

```sh
cargo test && ./scripts/verify-sandbox.sh
```

`verify-sandbox.sh` must print `verify-sandbox: OK`. It checks that the seccomp
filter and the syscall tables have not drifted, and it is the check that the
sandbox is still there at all. The suite is 298 library tests, 12 in the binary,
7 in the probe and 5 in the trace harness.

## How it is put together

The Rust side is the runtime: the chat client, the TUI, the seccomp engine, the
MCP transports and the Lua bridge. Everything a user would want to change is Lua,
and it is all in `lua/`:

| | |
|---|---|
| `lua/init.lua` | the entry script, run last on every VM: the `agent.llm` defaults, the cwd trust, automatic compaction, and the reference documentation for the whole configuration surface |
| `lua/lib/*.lua` | library modules, auto-required in sorted order and cached; each publishes itself on `agent` (`agent.ask`, `agent.bash`, `agent.mode`, `agent.utils`, …) |
| `lua/*.lua` | root modules, reached by name from a config: `fs`, `bash_tool`, `policy`, `coding`, `compact`, `mcps` |
| `lua/api.lua` | the bridge's annotations, and what the loader checks at startup: a primitive without one, or one for a primitive that no longer exists, is a startup error |
| `lua/agent_api.meta.lua` | the same 33 primitives as LuaLS types, for editors |
| `agent.lua` | the slate |

A tool is a connection — `{ name, tools }` — and `agent.mcps` is the registry of
them. There is no built-in catalog: the shell is a connection like any other, and
the ones you do not register do not exist.

## Modes

A mode is a prompt and a tool set, switched as a pair; `set` overwrites exactly
`agent.llm.system_prompt` and `agent.mcps`, and the next request already runs in
it. Two ship: `coding` (the working mode) and `compact` (no tools at all, so a
compaction turn can only answer). See `lua/lib/mode.lua`.

## Asks and trust

Nothing that touches a file or an endpoint is decided silently. The question is
put with `[y]es  [n]o  [a]lways`, and only `always` is remembered — as path
trust, or as a trustworthy-server entry, kept in separate tables so revoking one
never revokes the other. A question with nothing to remember is asked as
`[y]es  [n]o`. With no one to ask — headless, the tests, the probe — every ask
denies, so a sandboxed run reaches nothing it was not already trusted for.

## What the sandbox does not do

This is the part worth being precise about, because the name suggests more than
it delivers.

It is a **syscall filter, not a jail**. A command runs as a plain `fork()` of the
agent: no namespaces, no chroot, no dropped capabilities. Therefore:

- **The network is visible and reachable.** `ss` or `/proc/net/tcp` lists every
  listener on the machine, and anything bound to `127.0.0.1` that a command can
  guess can be connected to. Gating `connect` puts the question to the user; it
  does not make the destination unreachable. Real confinement needs
  `unshare(CLONE_NEWNET)`.
- **Anything not named in the policy is not intercepted at all.** The policy's
  keys *are* the mask, so a syscall nobody named runs straight through the kernel
  under its default (allow) and never reaches a callback.
- **The agent's own network access is a different path entirely.** `agent.http`
  and `agent.mcp` are bridge primitives in the agent process, not syscalls in a
  sandboxed tracee, so the policy does not see them.
- **A denied syscall kills the tracee.** That is the enforcement, and it is
  coarse: the whole run ends, not just the call.

What it does give: a real kernel-level floor under the *decisions it makes*, the
ability to read a syscall's arguments — including the `struct sockaddr` of a
`connect` — out of the frozen process, and a question the user can answer.
