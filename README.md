# agent

> **Work in progress.** The architecture is settled, the gate is green, and the
> boundaries below are decisions rather than defects. What is young is the
> project, not the design — and the one thing nobody has done yet is run it
> end to end. Read [Where the responsibility is](#where-the-responsibility-is)
> before you point it at anything you care about.

A coding agent in a terminal. A TUI over any OpenAI-compatible chat endpoint,
with a seccomp-sandboxed shell, file tools, and every layer above the API written
in Lua — including the tools, the sandbox policy, the permission prompts and the
modes.

## What is here

- A streaming TUI: turn stream, tool-drawn panels, a permission dialog at
  the bottom of the panel that raised it, a one-line status bar at the bottom,
  and `/reload`.
- A Lua surface for all of it: 33 locked bridge primitives, auto-required
  library modules, a mode system, an ask protocol with three answers, and the
  sandbox policy.
- A single-threaded process. One OS thread, a current-thread tokio runtime, no
  worker pool; tool calls, event handlers and HTTP all run as coroutines the
  event loop steps.
- A seccomp user-notify sandbox: `openat`, `unlinkat`, `renameat`/`renameat2`,
  `chmod`/`fchmodat`, `setxattr`/`lsetxattr`, `removexattr`/`lremovexattr`,
  `connect`, `bind` and `sendto` are intercepted, and each is *asked* about with
  its arguments decoded out of the frozen process. Reads, writes, deletes, moves,
  permission changes and capability changes are all questions about a path, and a
  move is two of them.

## Where the responsibility is

**The agent asks. You decide. Nothing is enforced beyond the decisions you make
in the moment.** That is the design, not a stage of it — the alternative, a
sandbox that decides on its own what a command may do, is a different product
with a different failure mode, and this one deliberately does not do that.

Which means the boundary is worth stating precisely, because the name
`sandbox` promises more than the mechanism delivers:

- **Asking is not confining.** The sandbox is a bare `fork()` with no
  `unshare`, so a command keeps the host's mount view and its network
  namespace. Gating `connect` means you are asked about each destination; it
  does not make the destination unreachable. See
  [What the sandbox is](#what-the-sandbox-is) for what does follow from that.
- **The agent's own network path is not gated either.** `agent.http` and
  `agent.mcp` are bridge primitives in the agent process, not syscalls in a
  sandboxed tracee, so no question is asked about them. If that matters for what
  you are running, it is your call to make — the mechanism to extend is the
  bridge, not the syscalls.
- **Trust is yours to grant and revoke, and it lasts as long as the process.** A
  path or endpoint you answer `always` for is remembered on the agent's own VM,
  so it holds for every later call and survives `/reload`, but not a restart.
  `agent.ask.forget` and `forget_server` take any of it back at any time.
- **The first run asks about every shared library, and it is a flood.** A cold
  `/bin/cat /dev/null` asks **55 times** on this machine — 51 distinct paths,
  spread over about two dozen directories. Most of it is not libraries: the
  loader probing CPU-variant directories that do not exist, plus locale
  catalogues. Trusting four paths in a config (`/usr/lib`, `/usr/share`,
  `/etc/ld.so.cache`, `~/.rustup/toolchains`) brings the same command down to
  **3** questions, and what is left is the command's own business. The working
  directory is trusted at startup, which does not help, since the libraries do
  not live there. See [Asks and trust](#asks-and-trust).
- **Headless, there is no one to ask, so everything is denied.** The probe, the
  tests and any run with no ask handler get a sandboxed command that reaches
  nothing it was not already trusted for.

Two smaller calls, both reversible and both ours to change on request: the policy
traps `sendto` as well as the three syscalls it was originally asked for, because
UDP has no handshake and leaving it out would make the `connect` gate trivially
bypassable; that it traps `renameat2` as well as `renameat`, because glibc's
`rename()` is `renameat2` now and gating only the other one would have left every
real `mv` ungated while still looking right; and that the `"all"` mode sentinel
currently has no shipped user, since `coding` names its registry instead.

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

The TUI wants a chat endpoint, and it configures itself from
`~/.config/agent/init.lua`. There is no such file on a fresh machine, so the
first run copies the shipped `lua/init.lua` there and runs *that* — after which
the copy is yours: edit it and press `/reload`. It is the whole configuration,
not an overlay, so what your file does not set up the agent does not have.

That starter file is written to be edited. The settings you will actually change
are marked `>>>`, each with its documentation attached, and the sections below
them explain how the rest fits together.

For a one-off, the environment overrides the endpoint: `AGENT_BASE_URL`,
`AGENT_MODEL`, `AGENT_API_KEY`.

| variable | |
|---|---|
| `AGENT_BASE_URL`, `AGENT_MODEL`, `AGENT_API_KEY` | the endpoint, when you would rather not write a config |
| `AGENT_LUA_DIR` | load a different Lua tree entirely, instead of the `lua/` beside the executable |

## The gate

```sh
cargo test && ./scripts/verify-sandbox.sh
```

`verify-sandbox.sh` must print `verify-sandbox: OK`. It checks that the seccomp
filter and the syscall tables have not drifted, and it is the check that the
sandbox is still there at all. The suite is 298 library tests, 12 in the binary
and 7 in the probe.

## How it is put together

The Rust side is the runtime: the chat client, the TUI, the seccomp engine, the
MCP transports and the Lua bridge. Everything a user would want to change is Lua,
and it is all in `lua/`:

| | |
|---|---|
| `lua/init.lua` | the starter configuration: the settings (`agent.llm`, the context window, the log), the tools, the modes, the trust grants and the automatic compaction — each documented where it is set, with the `>>>`-marked lines being the ones meant to be edited. Copied to `~/.config/agent/init.lua` on first run |
| `lua/lib/*.lua` | library modules, auto-required in sorted order and cached; each publishes itself on `agent` (`agent.ask`, `agent.bash`, `agent.mode`, `agent.utils`, …) |
| `lua/*.lua` | root modules, reached by name: `fs`, `bash_tool`, `policy`, `coding`, `compact`, `mcps` |
| `lua/api.lua` | the bridge's annotations, and what the loader checks at startup: a primitive without one, or one for a primitive that no longer exists, is a startup error |
| `lua/agent_api.meta.lua` | the same 33 primitives as LuaLS types, for editors |

`lua/init.lua` and `~/.config/agent/init.lua` share a name on purpose — they
are the same kind of thing, a chunk of Lua that configures the agent — and they
never meet: the shipped one is only what a fresh config is seeded from. Delete
your copy and the next run re-seeds it from whatever ships next, which is also
how you pick up a newer starter after an upgrade.

A tool is a connection — `{ name, tools }` — and `agent.mcps` is the registry of
them. The registry is the whole of what the agent can do: nothing is hard-coded
in Rust, the shell is a connection like any other, and what nobody registers does
not exist. Out of the box `lua/init.lua` registers exactly two — `fs` and
`bash`.

**A tool call puts nothing in the transcript.** Not the arguments, not the result,
not an error — the loop records the result for the model and draws nothing. A tool
is in charge of its own reporting, which is also the only way it can be formatted
properly: `agent.panel` opens a panel, `p:append` fills it, and `agent.split_panel`
splits it. The shell is the worked example — a panel titled with the command, with
stdout appended as it arrives. A tool that wants to be seen draws itself; a tool
that wants to be quiet is quiet. The cost is that a tool with nothing to say is
invisible, including when it fails — and the fix is the tool's, not the loop's.
The shipped `fs` tools each draw their own panel, and each asks its permission
question *inside* that panel, so a question is never asked into the void. `fs.read`
covers both kinds of path — a file comes back numbered, a directory comes back as
a listing — and shows only the resolved path, plus the one the model wrote when
the two differ. `fs.write_file` shows the bytes it wrote, highlighted.

`fs.hand_to_user` is the odd one out, and it exists because creating a file is
silent by design: a new name records write-trust for itself, so a directory full
of generated files is a set of paths the agent can keep rewriting with no further
questions. That is right while it is still building them and wrong once they are
yours, and nothing else in the system revokes a grant the agent made to itself.
`hand_to_user` takes those paths back, so the next write asks again. It touches
no file and therefore asks nothing itself; it also cannot widen anything, since a
path the agent was never granted has nothing to forget — and it reports which
paths those were, so a confused call is visible rather than quiet. Only the write
half is given up: reads of a handed-over file stay silent. `agent.ask.forget(path)`
takes both halves.

**An MCP tool is the exception, and the module draws for it.** Its code is on
the other side of the wire, so there is no arrangement in which it could report
itself — it would be invisible forever. `lua/lib/mcp.lua` therefore opens a panel
per call, titled `{connection}.{tool}`, before the request; fills it with the
result's text blocks, with `notifications/progress` appended as they arrive
(setting that callback is what asks the server for them); and marks a failure as
one. `agent.mcp(name, transport, { draw = false })` opts out, and then the
request on the wire is byte for byte what it always was.

## Modes

A mode is a prompt and a tool set, switched as a pair; `set` overwrites exactly
`agent.llm.system_prompt` and `agent.mcps`, and the next request already runs in
it. Two are built in and `coding` is the one in force: `coding` (the working
mode) and `compact` (no tools at all, so a compaction turn can only answer). A
config that wants neither drops them with `agent.mode.forget_all()`. See
`lua/lib/mode.lua`.

## The status bar

The bottom row is one line, and it is the only place anything reports *in
progress*: `streaming...` while a turn's answer is arriving, grammar acquisition
at startup (which is a registry lookup, a tarball and a C compile per language,
before the first frame — a cold cache used to be a blank screen), and anything
Lua `print`s. A second message replaces the first, so a run of progress steps
reads as the latest one rather than a queue, and the bar empties when the thing
it described is over rather than showing a state that has passed.

`print` is Lua's own, argument handling and all — `tostring` each argument, join
with tabs — pointed at the bar instead of stdout, because a TUI owns the terminal
and a stray print would scribble over it. Headless (the probe, the tests) there
is no screen, so `print` goes to stdout exactly as before. It is one line either
way: a status bar is not a log. Output meant to be read later belongs in a
panel, via `agent.panel`.

The `bash` tool titles its panel with the command it is running, so what ran is
visible without expanding anything. The title is one row, so the command is
flattened to a single line and cut with an ellipsis if it is still too wide for
the box — the full command is in the transcript either way, in the model's own
call.

## Asks and trust

Nothing that touches a file or an endpoint is decided silently. A tool asks
through its own panel — `panel:ask(text, always)` — and the question appears as
a **dialog at the bottom of that panel's own box**, under the output it has
produced so far:

```
┌─ cat /etc/hostname [−] ─────────────────────────────────┐
│                                                       │
│ ┌─ [y]es · [n]o · [a]lways ─────────────────────────┐ │
│ │ The process want to read /etc/hostname            │ │
│ └───────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────┘
```

The question belongs to the thing that raised it, and the panel is what raises
it, so there is no separate prompt in the transcript and nothing accumulates
while you think: a cold command asks dozens of times and the transcript still
grows by nothing. Your answer goes on the status bar — `allowed`, `allowed, and
remembered`, or `denied` — because one line cannot pile up.

`[a]lways` is offered only when the answer is one the agent can act on: a
question with a path or an endpoint to remember offers it, and one without does
not. Only `always` is remembered, as path trust or as a trustworthy-server
entry, kept in separate tables so revoking one never revokes the other.

With no one to ask at all — headless, the tests, the probe — every ask denies,
so a sandboxed run reaches nothing it was not already trusted for.

Path trust is a prefix, so trusting a directory trusts everything under it. That
is what makes the library flood survivable, and the shipped config spends it on
what a dynamically-linked program reads before its own first line — the loader's
cache, its map of the process, and every `DT_NEEDED` library and locale message:

```lua
agent.ask.trust_readonly("/usr")             -- libraries, binaries, locale, docs
agent.ask.trust_readonly("/lib")             -- -> /usr/lib on a merged-/usr system
agent.ask.trust_readonly("/etc/ld.so.cache") -- the loader's cache
agent.ask.trust_readonly("/proc/self/maps")  -- read by the loader, every exec
agent.ask.trust_readonly(os.getenv("HOME") .. "/.rustup/toolchains")
```

`trust_readonly` is a **third** table, not the general one, and the difference is
the point: "you may look here" and "you may make things here" are different
promises, and a system directory is only ever the first. Every read under `/usr`
is silent; every write, **create**, delete and move there still asks. That last
one is why it cannot be a plain `trust` — a create is otherwise silent by design,
and a read-only grant that let the agent quietly drop a file into `/usr` would not
be read-only at all. A *working directory* is granted with plain `trust`, so work
in a repository still creates quietly, which is the point of a working directory.

`/etc/ld.so.preload` is deliberately **not** granted. It is the file that decides
what gets loaded into every process, so trusting it would mean trusting whatever
it names, and those names are not the loader's to hold.

There is a **blocklist** as well as the three trust tables, and it is what makes
the others composable. A directory grant covers its whole subtree, so trusting
the working directory trusts every file in it — and without a negative there is
no way to take one back:

```lua
agent.ask.trust(cwd)              -- the project, quietly
agent.ask.block(cwd .. "/.env")   -- except this
agent.ask.block(cwd .. "/.git")   -- and this whole tree
```

A block is a **preference, not a one-way door**: `trust` on a path that carries
a block of its own lifts the block and grants, so changing your mind is just
trusting it again. But *exact* is the load-bearing word. A block on a **directory**
is a statement about a tree, so naming something inside it does not lift it —
`block("/a")` then `trust("/a/b")` is refused, because the only way to say "not
in this tree" is to say it about the tree. Lift the directory block, or grant the
directory.

`unblock` is the explicit spelling of the same lift, and either way the enclosing
grant was never revoked — only stood in front of. `forget(path)` reaches the same
place: given a path with no grant of its own but covered by a directory that has
one, it blocks it rather than dropping nothing. Calling `forget` twice leaves
nothing behind.

One asymmetry worth knowing: a block also stops the policy's *create* rule from
silently trusting a new name, so the agent cannot un-block a path you excluded by
creating a file at it. The automatic grant stays out of it; only a `trust` in your
config lifts a block.

The working directory is trusted at startup, so work inside a repository asks
nothing. `forget` takes a grant back, `forget_write` the write half only,
`forget_readonly` the read-only one, and `forget_all` empties every table. Each
is listed by `trusted_paths`, `trusted_write_paths`, `trusted_readonly_paths` and
`blocked_paths`.

## What the sandbox is

It is a **syscall filter that asks**, and calling it a jail would be a lie about
what it does. A command runs as a plain `fork()` of the agent — no namespaces,
no chroot, no dropped capabilities — and every syscall the policy names is
intercepted, decoded, and put to you before it runs.

The mechanics, stated so there is nothing to discover later:

- **Anything not named in the policy is not intercepted at all.** The policy's
  keys *are* the mask, so a syscall nobody named runs straight through the kernel
  under its default (allow) and never reaches a callback. The policy is four
  syscalls because those four are all anyone asked to gate — not because the
  other ~300 were considered and cleared.
- **`agent.http` and `agent.mcp` are not syscalls.** They are bridge primitives
  in the agent process, so no filter and no question stands between a tool and
  the network through them. Only a command inside a sandboxed run is gated.
- **A denied syscall kills the tracee.** That is the enforcement, and it is
  coarse: the whole run ends, not just the call.
- **The network stays shared.** No `unshare(CLONE_NEWNET)`, so a sandboxed
  command is in the host's network namespace: `ss` lists every listener, and
  anything on `127.0.0.1` it can guess is reachable. Gating `connect` makes you
  the one who decides, not the gate.

What it does give, and the reason to want it: a real kernel-level floor under
every decision *you* make, the arguments of a frozen syscall read out of the
process — including the `struct sockaddr` of a `connect`, so a question can name
the host and the port rather than just "a connection" — and a prompt with three
answers, so the decision is yours and stays yours until you revoke it.

In one line: **it moves the decision to you at the moment it matters, and gets
out of the way.** It does not make the decision for you, and it is not trying to
be the only thing between the command and the machine.
