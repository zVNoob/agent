# agent

**A coding agent in your terminal, where the sandbox asks you instead of deciding for you.**

A streaming TUI over any OpenAI-compatible endpoint — with a seccomp sandbox that
intercepts thirty-one syscalls and puts each one to you with its arguments
decoded out of the frozen process, file tools, and every layer above the API
written in Lua. Including the tools, the sandbox policy, the permission prompts,
and the modes.

```
┌─ response ──────────────────────────────────────────────────────────────────┐
│                                                                          │
│  I'd like to look at the test for `wrap_lines` before I touch it.        │
│                                                                          │
├─ cat src/tui/mod.rs ───────────────────────────────────────────────────────┐
│                                                                          │
│   736│ pub fn wrap_lines(text: &str, width: usize) -> Vec<String> {      │
│   737│     if width == 0 {                                               │
│   738│         return vec![String::new()];                               │
│   739│     }                                                             │
│   740│     let mut out = Vec::new();                                     │
│   741│     for para in text.split('\n') {                                │
│   742│         if para.is_empty() {                                      │
│   743│             out.push(String::new());                               │
│                                                                          │
│ ┌─ [y]es · [n]o · [a]lways ───────────────────────────────────────────┐ │
│ │ The process want to read src/tui/mod.rs                            │ │
│ └────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
 Ctrl+d quit · Ctrl+c stop                                                          │
```

> **Work in progress.** The architecture is settled and the gate is green; the
> boundaries below are decisions, not defects. What is young is the project, not
> the design — and nobody has yet run this end to end against a real model.
> [Read the security model](#security-model) before you point it at anything you
> care about.

---

## Contents

- [Quick start](#quick-start) · [What's in the box](#whats-in-the-box)
- [How it works](#how-it-works) · [Security model](#security-model)
- [Writing a tool](#writing-a-tool) · [Configuration](#configuration)
- [Keys](#keys) · [Asks and trust](#asks-and-trust)
- [The sandbox](#the-sandbox) · [Project layout](#project-layout)
- [Development](#development) · [Status](#status)

---

## Quick start

```sh
git clone <this repo> && cd agent
make install PREFIX=~/.local          # no root needed; /usr/local is the default
~/.local/bin/agent
```

That installs two things, and both are needed:

```
<prefix>/bin/agent            the executable
<prefix>/share/agent/lua/     the tree — the sandbox policy, the tools, the
                              starter configuration, as editable files
```

The tree is files rather than something compiled into the binary on purpose: a
tool that asks you before it touches a file ought to let you *read* the policy it
is asking you to approve. `<prefix>` can be anywhere and the binary finds it by
walking up from its own path, so it stays relocatable. `$AGENT_LUA_DIR` overrides
the search if you keep the tree somewhere else.

You need a C compiler for grammar highlighting — parsers are built from source at
first use — and a network for the first grammar fetch. Nothing else is needed
beyond a recent Rust toolchain to build it.

**On first run** the agent copies its own starter config to
`~/.config/agent/init.lua`, and says so. That file *is* the configuration — what
it does not set up, the agent does not have — and there is no endpoint flag, so
this is the step that cannot be skipped:

```sh
$EDITOR ~/.config/agent/init.lua       # the settings are the lines marked >>>
~/.local/bin/agent                     # press /reload after editing; no restart
```

One other binary is worth having while you are getting there:

```sh
cargo run --bin agent_probe            # one headless turn through the sandbox
cargo run --bin agent_probe -- "…"     # …or ask it something
```

With no argument the probe runs `echo hello-from-sandbox` through the shell, which
is the quickest end-to-end check that the sandbox, the ask path and the panel
plumbing are all still wired together.

`make uninstall PREFIX=…` reverses the install. Nothing is written outside
`<prefix>` and `~/.config/agent`.

---

## What's in the box

| | |
|---|---|
| **Streaming TUI** | turn stream, tool-drawn panels, a permission dialog at the bottom of the panel that raised it, a one-line status bar, `/reload`, `/save` |
| **A seccomp sandbox that asks** | thirty-one syscalls intercepted; reads, writes, deletes and moves are questions about a *path*, and a move is two of them — plus the gates that would otherwise walk past every one of those paths, above all `io_uring` |
| **Lua for everything above the API** | 36 locked bridge primitives, nine auto-required library modules, a mode system, an ask protocol with three answers, the sandbox policy, the tools |
| **One thread** | one OS thread, a current-thread tokio runtime, no worker pool — tool calls, event handlers and HTTP are coroutines the event loop steps |
| **Runtime syntax highlighting** | tree-sitter grammars fetched from a registry, compiled with your `cc`, and `dlopen`'d — and applied to text already on screen, mid-conversation, including inside a `write_file` or `apply_patch` panel |
| **MCP** | a pure-Lua client (`agent.mcp`) that talks to any transport you inject, with per-call progress streaming and its own panels |

---

## How it works

```
                    ┌──────────────────────────────────────────┐
  OpenAI-compatible │  src/api.rs — SSE stream → TurnEvents     │
  chat endpoint  ──▶│                                          │
                    └────────────────┬─────────────────────────┘
                                     │  TurnEvent::ToolCallDelta
                                     ▼
   ┌─────────────────────────────────────────────────────────────────────┐
   │  src/main.rs — one event loop, one thread                           │
   │    • renders, steps coroutines, drains panel ops, pumps grammars    │
   └───┬──────────────────────────────────────────────┬──────────────────┘
       │                                              │
       ▼                                              ▼
  ┌────────────────────┐              ┌───────────────────────────────┐
  │ ToolRun (Lua coro) │              │ grammar acquisition (tokio)  │
  │  on the config VM  │              │  registry → tarball → cc →   │
  └─────────┬──────────┘              │  dlopen → re-highlight       │
            │ agent.bash              └───────────────────────────────┘
            ▼
  ┌────────────────────┐      ┌──────────────────────────────────┐
  │  lua/lib/bash.lua  │─────▶│ seccomp user-notify on a fork()  │
  │  + lua/policy.lua │      │  31 syscalls → ask → verdict     │
  └────────────────────┘      └──────────────────────────────────┘
            │                              │
            └──────────► PanelSink ◄──────┘
                          (agent.api.panel_*)
                                │
                                ▼
                        TurnPanel (transcript)
```

The one thing worth internalising: **a tool call runs as a Lua coroutine on the
agent's own config VM.** Not a thread, not a subprocess — the same VM that holds
your configuration. That is what makes a path you answer `always` to still be
trusted on the *next* tool call, and it is why the trust tables used to die with
each call before they were moved.

---

## Security model

**The agent asks. You decide. Nothing is enforced beyond the decisions you make
in the moment.** That is the design, not a stage of it — the alternative, a
sandbox that decides on its own what a command may do, is a different product
with a different failure mode, and this one deliberately does not do that.

The name `sandbox` promises more than the mechanism delivers, so the boundary is
worth stating precisely:

- **Asking is not confining.** A command is a plain `fork()` with no `unshare`,
  so it keeps the host's mount view and its network namespace. Gating `connect`
  means you are asked about each destination; it does not make the destination
  unreachable. `ss` lists every listener, and anything on `127.0.0.1` a command
  can guess is reachable.
- **The agent's own network path is not gated at all.** `agent.http` and
  `agent.mcp` are bridge primitives *in the agent process*, not syscalls in a
  sandboxed tracee, so no question is asked. If that matters for what you are
  running, it is your call — and the mechanism to extend is the bridge, not the
  syscalls.
- **Headless, there is no one to ask, so everything is denied.** The probe, the
  tests, and any run with no ask handler get a command that reaches nothing it was
  not already trusted for.
- **Trust lasts as long as the process.** A path or endpoint you answer `always`
  to is remembered on the agent's VM, so it holds for every later call and
  survives `/reload` — but not a restart. `agent.ask.forget` and `forget_server`
  take any of it back at any time. A **capability** is the exception: it lasts
  one sandbox run, because there is no specific thing about it to outlive
  anything.
- **Allowing a capability is a wider answer than allowing a file.** A `yes` on
  `io_uring` means the program may now do that — and, since a ring can do the
  file work this policy asks about without asking, that it may also do all of
  that silently, for the rest of the run. Its third answer says so in its own
  name (`lways this run`) rather than as a plain `always`, because that is the
  honest scope. Read the second clause of the question; the first is the verb.
- **The first run is a flood, by design.** A cold `/bin/cat /dev/null` asks
  dozens of times — once per file: the loader's cache and map, every
  `DT_NEEDED` library, the locale catalogues, and the CPU-variant directories it
  probes that do not exist. The shipped config pre-grants the boring ones (see
  [Asks and trust](#asks-and-trust)); the working directory being trusted does
  not help here, because the libraries do not live there.

Two smaller calls, both reversible and both ours to change on request: the policy
traps `sendto` alongside the other twelve, because UDP has no handshake and
leaving it out would make the `connect` gate trivially bypassable; and it traps
`renameat2` as well as `renameat`, because glibc's `rename()` is `renameat2` now,
so gating only the other one would leave every real `mv` ungated while still
looking right.

---

## Writing a tool

There is no Rust. A tool is a *connection* — `{ name, tools }` — and
`agent.mcps` is the registry of them. The registry is the whole of what the agent
can do: the shell is a connection like any other, and what nobody registers does
not exist.

```lua
agent.mcps.mine = {
  name = "mine",
  tools = {
    hello = agent.utils.tool("Say hello.", {
      type = "object",
      properties = { who = { type = "string", description = "who to greet" } },
      required = { "who" },
    }, function(args)
      return { ok = true, result = "hello, " .. args.who }
    end),
  },
}
```

The model sees it as `mine.hello` — tools are advertised as `{connection}.{tool}`,
so two servers offering the same tool name do not collide. The callback returns
the MCP shape: `{ ok = true, result = … }`, `{ ok = false, error = "…" }`, or a
bare `false` to deny.

**A tool call puts nothing in the transcript.** Not the arguments, not the result,
not an error — the loop records the result for the model and draws nothing. A tool
is in charge of its own reporting, which is also the only way it can be formatted
properly:

```lua
local p = agent.panel("my report", { boxed = true })
p:append("done\n")
p:ask("delete the scratch file?", false)   -- the dialog, inside this box
```

The cost of that choice is that a tool with nothing to say is invisible,
*including when it fails* — and the fix is the tool's, not the loop's. The one
exception is an MCP tool, whose code is on the other side of the wire and so
could never report itself: `lua/lib/mcp.lua` therefore draws for it, one panel
per call, and `{ draw = false }` opts out.

The shipped tools are all in `lua/`, all documented where they are set:

| tool | what it does |
|---|---|
| `fs.read` | a file comes back numbered, a directory as a listing; shows the resolved path, and the one the model wrote when the two differ |
| `fs.write_file` | asks first; draws the bytes it wrote, with the file's language declared so the highlighter runs on it |
| `fs.apply_patch` | a pure-Lua unified-diff engine, asked once for the file it is about to edit; draws a **split** panel — before on the left, after on the right, each pane declaring its own language |
| `fs.hand_to_user` | gives write-trust on paths back, so the next write asks again. Exists because *creating* a file is silent by design, which is right while the agent is still building them and wrong once they are yours |
| `bash.bash` | runs a command through the seccomp sandbox under the Lua policy, streaming stdout into a panel titled with the command |

---

## Configuration

Everything is `~/.config/agent/init.lua`, a chunk of Lua. The lines you will
actually want to change are marked `>>>`, each with its documentation attached,
and the sections around them explain the rest.

| § | what it holds |
|---|---|
| 1 · THE ENDPOINT | base URL, model, key and system prompt — the `>>>` lines |
| 2 · THE CONTEXT WINDOW | the size that turns automatic compaction on |
| 3 · THE CONVERSATION LOG | where the transcript is archived |
| 4 · TOOLS | which connections are registered; out of the box, `fs` and `bash` |
| 5 · MODES | `coding` (the working mode) and `compact` (no tools at all) |
| 6 · TRUST | the pre-grants that keep the first run survivable |
| 7 · WHAT HAPPENS AT THE END OF A TURN | the automatic compaction policy |
| 8 · KEYS | the whole binding table |
| 9 · WHAT IS NOT IN THIS FILE | what you must not put in a config, and why |

`lua/init.lua` and `~/.config/agent/init.lua` share a name on purpose — they are
the same kind of thing.

Once you have edited yours, the two never meet: yours is the configuration, and
the shipped one is only what a fresh install is seeded from. **One line is
enough to take ownership of the whole file.** Until then, the agent keeps a copy
of exactly what it seeded you (`~/.config/agent/.init.lua.seeded`) and refreshes
your config from the shipped one on an upgrade — because that file is 36 KB of
prose and it is the only documentation of the configuration, so a fix to it would
otherwise reach nobody who installed the agent in its first week. When that
happens the startup line says so. If you have edited the file, nothing is
touched, ever; delete it and the next run re-seeds from whatever ships now.

### Environment

There is almost none, deliberately: the endpoint is configuration, not an
environment variable.

| variable | read by |
|---|---|
| `AGENT_LUA_DIR` | anything that builds a Lua VM — the TUI and `agent_probe`. Loads a different tree instead of the `lua/` beside the executable (used only if it holds an `init.lua`, else `./lua`) |
| `AGENT_BASE_URL`, `AGENT_MODEL`, `AGENT_API_KEY` | **only `agent_probe`**, and only when any one of them is set. A dev-harness override so an existing headless invocation keeps working; the TUI has no environment override at all |

### Modes

A mode is a prompt and a tool set, switched as a pair — `set` overwrites exactly
`agent.llm.system_prompt` and `agent.mcps`, and the next request already runs in
it. `compact` narrows to nothing, so a compaction turn can only answer.
`agent.mode.forget_all()` drops both built-ins. See `lua/lib/mode.lua`.

---

## Keys

Rust binds two keys and nothing else: `Ctrl+c` (stop the running command) and
`Ctrl+d` (leave). Everything else — `Enter`, `Esc`, `q`, `Alt+c`, `Alt+Enter`,
scrolling — is a config's business, bound by name in Lua:

```lua
agent.on_event("key", function(k) return BIND[k.spec] end)   -- see lua/init.lua §8
```

The handler is given `spec` (the chord as a table writes it — `alt+enter`,
`ctrl+c`, `f5`), `char`, and the three modifier booleans, and returns an action
name — `newline`, `send`, `quit`, `interrupt`, `conceal`, `scroll_up`,
`scroll_down`, `top`, `bottom` — or nothing, meaning the key keeps its default.

**Returning a name is a shorthand, not the limit.** A handler can also call
`agent.api.input_insert(text)` (or `input_backspace` / `input_clear`) and change
the input line directly, so a binding is not limited to a set of actions frozen
into Rust — a chord bound to `input_insert("0")` types a zero mid-sentence, which
is what a leader key is for. That is why `Alt+Enter` is a line in `lua/init.lua`
rather than a Rust default: it was kept here as a "fallback for terminals that
cannot send the chord", which was never true, because such a terminal does not
deliver a distinguishable event and Rust would not have received one either.

**A bare letter is a character first and a command second.** A letter reaches an
action only when the input line is empty; a chord always does. That one rule is
what makes a flat table safe — without it, `BIND["q"] = "quit"` would quit the app
halfway through the word "quick" — and it lives in Rust precisely so a config gets
it for free. It is also why leaving is `Ctrl+d` and not a letter. Input edits are
exempt: by the time one is queued a command has already been chosen, so a leader
key works mid-sentence.

**Pasting keeps its newlines.** The terminal is put into bracketed-paste mode,
so a paste arrives as one event carrying its text rather than a stream of
keypresses, and a newline inside it lands in the input line as a newline instead
of sending a half-finished message. That difference is not recoverable from the
receiving end — a `\r` in a stream of keypresses is indistinguishable from the
user pressing Enter — so it has to be the terminal telling us, and a terminal
that does not support it just pastes as before.

Pasted text is normalised rather than trusted, because a paste is arbitrary
clipboard content: `\r\n` becomes one newline (not two, and not a stray return
per line), tabs and other control characters become spaces, and no control
character reaches the renderer — so a paste can never move the cursor or clear
the screen. A paste is also never submitted on its own, and never submitted while
a permission question is on screen.

Two more things the event machinery gets right:

- The event is **not fired while a permission question is on screen**. `y`/`n`/`a`
  are verdicts there, and a table that could redirect them could answer a
  question by accident. `Ctrl+c` is the deliberate exception — it *does* work
  with a question up, because the command asking is the one thing worth
  interrupting, and its tree is frozen on that very question.
- `[y]es` / `[n]o` in a dialog are clickable, and a click is turned into the
  letter inside the brackets and run through the same `ask_choice` a keypress
  uses — so a pointer and a keypress are the same decision *by construction*
  rather than by two copies agreeing.

`Ctrl+c` reaches the sandbox through a per-run flag, not a signal: the caller has
no reference to the running tree, which lives inside the tool's coroutine, and it
cannot signal a pid because the tree grows as it forks. The request travels to the
one place that can act, which kills the whole captured tree and lets the run
finish the ordinary way — so the result comes back marked `interrupted` rather
than looking like a crash.

---

## Asks and trust

Nothing that touches a file or an endpoint is decided silently. A tool asks
through its own panel — `panel:ask(text, always)` — and the question appears as a
**dialog at the bottom of that panel's own box**, under the output it has produced
so far:

```
┌─ cat /etc/hostname [−] ─────────────────────────────────┐
│                                                       │
│ ┌─ [y]es · [n]o · [a]lways ─────────────────────────┐ │
│ │ The process want to read /etc/hostname            │ │
│ └───────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────┘
```

The question belongs to the thing that raised it, so there is no separate prompt
in the transcript and nothing accumulates while you think. Your answer goes on the
status bar — `allowed`, `allowed, and remembered`, or `denied` — because one line
cannot pile up.

Every question from a sandboxed command also names **who is asking** — the pid,
and the process's own `/proc` command line:

```
┌─ [y]es · [n]o · [a]lways ──────────────────────────┐
│ The process want to write /etc/cron.d/agent (O_WRONLY│
│ |O_CREAT) (pid 41337) [make -C /srv/app install]     │
└─────────────────────────────────────────────────────┘
```

That is not decoration. A question naming only a path is not answerable on its
own: `/tmp/build.log` is a file the agent is expected to touch, and something
else asking for it is a different question entirely — and an answer to one is not
the answer to the other. The pid says *which* process; the command line is what
you read to tell a `make` from a `curl` from a process that has renamed itself
to look like one of them. When `/proc` cannot be read the line is dropped and the
pid is shown alone, because `[]` reads as a field you left blank rather than a
process that has already exited.

`[a]lways` is offered only when the answer is one the agent can act on: a question
with a path or an endpoint to remember offers it, and one without does not. Only
`always` is remembered, as path trust or as a trustworthy-server entry, kept in
separate tables so revoking one never revokes the other.

### The four tables

| | |
|---|---|
| `trust(path)` | may be here at all |
| `trust_write(path)` | …and may make things here |
| `trust_readonly(path)` | may be *looked at*, and no more — this is the system tree |
| `block(path)` | never, whatever a grant above says |

Path trust is a prefix, so trusting a directory trusts everything under it. That
is what makes the library flood survivable, and the shipped config spends it on
what a dynamically-linked program reads before its own first line:

```lua
-- lua/init.lua §6, verbatim in shape
for _, ro in ipairs({
  "/lib", "/lib64", "/usr",                 -- libraries, binaries, locale, docs
  "/etc/ld.so.cache",                       -- the loader's own cache
  "/proc/self/maps",                        -- read by the loader, every exec
  "/proc/filesystems",                      -- glibc lists fs types, every exec
}) do
  agent.ask.trust_readonly(ro)
end
-- and the /dev entries that carry nothing, plus a write grant on /dev/null
```

`trust_readonly` is its own table rather than the general one, and the difference
is the point: "you may look here" and "you may make things here" are different
promises, and a system directory is only ever the first. Every read under `/usr` is
silent; every write, **create**, delete and move there still asks. That last one is
why it cannot be a plain `trust` — a create is otherwise silent by design, so a
read-only grant that let the agent quietly drop a file into `/usr` would not be
read-only at all. A *working directory* is granted with plain `trust`, so work in a
repository still creates quietly, which is the point of a working directory.

`/etc/ld.so.preload` is deliberately **not** granted: it decides what gets loaded
into every process, so trusting it would mean trusting whatever it names.

`block` is what makes the grants composable — a directory grant covers its whole
subtree, and without a negative there is no way to take one back:

```lua
agent.ask.trust(cwd)              -- the project, quietly
agent.ask.block(cwd .. "/.env")   -- except this
agent.ask.block(cwd .. "/.git")   -- and this whole tree
```

A block is a **preference, not a one-way door**: `trust` on a path that carries a
block of its own lifts the block and grants, so changing your mind is just trusting
it again. But *exact* is the load-bearing word — a block on a **directory** is a
statement about a tree, so naming something inside it does not lift it. `unblock`
is the explicit spelling of the same lift, and `forget(path)` reaches the same
place. One asymmetry worth knowing: a block also stops the policy's *create* rule
from silently trusting a new name, so the agent cannot un-block a path you
excluded by creating a file at it.

The working directory is trusted at startup. `forget` takes a grant back,
`forget_write` the write half only, `forget_readonly` the read-only one, and
`forget_all` empties every table. Each is listed by `trusted_paths`,
`trusted_write_paths`, `trusted_readonly_paths` and `blocked_paths`.

---

## The sandbox

It is a **syscall filter that asks**, and calling it a jail would be a lie about
what it does. A command runs as a plain `fork()` of the agent — no namespaces, no
chroot, no dropped capabilities — and every syscall the policy names is
intercepted, decoded, and put to you before it runs.

```
# files and endpoints — a question about a path, a host, a port
openat  unlinkat  renameat  renameat2  chmod  fchmodat  fchmod
setxattr  lsetxattr  removexattr  lremovexattr
connect  bind  sendto  name_to_handle_at
link  linkat  symlink  symlinkat

# capabilities — a question about the syscall itself, and nothing to remember
io_uring_setup  io_uring_enter  io_uring_register
open_by_handle_at  memfd_create  pidfd_getfd
process_vm_readv  process_vm_writev  bpf  userfaultfd
pkey_alloc  pkey_mprotect  pkey_free
```

- **Anything not named in the policy is not intercepted at all.** The policy's
  keys *are* the mask, so a syscall nobody named runs straight through the kernel
  under its default (allow) and never reaches a callback. Each of the
  thirty-one is a decision. `mkdirat` and `rmdir` are left out on purpose. The
  mask is not a checklist that stays true: the kernel adds syscalls every
  release, and each new one arrives *ungated*.

  The subtler half is that a gate can be correct and still catch nothing, because
  the program issues a *different* syscall than the one you named. `ln -s` calls
  `symlink()`, not `symlinkat()`; glibc's `rename()` is `renameat2`. Both pairs
  are gated here, and `lua/policy.lua` argues why for each — it is the single
  most useful thing to know when adding a gate.
- **`agent.http` and `agent.mcp` are not syscalls** — see
  [Security model](#security-model).
- **A denied syscall kills the tracee.** That is the enforcement, and it is
  coarse: the whole run ends, not just the call.
- **The network stays shared.** No `unshare(CLONE_NEWNET)`.

### The gates that would otherwise walk past the rest

Twenty of the twenty-seven ask about a *thing* — a path, a host, a port — so a
trust table can answer them before you are asked and `always` has somewhere to
record. The other seven ask about a **capability**, and they are the ones worth
reading the list above for, because each one closes a route around all the others:

- **`io_uring_enter` defeats the file gates rather than adding to them.**
  `IORING_OP_OPENAT` and its siblings are submission-queue *opcodes*, not
  syscalls: a program that speaks the ring protocol can open, stat, unlink,
  rename, link and symlink without `openat`, `unlinkat` or `renameat` ever being
  called. While the ring is ungated, every question the policy asks about a file
  is one a program that cares to ask can walk around. All three of
  `io_uring_setup` / `enter` / `register` are gated, because each alone is undone
  by one of the other two.
- **`open_by_handle_at` names a file without naming a path.** Its `path` argument
  is a component hint of at most 64 bytes that decides nothing; the file is
  chosen by an opaque handle. It is gated with *no path in the question*,
  deliberately — naming the hint would produce a confident question about the
  wrong file. Its partner `name_to_handle_at` takes a real path and is asked on
  read trust like any other read, since the handle is only as good as the read
  you vouched for.
- **`memfd_create`, `pidfd_getfd`, `process_vm_readv`/`writev`, `bpf`,
  `userfaultfd`, `pkey_*`** reach past the filesystem altogether — a file with no
  name, a descriptor belonging to another process, another address space's
  memory, the kernel itself. None of them has an argument worth decoding, so
  each is one line in `lua/policy.lua` and one plain question.

Capability questions can be remembered, but only for the command they were
accepted in — so their third answer is not `always` but **`lways this run`**, and
that is what the dialog draws:

```
┌─ cat /etc/hostname [−] ─────────────────────────────────┐
│ ┌─ [y]es · [n]o · [a]lways this run ─────────────────┐ │
│ │ nginx (pid 4242) requests to submit work to an      │ │
│ │ io_uring event loop, which can reach any file or    │ │
│ │ endpoint without asking about it [nginx: worker]    │ │
│ └─────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────┘
```

`y` is one operation and asks again. `a` answers itself for the rest of *that
command* — every worker in the tree, however many times — and the next `bash`
asks afresh. That scope is the design, not a shortfall. An `always` is a promise
about a *specific* thing, and "this program may reach any file" is not specific
to anything: kept past the run, it would be inherited silently by the next
command, which is a different program. A per-run grant costs you one question
per command instead of one per syscall, and cannot leak past the thing you read.

**There is no id anywhere in that.** `lua/policy.lua` exports a constructor
rather than a policy, and `bash_tool.lua` calls it once per command:

```lua
agent.bash(args.cmdline, require("policy").new(), { … })
```

Each call builds a fresh table of fresh closures. A gate's memory is an upvalue,
and the next command has no reference to this table — so the grant is not
*scoped* to a run, it is unreachable from any other. Nothing identifies a run
for a stale grant to be confused with a live one, which is also why a recycled
pid cannot inherit anything: there is no key to recycle.

`memfd_secret` is the near miss, and is deliberately **not** gated: glibc uses it
for the per-thread guard pages behind `MALLOC_TUNABLE_*`, and a gate that fires on
libc's own housekeeping is a gate that teaches you to press `a`.

What it does give, and the reason to want it: a real kernel-level floor under every
decision *you* make, the arguments of a frozen syscall read out of the process —
including the `struct sockaddr` of a `connect`, so a question can name the host
and the port rather than just "a connection" — and a prompt with three answers, so
the decision is yours and stays yours until you revoke it.

In one line: **it moves the decision to you at the moment it matters, and gets out
of the way.**

---

## Project layout

```
src/
  main.rs            the agent binary: the TUI, the event loop, tool rounds
  api.rs             chat-completions client — SSE parsing, turn accounting
  seccomp/           the user-notify engine and the x86-64 syscall tables
  lua/               the `agent` namespace
    mod.rs             the contract: what Lua may see and do
    vm.rs  tree.rs     building a VM; assembling it from the shipped lua/
    bridge.rs          the agent.api table and the lock that guards it
    sandbox.rs         the seccomp primitives and the /proc introspection
    config.rs run.rs   the agent.llm surface; a tool call as a coroutine
    memory.rs usage.rs the two small bindings
    tests/             split by shipped Lua surface, not by module
  tui/               the screen shell, the transcript, the markdown highlighter
  mcp.rs panels.rs    MCP transports; the Lua→TUI panel op stream
lua/                 everything a user would want to change
  init.lua           the starter configuration, seeded to ~/.config on first run
  fs.lua  bash_tool.lua  policy.lua  coding.lua  compact.lua  mcps.lua
  lib/*.lua          auto-required, each publishing itself on `agent`
scripts/             the gate
```

A tool is a connection and `agent.mcps` is the registry of them. The registry is
the whole of what the agent can do — nothing is hard-coded in Rust, and what
nobody registers does not exist.

---

## Development

```sh
make test          # cargo test
make gate          # ./scripts/verify-sandbox.sh — what CI runs
make fmt           # cargo fmt
```

`verify-sandbox.sh` must print `verify-sandbox: OK`. It runs the whole suite,
fails on any clippy warning in a sandbox file — `src/seccomp/`, `src/lua/`,
`src/mcp.rs`, `src/panels.rs` — and scans those for leftover instrumentation. It is
the check that the sandbox is still there at all. The suite is 398 library tests
and 14 in the `agent` binary, plus 4 `#[ignore]`d for want of the network or a C
compiler (`-- --ignored` runs them).

Other binaries, for narrower jobs: `chat` (a terminal setup demo, no Lua),
`grammar_probe` (fetch the four grammars the TUI preloads and parse a sample
with three of them), `mcp_fake` (a reference MCP server), `sandbox` (drive one
sandboxed run directly).

---

## Status

Work in progress, and honest about the edges:

- **Nobody has run this end to end against a real model yet.** Everything is
  green because it is hermetically tested; the integration is not.
- **The mask is a list, not a property, and it cannot be a property.** Every
  syscall the policy does not name runs ungated under the kernel's default, and
  the kernel adds more every release. What the list *can* do is catch the routes
  around the gates that are there — which is what the capability gates above are
  for — and it has been extended to twenty-seven on that basis. Audit it when the
  kernel moves, not when something breaks.
- **`link`/`linkat` and `symlink`/`symlinkat` are gated**, and had to be found by
  running `ln` under the sandbox: the first version of this fix named only the
  `*at` pair and caught nothing, because on x86-64 `ln -s` issues `symlink()` and
  never `symlinkat()`. A hard link into a trusted directory is the sharpest hole
  the sandbox had, because a hard link has no target for the resolver to chase:
  the read looks like a read of a file in the working directory, which is
  trusted, and the secret arrives with no question. The gate is at creation,
  which is the only place it can be.
- **`fchmod` is gated**, by reading the descriptor back through
  `/proc/<pid>/fd`, so the question names the real file. Read-trust on a path no
  longer implies being able to make that file executable. When the descriptor is
  not a file — a pipe, a socket — there is no path to name and it is asked as a
  plain yes/no rather than waved through.
- **Grammars are fetched and compiled at runtime**, which means a first run on a
  cold cache needs a network and a working `cc`.
- **`cargo install` does not work, and cannot.** The tree is loose files, so
  there is nothing for it to install; use `make install`. The Makefile is the
  whole packaging story — no distro packages, no Homebrew formula.

`RESEARCH-AGENT-EXTENSIBILITY.md` is a dated research brief on how other agents
handle extensibility and sandboxing, kept as the record of *why* the design looks
the way it does. It is not the documentation — this file and the module docs are.
