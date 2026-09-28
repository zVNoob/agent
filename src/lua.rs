//! The `agent` namespace: the seccomp sandbox, exposed to Lua.
//!
//! The sandbox's only client is Lua. This module installs a global `agent`
//! table into a LuaJIT VM (embedded via `mlua`, see `Cargo.toml`) and defines
//! the policy surface on it:
//!
//! ```lua
//! agent.bash(cmdline, policy, opts)  -- spawn; returns a stdio stream object
//! ```
//!
//! `policy` is a table mapping **generalized syscall names** (as resolved by
//! the engine, e.g. `"execve"`, `"openat"`, `"write"`) to policy callbacks:
//!
//! ```text
//! policy[name] = callback(syscall) -> boolean | agent.allow() | agent.deny(reason)
//! ```
//!
//! The callback receives a table describing the intercepted syscall (entry
//! only — this mechanism has no syscall return values, by design):
//!
//! ```text
//! { name = "openat", nr = 257, pid = 1234,
//!   cmdline = "bash -c echo hi > /tmp/x",          -- caller's /proc/<pid>/cmdline
//!   args = { [1] = <number>, ..., [6] = <number> } }   -- 1-based, lossy f64
//!   str   = { [2] = "/tmp/x" }   -- C-string args, dereferenced; paths resolved
//! ```
//!
//! `cmdline` is the calling process's `/proc/<pid>/cmdline` — its argv joined
//! with spaces (the `ps`-style view), `""` when it can't be read (the process
//! exited, or isn't ours). It is resolved fresh from `/proc` at each
//! interception, so a policy can see — and an ask can show — *who* is making
//! the request, not just which syscall.
//!
//! Arg values are u64s converted to Lua numbers (doubles), so pointer-valued
//! args are lossy; flag/errno-sized args are exact. For the syscalls whose
//! arguments are C strings (the pathname syscalls — `execve`, `open`,
//! `openat`, `openat2`, `stat`, `access`, `unlink`, `rename`, ...) the string
//! args are **dereferenced from the caller's memory before the callback
//! runs** and exposed under **`str`** — 1-based, aligned with `args` (so
//! `openat`'s pathname is `str[2]`), only the positions that are strings for that
//! syscall, `nil` when the pointer is unreadable. The raw numbers stay in
//! `args`. That is what makes **ask-and-remember per file** possible: a policy
//! (or the ask it raises) decides on the actual path, not an opaque pointer.
//!
//! Each `str` value that names a file or directory is additionally **resolved
//! to the actual path** as far as the filesystem allows — symlinks chased and
//! `..` collapsed (relative names against the tracee's `/proc/<pid>/cwd`). An
//! existing file arrives as its canonical path. A not-yet-created tail
//! (open-for-create, `unlink`, ...) keeps its literal name — but when the
//! input carried a symlink or `..` that *did* resolve, the result is the
//! actual directory plus the literal tail, so a soon-to-exist file still keys
//! on where it will live; a dangling symlink (target not yet created) reports
//! where it points, capped like the kernel (40 hops — chains unwind, cycles
//! give up and stay literal); and when even the prefix cannot be resolved the
//! name passes through unchanged — Lua always gets a string it can ask-and-remember
//! on. The dirfd
//! family (`openat` & friends) only resolves relative names when the fd slot
//! is `AT_FDCWD`; a path relative to a caller-held dirfd we cannot see passes
//! through as-is.
//!
//! **What the sandbox masks.** The syscall names whose keys you list in the
//! policy table are the ones the seccomp filter traps — everything you do
//! **not** list is not handled at all: it is not masked, so it runs straight
//! through the kernel (default allow) without ever reaching a callback. The
//! engine also always masks the fork family (`fork`/`vfork`/`clone`/`clone3`)
//! so its pid bookkeeping keeps working; those are auto-allowed by the engine
//! unless your policy names them. (The old contract — every unlisted syscall
//! denied, fail closed — no longer applies: unlisted syscalls are simply not
//! decided. A `__index` metatable is only consulted for the fork-family
//! syscalls you did name, in practice never — those are engine-handled.)
//!
//! The callback's outcome — callbacks may call **user-asking functions** that
//! yield the Lua thread until answered, and they decide by returning a
//! **boolean** or a **verdict object**:
//!
//! - returns `true` (or `agent.allow()`) → `Verdict::Allow` — the syscall runs
//!   normally;
//! - returns `false` → `Verdict::Deny` — final: the whole tree is SIGKILLed
//!   and the run ends (see `src/seccomp/` for the deny semantics);
//! - returns `agent.deny(reason)` → `Denied(reason)` — the same final deny,
//!   but the run's result carries `denied_reason` so the panel status line
//!   reads `Denied: <reason>` and the tool's JSON result names it;
//! - calls a user-asking function — plain user code, e.g.
//!   `local function uask(a) return coroutine.yield(a) end` — → a system
//!   call **ask**: the asking thread's syscall stays frozen in-kernel (its
//!   notification is parked awaiting the verdict). The ask reaches whoever
//!   resumed the run's pump, yielded **raw** (unwrapped), and resuming the
//!   pump **with the verdict** — a boolean, or the same `agent.allow()` /
//!   `agent.deny(reason)` object a policy may return — delivers it to the
//!   yield site: the user-asking function returns it, the callback keeps
//!   going, and its eventual return (boolean or verdict object) is the
//!   decision. While an ask is pending the engine stops every *other*
//!   process in the tree ([`seccomp::Sandbox::freeze_others`]) — never the
//!   asker, whose kernel-side wait must not be disturbed (see below) — so the
//!   string/path deref, the resolution, and the policy run all see a quiesced
//!   tree and nothing can mutate the filesystem under the check.
//!
//! So `Verdict::Ask` is the Lua `coroutine.yield`, and a call to
//! `Sandbox::resolve_ask` is the resume-with-verdict. `Ask` is never a final
//! answer: the policy only ever returns `Allow` / `Deny` (as a boolean or an
//! `agent.allow()` / `agent.deny(reason)` object).
//!
//! **Freeze, asker-excluded:** the engine offers [`seccomp::Sandbox::freeze`],
//! but it SIGSTOPs *every* captured pid — on this kernel that stop interrupts
//! the asker's wait on the very notification being asked about, the kernel
//! discards it and restarts the syscall, an `Allow` answer cannot be
//! delivered (`ENOENT`), and the restarted syscall re-asks forever (that
//! livelock is the regression pinned by
//! `ask_round_trip_is_stable_under_repetition`). The bridge therefore freezes
//! its own way around a blocked syscall: [`seccomp::Sandbox::freeze_others`]
//! SIGSTOPs every tree process *except* the asker's (SIGSTOP is process-wide,
//! so the asker's whole thread group is excluded — sibling *threads inside
//! the asker's own process* are the one unreachable residual), and
//! [`seccomp::Sandbox::resolve_ask_frozen`] answers the ask, holds the
//! still-frozen siblings until the allowed syscall has executed (a bounded
//! `SECCOMP_IOCTL_NOTIF_ID_VALID` completion wait), and only then SIGCONTs.
//! Between the policy's check and the kernel's own pathname resolution no
//! sibling process runs — the TOCTOU gate a path-based policy would
//! otherwise sit inside.
//!
//! A callback that **raises** an error kills the sandbox on the spot and the
//! error is re-raised to the caller; a callback whose completion value is not
//! a boolean or a verdict object does the same.
//!
//! `agent.bash(cmdline, policy, opts)` **spawns immediately** and returns a
//! stdio **stream object**. Output is *pushed* through optional callbacks — the
//! config chooses how much of the stream it wants:
//!
//! ```lua
//! local s = agent.bash(cmdline, policy, {
//!   on_stdout = function(chunk, stream) ... end,  -- optional; pushed as chunks arrive
//!   on_stderr = function(chunk, stream) ... end,  -- optional
//!   on_exit   = function(result) ... end,         -- optional; result = final table
//! })
//! ```
//!
//! - **Use it fully** (an MCP server in stdio mode): register `on_stdout` +
//!   `on_stderr` — both pipes are the protocol channel — feed requests with
//!   `s:write_stdin(data)` and signal EOF with `s:close_stdin()`.
//! - **stdout only** (a bash tool call): register `on_stdout`; stderr is still
//!   captured and returned in the result, just not pushed.
//! - **Ignore it entirely** (a detached launch): register no output callbacks;
//!   drive the run with `s:run()` and output is discarded, only the final
//!   result is produced.
//!
//! The object (streams are pushed; nothing is yielded for output):
//!
//! ```text
//! s.on_stdout / s.on_stderr / s.on_exit   -- assignable fields; called with
//!                                            (chunk, stream) and (result)
//! s.pump                                   -- the drive loop as a coroutine:
//!                                            resume it to run; it yields only
//!                                            asks and returns the result
//! s:run(on_ask?)                           -- drive to completion, return result
//! s:write_stdin(data) / s:close_stdin()    -- feed / EOF the tracee's stdin
//! s:kill()                                 -- SIGKILL the whole tree
//! ```
//!
//! Driving: a run only advances while driven — the syscalls your policy names
//! are seccomp-gated, so nothing you are deciding runs by itself; un-named
//! syscalls run freely (they are not intercepted at all). `s:run(on_ask)` drives to
//! completion and returns the final result table
//! (`{stdout, stderr, exit = {code|signal}, syscalls, denied}`). With a plain
//! allow/deny policy (no asks) pass nothing; `on_ask(ask) -> boolean` (or an
//! `agent.allow()` / `agent.deny(reason)` verdict object) answers
//! asks raised by user-asking functions. `on_exit` fires on completion either
//! way.
//!
//! Interactive drivers use `s.pump` directly — it is the same drive, as a
//! resumable coroutine. `coroutine.resume(s.pump)` runs until the next **ask**
//! (or completion): a yielded ask is the raw value a user-asking function
//! yielded (never wrapped), and the next resume's argument is the verdict.
//! Output still goes through the callbacks; the pump *only* yields asks.
//! Drive exactly one of `self.pump` resumes or `s:run()` — not both.
//!
//! Pull readers: users who want pull semantics wrap the pump in their own
//! coroutine and it is safe to do so — the driver steps the engine only
//! through pure Lua frames, so no ask yield ever crosses a C call (see below):
//!
//! ```lua
//! local co = coroutine.create(function()
//!   local pump = s.pump
//!   local pending
//!   while true do
//!     local ok, ev = coroutine.resume(pump, pending)
//!     pending = nil
//!     assert(ok, ev)
//!     if coroutine.status(pump) == "dead" then return ev end
//!     pending = coroutine.yield(ev)   -- re-yield the ask to *your* resumer
//!   end
//! end)
//! ```
//!
//! Convenience pattern — allow every syscall and stream stdout to a collector:
//!
//! ```lua
//! local allowall = setmetatable({}, {
//!   __index = function() return function() return true end end,
//! })
//! local out = {}
//! local s = agent.bash("echo hi", allowall,
//!                      { on_stdout = function(c) out[#out + 1] = c end })
//! local r = s:run()   -- {stdout="hi\n", ...}; echoed output is also in `out`
//! ```
//!
//! ## Why policy dispatch lives in Lua
//!
//! `agent.bash` is a Lua driver loop over the engine's non-blocking steps. It
//! calls each policy callback inside a fresh coroutine and re-yields its asks,
//! so a yield unwinds through **pure Lua frames** to the caller's coroutine
//! boundary — never across a C call (`mlua` function calls are `lua_pcall`
//! boundaries, which reject `coroutine.yield`). The Rust side only exposes
//! primitives that never yield:
//!
//! ```text
//! agent.api.spawn(cmdline, mask?)-> sandbox handle; mask = list of syscall names
//!                                to trap (nil/absent = trap nothing; the
//!                                fork family is always trapped regardless)
//! agent.api.step(handle)        -> one step: {kind="blocked"|"output"|"idle"|"finished", ...}
//! agent.api.decide(handle, bool)-> Allow/Deny for the pending ask
//! agent.api.kill(handle)        -> SIGKILL the whole tree
//! agent.api.write(handle, data) -> feed bytes to the tracee's stdin (non-blocking, queued)
//! agent.api.close_stdin(handle) -> EOF on the tracee's stdin
//! agent.api.json_encode(value)  -> JSON text (the MCP JSON boundary, src/mcp.rs)
//! agent.api.json_decode(text)   -> value
//! agent.api.http_req(m,url,hd,b,timeout_ms) -> HTTP request handle (src/mcp.rs)
//! agent.api.http_step(handle)   -> headers | chunk | done | error event (or nil)
//! agent.api.http_close(handle)  -> abort an HTTP request
//! agent.api.sse_open(url, hd)   -> SSE stream handle (src/mcp.rs)
//! agent.api.sse_step(handle)    -> event | done | error (or nil)
//! agent.api.sse_close(handle)   -> abort an SSE stream
//! agent.on_timeout(ms, fn)   -> wait ms, then run fn (nil = plain wait):
//!                               on the reactor-driven handler coroutine the
//!                               wait suspends the coroutine (the loop stays
//!                               live); elsewhere it falls back to a thread
//!                               sleep (the old `agent.api.sleep` cadence)
//! ```
//!
//! These are the engine's [`seccomp::Sandbox`] contract 1:1; `agent.bash` is
//! sugar over them. Direct use is for interrupt/cancel and custom driver loops.
//!
//! ## Panels: `agent.panel`
//!
//! `agent.panel(title, opts)` returns a handle for driving TUI transcript
//! panels (`:append`/`:set` text, `:highlight` styled byte regions,
//! `:clear_regions`) — the primitives underneath are the `agent.api.panel_*`
//! entry points above. Emitted ops buffer in the round's
//! [`PanelSink`] and the TUI applies them; with no
//! sink (headless) they are no-ops. Panels render through the same pipelines
//! as every other message, so the UI stays the familiar one.
//!
//! `agent.split_panel(title, panes)` is the sibling for multi-region panels:
//! one titled box holds several sub-panels, each with its own text and
//! *declared highlighting language* (`:set(pane, …)`, `:lang(pane, lang)`,
//! `:highlight(pane, …)`, `:clear_regions(pane)`). That is the building block
//! for a Lua `apply_patch`: before/after code renders side-by-side with
//! tree-sitter running on each pane's own clean text (a unified diff could
//! never do that — the grammar would choke on its `+`/`-` prefixes).
//! Underneath this is [`PanelOp::Split`] +
//! the `_panel_pane_*` primitives, mirroring the single-body `agent.panel`.
//!
//! Rust consumers get the same thing in one shot, and it is all Lua: `agent.bash`
//! (`lua/lib/bash.lua`) runs a sandboxed `bash -c "cmdline"` under a Lua policy
//! that is itself plain Lua source, on the agent's own VM.
//!
//! ## MCP: `agent.mcp` and `agent.mcps`
//!
//! [`mcp`](crate::mcp) adds the JSON text boundary above; the **MCP client protocol** is
//! `lua/lib/mcp.lua` — the pure-Lua `agent.mcp(name, func, opts)` module: it
//! performs the MCP handshake (initialize → notifications/initialized →
//! tools/list) and registers a callable **tool object** per advertised tool on
//! `conn` and `conn.tools`. The *transport* is injected:
//! `func(request_json, on_streaming_response_json)` sends each serialized
//! JSON-RPC request and streams the reply messages back through the callback:
//!
//! ```lua
//! local func = function(request_json, on_streaming_response_json) ... end
//! agent.mcps.fs = agent.mcp("fs", func)
//! local r = agent.mcps.fs.read({ path = "/etc/hostname" })
//! -- r = { ok = true|false, result = <tools/call result>, error = <rpc error>, denied = true|false }
//! ```
//!
//! func can speak any transport (an MCP stdio server spawned with
//! `agent.bash`, HTTPS via `agent.http`, an in-process stub, a
//! test mock — the client never spawns). Correlation, notification routing,
//! and the tool registry all live in Lua; the Rust side only contributes the
//! JSON text boundary. Tool calls are allow-by-default and narrowable per
//! tool (`tool.policy` / `tool.callback`). See the module docs inside
//! `lua/lib/mcp.lua` for the full contract.
//!
//! Each round can also stream *per-call*:
//! `conn:invoke(name, args, { on_progress = fn, on_message = fn })` routes
//! `notifications/progress` (the request then carries `_meta.progressToken`)
//! and other inbound notifications to those callbacks in order while the
//! round runs; callbacks may `coroutine.yield` (the whole round is
//! coroutine-wrappable). Without the per-call opts they fall back to the
//! global `opts.on_message`.
//!
//! ## HTTP(S) transport: `agent.http` (one interface, auto-routed)
//!
//! The MCP streamable HTTP transport is implemented in [`mcp`](crate::mcp) **as a
//! transport only** — Rust owns TLS, HTTP framing, and SSE parsing, as tasks on
//! the agent's own single reactor; there is no protocol client over HTTP (no
//! handshake, no tool registry, no session machinery). The Lua half is
//! `lua/lib/http.lua`: **one** `agent.http(method, url, opts)` returning a
//! stream object that pushes the response through callbacks as it arrives,
//! mirroring `agent.bash`'s output streams. It is what an MCP connection's
//! transport is usually built on — the protocol half is `lua/lib/mcp.lua`:
//!
//! ```lua
//! local s = agent.http("POST", "https://…/mcp", {
//!   body = '{"jsonrpc":"2.0","id":1,"method":"initialize"}',
//!   headers = { ["content-type"] = "application/json" },
//!   on_chunk = function(c) ... end,      -- response body, streamed as it arrives
//!   on_event = function(event, data) ... end,  -- if the response is an event stream
//!   on_done  = function(o) ... end,      -- o = { status = <int>, headers = {...} }
//!   on_error = function(e, status) ... end,
//! })
//! s:run()   -- drive to completion; returns the stream object
//! s:close() -- abort + release
//!
//! -- a bare event stream: on_event and no body takes the stream route
//! local s = agent.http("GET", "https://…/events", {
//!   headers = { ["accept"] = "text/event-stream" },
//!   on_event = function(event, data) ... end,
//! })
//! s:run()
//! ```
//!
//! The route is chosen for you: `on_event` with no body opens an SSE *stream*;
//! otherwise a request goes out — and if that request's response turns out to
//! be `content-type: text/event-stream`, its body is parsed as events and
//! delivered to `on_event` too (the MCP streamable-HTTP case: one endpoint
//! answering with JSON *or* an event stream). `opts.sse` overrides either way.
//!
//! A non-2xx status is **not** a transport error: the status arrives in
//! `on_done` (as `o.status`) and the body still streams through `on_chunk`.
//! `on_error` fires only for transport-level failures (unreachable host,
//! timeout, ...). Requests carry an overall timeout (`opts.timeout_ms`,
//! default 30000; `0` disables it).
//!
//! ## Limits of this version
//!
//! - Output is captured internally regardless of what the config consumes
//!   (streaming callers ignore the returned copies; a "detached" run's
//!   capture grows with its output — a background pump is future work).
//! - A run only advances while driven (`s:run()` or resumes of `s.pump`);
//!   "detached" runs still need their pump driven from a loop.
//! - `bash` is resolved via PATH at spawn time on the supervisor side.
//! - The sandbox engine itself has no async races and the LuaVM is
//!   single-threaded; concurrent runs each own their sandbox handle.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex, OnceLock};

use tokio::sync::mpsc;

use mlua::{AnyUserData, Lua, Table, UserData};

use crate::memory::Memory;
use crate::panels::{PaneInit, PanelOp, PanelSink};
use crate::seccomp::{self, CoroutineEvent, FdSlot, Step, Verdict};

/// The sandbox handle handed to Lua. A single-owner wrapper around the live
/// [`seccomp::Sandbox`]; dropping the userdata (GC, coroutine unwind,
/// `agent.api.kill`) runs the engine's destructor, which SIGKILLs the whole tree
/// (see `src/seccomp/`).
struct SandboxHandle(Rc<RefCell<seccomp::Sandbox>>);

impl UserData for SandboxHandle {}

/// Install the `agent` namespace into `lua` (globals table `agent` plus the
/// Lua driver primitives), then load the shipped `lua/` tree: every
/// `lua/lib/**.lua` module and the `lua/init.lua` entry script. No panel sink:
/// `agent.api.panel_*` are no-ops.
pub fn setup(lua: &Lua) -> mlua::Result<()> {
    setup_inner(lua, None, None)
}

/// [`setup`] with an optional panel sink, so `agent.api.panel_*` emissions from
/// policy/tool Lua are buffered for the TUI to apply (headless: `None`).
fn setup_inner(lua: &Lua, sink: Option<&PanelSink>, on_ask: Option<AskHandler>) -> mlua::Result<()> {
    setup_tree(lua, sink, on_ask, &lua_dir(), &ConfigSource::default())
}

/// [`setup_inner`] against an explicit `lua/` tree instead of the resolved
/// one — the seam the loader tests drive fixture trees through.
fn setup_tree(
    lua: &Lua,
    sink: Option<&PanelSink>,
    on_ask: Option<AskHandler>,
    dir: &Path,
    config: &ConfigSource,
) -> mlua::Result<()> {
    // The bridge first: every primitive in one locked table, so the entry
    // script and the lib modules can call them while they load.
    let api = install_api(lua, sink, on_ask)?;
    let agent = lua.create_table()?;
    agent.set("api", lock_table(lua, api.clone(), "api")?)?;
    lua.globals().set("agent", agent)?;
    install_require(lua, dir)?;
    load_lib_modules(lua, dir)?;
    // The settings table, created empty, before any configuration runs.
    //
    // A configuration assigns *fields* of it and never the table itself, and it
    // has to be able to: the user's `~/.config/agent/init.lua` may be three
    // lines long, and a file that cannot set `agent.llm.base_url` without
    // first inventing the table is not a configuration. Every field defaults
    // independently on the Rust side (`llm_config`, `memory_config`), so an
    // absent key means "the default", and the starter config can still spell
    // every value out where a user would go to change it.
    {
        let agent: Table = lua.globals().get("agent")?;
        let existing: mlua::Value = agent.get("llm")?;
        if !matches!(existing, mlua::Value::Table(_)) {
            agent.set("llm", lua.create_table()?)?;
        }
    }
    // The bridge's annotations, required by the *loader* rather than by the
    // configuration script. The drift check below is a statement about the
    // bridge, so it cannot depend on a file the user is invited to edit: making
    // `agent.api_docs` the configuration's job meant that deleting one line from
    // your own config stopped the agent with a message about a missing require.
    load_api_docs(lua)?;
    // The configuration script: the user's, seeded from the tree's on first run
    // (see `ConfigSource`). Exactly one script runs — the user's file is not an
    // overlay on top of the shipped one, it *is* the configuration.
    match config {
        ConfigSource::Tree => load_init(lua, dir)?,
        ConfigSource::UserHome(home) => {
            let (path, _) = ensure_config(dir, home.as_deref());
            load_init_at(lua, &path)?;
        }
    }
    // The read-only token counters of the most recent request, seeded from the
    // process-wide snapshot so *every* VM agrees (see `record_usage`). They live
    // inside `agent.llm`, which is why this runs after the entry script created
    // it.
    install_usage(lua)?;
    // The annotations were loaded above; they and the bridge must not drift
    // apart.
    verify_api_annotations(lua, &api)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// `agent.api` — the Rust↔Lua bridge.
//
// Every primitive Rust exposes to Lua lives in one table, under its bare name
// (the namespace carries the "this is the substrate" signal, so there is no `_`
// prefix left to carry as well). Three properties:
//
//   * **one place**: `agent.api.<name>`, annotated in `lua/api.lua` and
//     published as `agent.api_docs` — so the surface is discoverable instead
//     of folklore spread over the driver.
//   * **read-only**: `agent.api` is a proxy whose metatable raises on any
//     assignment and hides itself from `getmetatable`/`setmetatable`
//     ([`lock_table`]), so a policy cannot rewrite the bridge it is judged by.
//     (The `agent.api` slot itself is still an ordinary key on `agent`; the
//     sandbox's real security boundary is seccomp, not this table.)
//   * **annotated or it does not ship**: [`verify_api_annotations`] fails the
//     VM when a primitive has no entry in `lua/api.lua`, or an entry names a
//     function that does not exist.
//
// Lua-side fields deliberately stay on `agent` (they are not the bridge):
// `agent._events` (the hook registry), `agent.__on_reactor` (a flag Rust sets
// while a handler coroutine runs), and whatever the user's own config
// defines.
// ---------------------------------------------------------------------------

/// Install the whole bridge into a fresh table: the sandbox engine primitives,
/// the panel sink, and the MCP transport/JSON boundary.
fn install_api(
    lua: &Lua,
    sink: Option<&PanelSink>,
    on_ask: Option<AskHandler>,
) -> mlua::Result<Table> {
    // The panel sink is a *slot*, not a captured value: the panel primitives
    // read it when they are called, so the agent's long-lived config VM can be
    // given the current round's sink (or none) between tool calls instead of
    // being built per call to get one. See `install_sink`.
    let sink_slot = Rc::new(RefCell::new(sink.cloned()));
    lua.globals().set("__agent_sink", SinkSlot(sink_slot.clone()))?;
    let api = lua.create_table()?;
    api.set("spawn", lua.create_function(lua_spawn)?)?;
    api.set("step", lua.create_function(lua_step)?)?;
    api.set("decide", lua.create_function(lua_decide)?)?;
    api.set("kill", lua.create_function(lua_kill)?)?;
    api.set("write", lua.create_function(lua_write_stdin)?)?;
    api.set("close_stdin", lua.create_function(lua_close_stdin)?)?;
    api.set("trigger", lua.create_function(lua_trigger)?)?;
    // The `&Lua` argument is required by `create_function` and unused: these
    // send on the same channel `agent.trigger` does, and the VM is not involved.
    api.set(
        "input_insert",
        lua.create_function(|_: &Lua, text: String| lua_input_op(InputOp::Append(text)))?,
    )?;
    api.set(
        "input_backspace",
        lua.create_function(|_: &Lua, ()| lua_input_op(InputOp::Backspace))?,
    )?;
    api.set(
        "input_clear",
        lua.create_function(|_: &Lua, ()| lua_input_op(InputOp::Clear))?,
    )?;
    api.set("ask_user", lua.create_function(lua_ask_user(on_ask))?)?;
    api.set("memory_path", lua.create_function(lua_memory_path)?)?;
    api.set("memory_append", lua.create_function(lua_memory_append)?)?;
    api.set("memory_latest", lua.create_function(lua_memory_latest)?)?;
    api.set("memory_flush", lua.create_function(lua_memory_flush)?)?;
    install_panel_primitives(lua, &api, &sink_slot)?;
    install_print(lua)?;
    crate::mcp::install_bridge(lua, &api)?;
    Ok(api)
}

/// Replace the global `print` so it cannot land in the middle of the screen.
///
/// A TUI owns the terminal: a `print` from a tool callback or an event handler
/// would scribble over the alternate screen and leave the garbage there when it
/// exits. So `print` reports to [`crate::status`] instead — but only once a
/// screen has attached. Detached (the probe, the tests, `chat`) it writes to
/// real stdout exactly as before, which is what keeps a headless run debuggable.
///
/// The stringification is Lua's, not Rust's, and deliberately so: `print` is
/// specified in terms of `tostring`, so a `__tostring` metamethod and a
/// `__name` have to be honoured, and the C-level `lua_tolstring` mlua exposes
/// does neither. So the shim below does what the reference `print` does —
/// `tostring` every argument, join with tabs — and hands the finished line to a
/// Rust primitive that only has to decide where it goes.
fn install_print(lua: &Lua) -> mlua::Result<()> {
    let sink = lua.create_function(|_: &Lua, line: String| {
        if crate::status::is_attached() {
            crate::status::print_line(&line);
        } else {
            println!("{line}");
        }
        Ok(())
    })?;
    lua.globals().set("__agent_print", sink)?;
    lua.load(PRINT_SHIM).exec()?;
    Ok(())
}

/// The `print` replacement: Lua's own argument handling, one Rust call.
const PRINT_SHIM: &str = r#"
local emit = __agent_print
function print(...)
  local n = select('#', ...)
  if n == 0 then return emit("") end
  local parts = {}
  for i = 1, n do parts[i] = tostring((select(i, ...))) end
  return emit(table.concat(parts, "\t"))
end
"#;

/// Wrap `real` in a read-only proxy: reads pass through to the real table, any
/// assignment raises, and `__metatable` hides the indirection from
/// `getmetatable` / `setmetatable`.
fn lock_table(lua: &Lua, real: Table, name: &str) -> mlua::Result<Table> {
    let proxy = lua.create_table()?;
    let metatable = lua.create_table()?;
    metatable.set("__index", real)?;
    let name = name.to_string();
    metatable.set(
        "__newindex",
        lua.create_function(
            move |_, (first, second, _value): (mlua::Value, mlua::Value, mlua::Value)| {
                // Lua calls a `__newindex` metamethod as (table, key, value) —
                // the table itself arrives first, so the key is the *second*
                // argument. Name it when it is a string.
                let key = match (&first, &second) {
                    (mlua::Value::String(s), _) | (_, mlua::Value::String(s)) => {
                        s.to_string_lossy().to_string()
                    }
                    _ => "<non-string key>".to_string(),
                };
                Err::<(), _>(mlua::Error::RuntimeError(format!(
                    "agent.{name} is read-only: cannot set '{key}'"
                )))
            },
        )?,
    )?;
    metatable.set("__metatable", false)?;
    proxy.set_metatable(Some(metatable))?;
    Ok(proxy)
}

/// Every bridge function must be documented in `lua/api.lua` (which the entry
/// script requires and publishes as `agent.api_docs`), and every documented
/// name must be a real primitive with a `summary`. A bridge added without an
/// annotation, or an annotation left behind after a removal, fails the VM
/// instead of shipping as folklore.
/// Require `lua/api.lua` and publish it as `agent.api_docs`, so the bridge's
/// annotations are loaded and available whatever the configuration script does.
fn load_api_docs(lua: &Lua) -> mlua::Result<()> {
    let require: mlua::Function = lua.globals().get("require")?;
    let docs: mlua::Value = require.call("api").map_err(|e| {
        mlua::Error::RuntimeError(format!("agent.api: require(\"api\"): {e}"))
    })?;
    let agent: Table = lua.globals().get("agent")?;
    agent.set("api_docs", docs)
}

fn verify_api_annotations(lua: &Lua, api: &Table) -> mlua::Result<()> {
    let agent: Table = lua.globals().get("agent")?;
    let docs: Table = agent.get("api_docs").map_err(|_| {
        mlua::Error::RuntimeError(
            "agent.api: no api_docs — lua/api.lua did not load".to_string(),
        )
    })?;
    let mut undocumented: Vec<String> = Vec::new();
    for pair in api.pairs::<String, mlua::Value>() {
        let (name, _) = pair?;
        match docs.get::<Table>(name.as_str()) {
            Ok(entry) => {
                if entry.get::<String>("summary").is_err() {
                    undocumented.push(name);
                }
            }
            Err(_) => undocumented.push(name),
        }
    }
    undocumented.sort();
    if !undocumented.is_empty() {
        return Err(mlua::Error::RuntimeError(format!(
            "agent.api: no entry in lua/api.lua for: {}",
            undocumented.join(", ")
        )));
    }
    let mut stale: Vec<String> = Vec::new();
    for pair in docs.pairs::<String, mlua::Value>() {
        let (name, _) = pair?;
        if api.get::<mlua::Value>(name.as_str()).is_err() {
            stale.push(name);
        }
    }
    stale.sort();
    if !stale.is_empty() {
        return Err(mlua::Error::RuntimeError(format!(
            "agent.api: lua/api.lua documents functions that do not exist: {}",
            stale.join(", ")
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The shipped `lua/` tree: how a VM's Lua is assembled.
//
// The tree ships alongside the binary:
//
//   lua/init.lua      the entry script — the only top-level script, run last
//   lua/api.lua       annotations for the `agent.api` bridge
//   lua/fs.lua …      top-level modules, required on demand
//   lua/lib/**.lua    the module directory: every one is required (and cached)
//                     at VM setup, and any of them can require the others
//
// The tree is on the **module search path** ([`install_require`]), so `require`
// and `package.path` agree: `require("utils")` finds `lua/lib/utils.lua`,
// `require("fs")` finds `lua/fs.lua`, `require("net.http")` finds
// `lua/lib/net/http.lua` (dots are directories), and `require("net")` finds
// `lua/lib/net/init.lua`. Only `lib/` is auto-required at setup; a top-level
// module is pulled in by whoever wants it (the entry script requires `driver`
// and `api`, a user config requires what it registers — e.g.
// `agent.mcps.fs = require("fs")`). The still-embedded chunks stay reachable
// the same way through `package.preload` (see [`driver_module`]), which is how
// `lua/init.lua` gets `agent.bash` today and how every embedded chunk gets
// deleted later without touching a single call site.
//
// Because every lib module is auto-required, a lib module publishes itself by
// assigning to the `agent` table — `lua/lib/utils.lua` ends with
// `agent.utils = M`, so `agent.utils` is live on every VM with no require at
// the use site, while `require("utils")` still hands back the same table.
// That `lib/<name>.lua` -> `agent.<name>` convention is the whole mechanism;
// Rust stays out of it (a module that wants a different name just assigns a
// different field, or nothing at all).
//
// **Order matters for siblings, so use `require` for them.** The auto-scan
// requires lib modules in alphabetical order, so `lua/lib/aaa.lua` runs before
// `lua/lib/seccomp.lua` — a module that writes `local sc = agent.seccomp` at its
// top level gets `nil`, silently, because the sibling has not published itself
// yet. `local sc = require("seccomp")` is order-independent (it loads the
// sibling on demand, and the auto-scan's later require is a cache hit), and
// `agent.seccomp` then works for every caller *after* setup. Inside a function,
// at call time, `agent.seccomp` is fine.
// ---------------------------------------------------------------------------

/// The Lua tree to load: `$AGENT_LUA_DIR`, else `lua/` beside the executable
/// (when it holds an `init.lua`), else `lua/` in the working directory.
fn lua_dir() -> PathBuf {
    lua_dir_in(
        std::env::var_os("AGENT_LUA_DIR").map(PathBuf::from),
        std::env::current_exe().ok(),
    )
}

/// [`lua_dir`] with its two inputs taken explicitly, so the resolution order
/// is testable without touching the process environment.
fn lua_dir_in(explicit: Option<PathBuf>, exe: Option<PathBuf>) -> PathBuf {
    if let Some(dir) = explicit {
        return dir;
    }
    if let Some(parent) = exe.as_deref().and_then(Path::parent) {
        let beside = parent.join("lua");
        if beside.join("init.lua").is_file() {
            return beside;
        }
    }
    PathBuf::from("lua")
}

/// Put the tree on the module search path, so `require` finds the modules a
/// VM loads.
///
/// The standard mechanism, so `require` and `package.path` agree: the tree's
/// `lib/` comes first (it is the module directory), then the tree root (where
/// the entry script and other top-level modules like `fs` live), each with both
/// the `?.lua` and the `?/init.lua` form:
///
/// ```text
/// require("fs")        -> lua/fs.lua              (root)
/// require("utils")     -> lua/lib/utils.lua       (lib wins)
/// require("net.http")  -> lua/net/http.lua        (dots are directories)
/// require("net")       -> lua/net/init.lua        (the ?/init.lua form)
/// require("on_timeout") -> lua/lib/on_timeout.lua (the cooperative wait)
/// ```
fn install_require(lua: &Lua, dir: &Path) -> mlua::Result<()> {
    let package: Table = lua
        .globals()
        .get("package")
        .map_err(|e| mlua::Error::RuntimeError(format!("lua: no package library: {e}")))?;
    let old: String = package.get("path")?;
    let lib = dir.join("lib");
    let path = [
        lib.join("?.lua").display().to_string(),
        lib.join("?").join("init.lua").display().to_string(),
        dir.join("?.lua").display().to_string(),
        dir.join("?").join("init.lua").display().to_string(),
        old,
    ]
    .join(";");
    package.set("path", path)?;
    Ok(())
}


/// Require every module under `lua/lib/`, recursively, in sorted order (so the
/// load order never follows directory order). Each lands in `package.loaded`, so
/// a module that requires a sibling sees it already loaded, and a later
/// `require` of the same name is a cache hit.
///
/// Directories are part of a module's name: `lib/net/http.lua` is required as
/// `net.http`.
fn load_lib_modules(lua: &Lua, dir: &Path) -> mlua::Result<()> {
    let mut names: Vec<String> = Vec::new();
    collect_modules(&dir.join("lib"), "", &mut names)?;
    names.sort();
    let require: mlua::Function = lua
        .globals()
        .get("require")
        .map_err(|e| mlua::Error::RuntimeError(format!("lua lib: no require: {e}")))?;
    for name in &names {
        require.call::<mlua::Value>(name.as_str()).map_err(|e| {
            mlua::Error::RuntimeError(format!("lua lib: require(\"{name}\"): {e}"))
        })?;
    }
    Ok(())
}

/// Walk `dir` collecting module names, joining directory levels with dots
/// (`prefix` is the name of the level above).
fn collect_modules(dir: &Path, prefix: &str, out: &mut Vec<String>) -> mlua::Result<()> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| mlua::Error::RuntimeError(format!("lua lib: {}: {e}", dir.display())))?;
    let join = |base: &str, name: &str| {
        if base.is_empty() {
            name.to_string()
        } else {
            format!("{base}.{name}")
        }
    };
    for entry in entries {
        let entry = entry
            .map_err(|e| mlua::Error::RuntimeError(format!("lua lib: {}: {e}", dir.display())))?;
        let path = entry.path();
        let Some(file_name) = entry.file_name().to_str().map(str::to_string) else {
            continue; // not valid UTF-8: no Lua module can be named after it
        };
        if path.is_dir() {
            collect_modules(&path, &join(prefix, &file_name), out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("lua") {
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            out.push(join(prefix, stem));
        }
    }
    Ok(())
}

/// Run a configuration script — the last thing a VM's setup does, and either
/// the tree's `init.lua` or the user's `~/.config/agent/init.lua` (see
/// [`ConfigSource`]).
fn load_init(lua: &Lua, dir: &Path) -> mlua::Result<()> {
    load_init_at(lua, &dir.join("init.lua"))
}

/// The configuration script, run from wherever it lives — the tree's
/// `init.lua` or the user's `~/.config/agent/init.lua`. Which one is decided by
/// [`ConfigSource`], and both are the same script as far as the loader is
/// concerned: a chunk that sets up `agent`.
fn load_init_at(lua: &Lua, path: &Path) -> mlua::Result<()> {
    let source = std::fs::read_to_string(path).map_err(|e| {
        mlua::Error::RuntimeError(format!("lua config: {}: {e}", path.display()))
    })?;
    lua.load(&source)
        .set_name(path.display().to_string())
        .exec()
}

/// Strict read of an optional `opts` boolean field: absent -> `None`, a real
/// boolean -> `Some(b)`, anything else -> error. (mlua's `FromLua for bool`
/// is *truthy* — a typo'd `boxed = "yes"` would silently become `true`.)
fn opts_bool(t: &Table, key: &str) -> mlua::Result<Option<bool>> {
    if !t.contains_key(key)? {
        return Ok(None);
    }
    match t.get::<mlua::Value>(key)? {
        mlua::Value::Boolean(b) => Ok(Some(b)),
        v => Err(mlua::Error::FromLuaConversionError {
            from: v.type_name(),
            to: "boolean".to_string(),
            message: Some(format!("opts.{key} must be a boolean")),
        }),
    }
}

/// `agent.api.panel_*`: record [`PanelOp`]s into the optional sink (no-op when
/// headless); the `agent.panel` sugar over them lives in `lua/lib/panel.lua`.
fn install_panel_primitives(
    lua: &Lua,
    api: &Table,
    sink_slot: &Rc<RefCell<Option<PanelSink>>>,
) -> mlua::Result<()> {
    let panel_seq = Rc::new(RefCell::new(0u64));
    api.set("panel_create", {
        let seq = Rc::clone(&panel_seq);
        let sink = sink_slot.clone();
        lua.create_function(
            move |_: &Lua, (title, opts): (String, Option<Table>)| -> mlua::Result<u64> {
                // Ids come from the round's sink so Lua and Rust producers
                // in one round can never collide; headless falls back to a
                // per-VM counter (the ids still round-trip through the
                // handle's methods, they just don't reach any panel).
                let id = match &*sink.borrow() {
                    Some(s) => (*s).alloc_id(),
                    None => {
                        let mut n = seq.borrow_mut();
                        *n += 1;
                        *n
                    }
                };
                let (mut boxed, mut conceal_box) = (true, true);
                if let Some(t) = opts {
                    if let Some(b) = opts_bool(&t, "boxed")? {
                        boxed = b;
                    }
                    if let Some(c) = opts_bool(&t, "conceal_box")? {
                        conceal_box = c;
                    }
                }
                if let Some(s) = &*sink.borrow() {
                    s.push(PanelOp::Create {
                        id,
                        title,
                        boxed,
                        conceal_box,
                    });
                }
                Ok(id)
            },
        )?
    })?;
    api.set("panel_append", {
        let sink = sink_slot.clone();
        lua.create_function(move |_: &Lua, (id, text): (u64, String)| {
            if let Some(s) = &*sink.borrow() {
                s.push(PanelOp::Append { id, text });
            }
            Ok(())
        })?
    })?;
    api.set("panel_set", {
        let sink = sink_slot.clone();
        lua.create_function(move |_: &Lua, (id, text): (u64, String)| {
            if let Some(s) = &*sink.borrow() {
                s.push(PanelOp::Set { id, text });
            }
            Ok(())
        })?
    })?;
    api.set("panel_highlight", {
        let sink = sink_slot.clone();
        lua.create_function(
            move |_: &Lua, (id, start, finish, style): (u64, u64, u64, String)| {
                if let Some(s) = &*sink.borrow() {
                    s.push(PanelOp::Highlight {
                        id,
                        start: start as usize,
                        end: finish as usize,
                        style,
                    });
                }
                Ok(())
            },
        )?
    })?;
    api.set("panel_clear_regions", {
        let sink = sink_slot.clone();
        lua.create_function(move |_: &Lua, id: u64| {
            if let Some(s) = &*sink.borrow() {
                s.push(PanelOp::ClearRegions { id });
            }
            Ok(())
        })?
    })?;
    api.set("panel_overlay", {
        let sink = sink_slot.clone();
        lua.create_function(
            move |_: &Lua, (id, text, always): (u64, Option<String>, Option<bool>)| {
                if let Some(s) = &*sink.borrow() {
                    s.push(PanelOp::Overlay {
                        id,
                        text,
                        always: always.unwrap_or(false),
                    });
                }
                Ok(())
            },
        )?
    })?;
    // Split panels: one titled box holding several regions, each with its own
    // caption, text, and declared grammar (the sibling of the single-body
    // panels above — `agent.split_panel` is the driver sugar). `panes` is an
    // array; each entry is either a caption string or a table with optional
    // `caption` and `lang` fields.
    api.set("panel_split", {
        let seq = Rc::clone(&panel_seq);
        let sink = sink_slot.clone();
        lua.create_function(
            move |_: &Lua, (title, panes): (String, mlua::Table)| -> mlua::Result<u64> {
                let mut inits: Vec<PaneInit> = Vec::new();
                for pair in panes.pairs::<mlua::Value, mlua::Value>() {
                    let (_, v) = pair?;
                    match v {
                        mlua::Value::String(s) => {
                            inits.push(PaneInit {
                                caption: s.to_str()?.to_string(),
                                lang: None,
                            });
                        }
                        mlua::Value::Table(t) => {
                            let caption = match t.get::<mlua::Value>("caption")? {
                                mlua::Value::String(s) => s.to_str()?.to_string(),
                                mlua::Value::Nil => String::new(),
                                _ => {
                                    return Err(mlua::Error::runtime(
                                        "split pane caption must be a string",
                                    ));
                                }
                            };
                            let lang = match t.get::<mlua::Value>("lang")? {
                                mlua::Value::String(s) => Some(s.to_str()?.to_string()),
                                mlua::Value::Nil => None,
                                _ => {
                                    return Err(mlua::Error::runtime(
                                        "split pane lang must be a string",
                                    ));
                                }
                            };
                            inits.push(PaneInit { caption, lang });
                        }
                        _ => {
                            return Err(mlua::Error::runtime(
                                "split panes: each entry is a caption string or a \
                                     { caption = …, lang = … } table",
                            ));
                        }
                    }
                }
                if inits.is_empty() {
                    return Err(mlua::Error::runtime("split panel needs at least one pane"));
                }
                let id = match &*sink.borrow() {
                    Some(s) => (*s).alloc_id(),
                    None => {
                        let mut n = seq.borrow_mut();
                        *n += 1;
                        *n
                    }
                };
                if let Some(s) = &*sink.borrow() {
                    s.push(PanelOp::Split {
                        id,
                        title,
                        panes: inits,
                    });
                }
                Ok(id)
            },
        )?
    })?;
    api.set("panel_pane_set", {
        let sink = sink_slot.clone();
        lua.create_function(move |_: &Lua, (id, pane, text): (u64, usize, String)| {
            if let Some(s) = &*sink.borrow() {
                s.push(PanelOp::SetPane { id, pane, text });
            }
            Ok(())
        })?
    })?;
    api.set("panel_pane_lang", {
        let sink = sink_slot.clone();
        lua.create_function(
            move |_: &Lua, (id, pane, lang): (u64, usize, Option<String>)| {
                if let Some(s) = &*sink.borrow() {
                    s.push(PanelOp::SetPaneLang { id, pane, lang });
                }
                Ok(())
            },
        )?
    })?;
    api.set("panel_pane_highlight", {
        let sink = sink_slot.clone();
        lua.create_function(
            move |_: &Lua, (id, pane, start, finish, style): (u64, usize, u64, u64, String)| {
                if let Some(s) = &*sink.borrow() {
                    s.push(PanelOp::HighlightPane {
                        id,
                        pane,
                        start: start as usize,
                        end: finish as usize,
                        style,
                    });
                }
                Ok(())
            },
        )?
    })?;
    api.set("panel_pane_clear_regions", {
        let sink = sink_slot.clone();
        lua.create_function(move |_: &Lua, (id, pane): (u64, usize)| {
            if let Some(s) = &*sink.borrow() {
                s.push(PanelOp::ClearPaneRegions { id, pane });
            }
            Ok(())
        })?
    })?;
    Ok(())
}

/// The standard library every VM is created with.
///
/// The standard library is **available**: mlua's safe subset already carries
/// everything the shipped tree needs — `os`, `io`, `package`, `coroutine`,
/// `string`, `table`, `math` — so config, policies and tools may use it
/// directly rather than shelling out for something `os.getenv` or `io.open`
/// answers. `agent.ask.trust` is the worked example: it resolves and identifies
/// a path with `os.rename` / `io.open` alone, where the alternative is a
/// sandboxed subprocess per question.
///
/// The two modules the safe subset withholds are `debug` and LuaJIT's `ffi`, and
/// mlua only loads those into an *unsafe* state — which also re-enables
/// C-module loading (`package.loadlib`). That trade belongs to the policy layer,
/// not the loader: widen this to `StdLib::ALL` behind `unsafe { .. }` when the
/// policy that keeps the agent from editing its own configuration lands.
/// `stdlib_is_available_to_config_policies_and_tools` holds the loader to the
/// promise this makes.
const STDLIB: mlua::StdLib = mlua::StdLib::ALL_SAFE;

/// A fresh LuaJIT VM with the `agent` namespace pre-installed.
/// A VM's panel-sink slot, published into the VM's globals so Rust can reach it
/// again by VM. It carries no methods: the only thing anyone does with it is
/// read and write the slot it holds, which [`install_sink`] and
/// [`clear_sink`] do from Rust.
pub struct SinkSlot(Rc<RefCell<Option<PanelSink>>>);

impl UserData for SinkSlot {}

/// Point `lua`'s panel primitives at `sink` until [`clear_sink`] — the loop
/// installs the current round's sink on its own long-lived config VM before a
/// tool call, and clears it after, so a panel opened outside a round reaches no
/// panel at all (exactly what a VM built with no sink used to do).
pub fn install_sink(lua: &Lua, sink: &PanelSink) -> mlua::Result<()> {
    let any: AnyUserData = lua.globals().get("__agent_sink")?;
    let slot = any.borrow::<SinkSlot>()?;
    *slot.0.borrow_mut() = Some(sink.clone());
    Ok(())
}

/// Drop the VM's panel sink, so panel operations after this go nowhere.
pub fn clear_sink(lua: &Lua) -> mlua::Result<()> {
    let any: AnyUserData = lua.globals().get("__agent_sink")?;
    let slot = any.borrow::<SinkSlot>()?;
    *slot.0.borrow_mut() = None;
    Ok(())
}

pub fn new_vm() -> mlua::Result<Lua> {
    new_vm_with_sink(None)
}

/// The VM the agent binaries run on: its configuration is the user's
/// `~/.config/agent/init.lua`, seeded from the shipped one the first time.
///
/// Returns the VM and where its configuration came from, so startup can say so
/// — a user who has never run the agent before should be told that the file now
/// exists and is theirs, because that is the moment they can edit it.
///
/// Use [`new_vm_with_sink`] for an embedded or test VM instead: this one reads
/// and writes the invoking user's home directory.
pub fn new_agent_vm(sink: Option<&PanelSink>) -> Result<(Lua, ConfigOrigin), String> {
    new_vm_with_ask_from(sink, None, &user_home_config())
}

/// The configuration the *agent* runs on: the user's `~/.config/agent/init.lua`,
/// seeded from the shipped one when it is not there yet.
///
/// Public because "invoke a tool on a VM configured like the agent's" is a real
/// thing a binary may want, and because it is better passed explicitly than
/// inferred: a function that quietly reads the invoking user's home directory is
/// a function whose behaviour depends on who is running it.
pub fn user_config() -> ConfigSource {
    user_home_config()
}

/// The configuration the *agent* runs on: the user's `~/.config/agent/init.lua`,
/// seeded from the shipped one when it is not there yet.
fn user_home_config() -> ConfigSource {
    ConfigSource::UserHome(std::env::var_os("HOME").map(std::path::PathBuf::from))
}

/// A fresh VM whose configuration comes from `config` — the seam every
/// constructor funnels through, so "which script configures this VM" is one
/// decision in one place rather than one per caller.
fn new_vm_with_ask_from(
    sink: Option<&PanelSink>,
    on_ask: Option<AskHandler>,
    config: &ConfigSource,
) -> Result<(Lua, ConfigOrigin), String> {
    let tree = lua_dir();
    let origin = match config {
        ConfigSource::Tree => ConfigOrigin::Tree,
        ConfigSource::UserHome(home) => ensure_config(&tree, home.as_deref()).1,
    };
    let lua = Lua::new_with(STDLIB, mlua::LuaOptions::default())
        .map_err(|e| format!("lua: {e}"))?;
    setup_tree(&lua, sink, on_ask, &tree, config).map_err(|e| e.to_string())?;
    Ok((lua, origin))
}

/// [`new_vm`] with an optional panel sink (see `setup_inner`).
pub fn new_vm_with_sink(sink: Option<&PanelSink>) -> mlua::Result<Lua> {
    new_vm_with_ask(sink, None)
}

/// [`new_vm_with_sink`] plus the user-permission ask handler that
/// `agent.api.ask_user` calls: this is what makes a *tool* (a registered
/// `agent.mcps` entry, run as a coroutine on this VM by
/// [`invoke_mcp_tool_with_asks`]) able to put a question to the user. Without
/// one the primitive auto-denies, so an asking policy always terminates.
pub fn new_vm_with_ask(
    sink: Option<&PanelSink>,
    on_ask: Option<AskHandler>,
) -> mlua::Result<Lua> {
    let lua = Lua::new_with(STDLIB, mlua::LuaOptions::default())
        .map_err(|e| mlua::Error::external(format!("lua VM: {e}")))?;
    setup_inner(&lua, sink, on_ask)?;
    Ok(lua)
}

/// Run a Lua chunk that may *suspend* on the agent's reactor, and collect its
/// return values — the test-side twin of what the event loop does with a tool
/// call or an event handler.
///
/// The chunk runs in a Lua thread, marked reactor-driven, so `agent.on_timeout`
/// (and the stream transports' own cadence waits) *suspend* rather than sleep
/// the thread. Each suspension is answered here with a real `tokio` sleep, which
/// is what lets a request's task — now a task on that same single-threaded
/// reactor, not a transport thread — actually make progress. A test that polls a
/// stream this way is therefore testing the shipped path, not a threaded
/// approximation of it.
#[cfg(test)]
pub(crate) async fn eval_reactor<T: mlua::FromLuaMulti>(
    lua: &Lua,
    chunk: &str,
) -> mlua::Result<T> {
    let agent: Table = lua.globals().get("agent")?;
    agent.set("__on_reactor", true)?;
    let thread = lua.load(chunk).into_function()?;
    let thread = lua.create_thread(thread)?;
    // Bounded, so a chunk that never finishes fails the test instead of hanging it.
    for _ in 0..100_000 {
        let out: mlua::MultiValue = thread.resume(())?;
        match thread.status() {
            mlua::thread::ThreadStatus::Resumable => {
                let ms: i64 = out
                    .iter()
                    .next()
                    .and_then(|v| v.as_table())
                    .and_then(|t| t.get::<mlua::Value>("ms").ok())
                    .and_then(|v| match v {
                        mlua::Value::Integer(n) => Some(n),
                        _ => None,
                    })
                    .unwrap_or(0);
                if ms > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(ms as u64)).await;
                } else {
                    tokio::task::yield_now().await;
                }
            }
            // The coroutine is done: hand its return values back the way
            // `Function::eval` would, so a caller's `let (a, b): (A, B) = …`
            // still works.
            _ => {
                return <T as mlua::FromLuaMulti>::from_lua_multi(out, lua);
            }
        }
    }
    Err(mlua::Error::RuntimeError(
        "eval_reactor: the chunk never finished".into(),
    ))
}

/// The answer to a user-permission ask. An ask is a yielded user-asking call
/// resumed with its verdict — either a bare boolean or an [`AskAnswer`], which
/// additionally carries a reason. `Deny(Some(reason))` lands exactly like a
/// policy's `agent.deny(reason)`: `denied_reason` on the outcome, `Denied:
/// <reason>` on the panel status line, and `denied_reason` in the tool JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AskAnswer {
    /// The frozen syscall runs normally.
    Allow,
    /// The syscall runs, *and the path is remembered*: the "always allow this"
    /// answer. It travels with the ask rather than as a side effect, because the
    /// handler is handed the question as text and has no path to record — the
    /// asking side does, and `agent.ask` puts it in its trust table (so the same
    /// path is not asked about again in this run).
    AllowAndTrust,
    /// The syscall is denied; the optional string names why.
    Deny(Option<String>),
}

/// An ask handler: given the formatted ask text, produce the verdict —
/// allow, or deny with an optional reason (see [`AskAnswer`]).
///
/// A VM created by [`new_vm_with_ask`] carries one, and `agent.api.ask_user` on
/// that VM calls it: the tool thread forwards the question to the TUI's event
/// loop, blocks while the user answers, and returns the verdict, which the
/// sandbox delivers to the asking thread. The handler is also told whether the
/// question may be answered with "always" — Lua's call, passed as
/// `agent.api.ask_user(text, always)`: only a question carrying something to
/// remember (a path) offers the third answer, so a plain yes/no question is
/// never handed an "always" the asking side has nowhere to put. The Lua side is
/// `lua/bash_tool.lua`'s ask handler, so every tool that drives a sandbox can
/// ask — where before only the shell could.
/// The handler a question reaches: given the text and whether `[a]lways` is on
/// offer, the user's answer. A shared `Rc` because two things need it — the VM's
/// `agent.api.ask_user` and the [`ToolRun`] driver — and they must be the *same*
/// handler, or a tool would be answered by whichever one happened to be bound.
/// `Rc`, not `Arc`: a question is asked and answered on the one thread driving
/// the tool, so it never crosses a thread and need not be `Send`.
pub type AskHandler = std::rc::Rc<dyn Fn(&str, bool) -> AskAnswer + 'static>;

// ---------------------------------------------------------------------------
// Token usage: `agent.llm.usage`, read-only, refreshed after every request.
//
// The counts the server reported for the **most recent** request — nothing
// cumulative, so a compaction shrinks what the next turn reports. Servers
// differ in how they say it: an OpenAI-compatible `usage` block
// (`prompt_tokens` / `completion_tokens`), or llama.cpp's `timings`
// (`prompt_n` / `predicted_n`), which this also reads. A server that reports
// neither leaves `reported = false` and the counts at zero — "unknown", never a
// stale number from an earlier turn or a zero that reads as "free".
//
// It sits beside the endpoint and the system prompt rather than beside the
// tools, because it *describes the request* — what the model was sent and what
// it cost — where `agent.mcps` describes what it could do.
//
// Why a process-wide snapshot rather than a field on the config VM: a value
// written on the main thread's VM would be invisible to the VMs that actually
// run Lua — a tool call, a `turn_completed` handler — because each gets a fresh
// one. The numbers are plain `Copy` data, so a snapshot every VM can be seeded
// from is both simpler and more honest: Lua sees the count as of its own VM's
// creation.
// ---------------------------------------------------------------------------

/// The prompt/completion token counts of one request, as the server reported
/// them. `None` on either side means the server did not say.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    pub prompt: Option<u64>,
    pub completion: Option<u64>,
}

impl Usage {
    /// Prompt + completion over the halves the server *did* report; `None` when
    /// it reported neither.
    pub fn total(&self) -> Option<u64> {
        match (self.prompt, self.completion) {
            (None, None) => None,
            (p, c) => Some(p.unwrap_or(0) + c.unwrap_or(0)),
        }
    }
}

/// The most recent request's counts, process-wide (see the section docs).
static LAST_USAGE: OnceLock<std::sync::Mutex<Usage>> = OnceLock::new();

fn last_usage() -> Usage {
    LAST_USAGE
        .get()
        .and_then(|m| m.lock().ok().map(|g| *g))
        .unwrap_or_default()
}

/// Serialize the tests that read or write the process-wide usage snapshot, and
/// clear it. The snapshot is process-wide by design — that is how a tool VM and
/// the config VM agree on the counts — so tests that assert on it would
/// otherwise race each other through the shared state.
#[cfg(test)]
fn usage_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(slot) = LAST_USAGE.get()
        && let Ok(mut usage) = slot.lock()
    {
        *usage = Usage::default();
    }
    guard
}

/// Record the counts of a finished request: every VM created from here on sees
/// them, and the config VM's own `agent.llm.usage` is refreshed in place.
pub fn record_usage(lua: &Lua, usage: Usage) {
    let slot = LAST_USAGE.get_or_init(|| std::sync::Mutex::new(Usage::default()));
    if let Ok(mut guard) = slot.lock() {
        *guard = usage;
    }
    if let Some(t) = usage_backing(lua) {
        let _ = write_usage(&t, usage);
        return;
    }
    // Missing or not the locked proxy: a config that replaced `agent.llm` (or
    // the `usage` key in it) dropped it. Put a locked table back rather than
    // leave Lua holding a writable one — or none at all.
    let _ = install_usage(lua);
}

/// The real table behind `agent.llm.usage`'s read-only proxy, when it is there.
fn usage_backing(lua: &Lua) -> Option<Table> {
    let proxy = lua
        .globals()
        .get::<Table>("agent")
        .ok()?
        .get::<Table>("llm")
        .ok()?
        .get::<Table>("usage")
        .ok()?;
    let mt = proxy.metatable()?;
    let real = mt.get::<Table>("__index").ok()?;
    // Only trust our own proxy: a plain table with an `__index` of another
    // shape is not the read-only view.
    if mt.get::<mlua::Value>("__newindex").is_ok() {
        Some(real)
    } else {
        None
    }
}

/// (Re)install `agent.llm.usage` as a fresh read-only proxy over the current
/// snapshot. Called at VM setup (after the entry script created `agent.llm`) and
/// by [`record_usage`] when the key went missing. A tree with no `agent.llm` at
/// all (a loader fixture, say) simply has no counters to expose.
fn install_usage(lua: &Lua) -> mlua::Result<()> {
    let Ok(agent) = lua.globals().get::<Table>("agent") else {
        return Ok(());
    };
    let Ok(llm) = agent.get::<Table>("llm") else {
        return Ok(());
    };
    llm.set("usage", usage_proxy(lua, last_usage())?)
}

fn write_usage(t: &Table, usage: Usage) -> mlua::Result<()> {
    t.set("prompt", usage.prompt.unwrap_or(0))?;
    t.set("completion", usage.completion.unwrap_or(0))?;
    t.set("total", usage.total().unwrap_or(0))?;
    t.set("reported", usage.total().is_some())?;
    Ok(())
}

/// A fresh read-only `agent.llm.usage` proxy over the current snapshot.
fn usage_proxy(lua: &Lua, usage: Usage) -> mlua::Result<Table> {
    let real = lua.create_table()?;
    write_usage(&real, usage)?;
    lock_table(lua, real, "llm.usage")
}

// ---------------------------------------------------------------------------
// Agent configuration in Lua: the LLM endpoint, the system prompt, the tools.
// ---------------------------------------------------------------------------
//
// The agent's configuration lives in Lua, not in environment variables. A
// user config (`~/.config/agent/init.lua`, see [`config_path`]) is loaded
// after `lua/init.lua` and can set:
//
//   1. the LLM endpoint — `agent.llm = { base_url, model, api_key }`,
//      which used to be the AGENT_BASE_URL / AGENT_MODEL / AGENT_API_KEY
//      environment variables (the TUI builds `api::ChatConfig` from it);
//   2. the system prompt — `agent.llm.system_prompt`, sent as the leading
//      `system` message of every request;
//   3. the tools — plain `agent.mcps` entries: [`agent.utils.tool`] objects and the
//      connections `agent.mcp` opens. That table is the whole registry.
//   4. event hooks — `agent.on_event("turn_completed", fn)` registers a
//      handler Rust fires when a full user turn ends, with the conversation
//      in the payload (`{ history = {...} }`): the read side of compaction.
//      The handler runs **cooperatively on the agent's single reactor
//      thread** as a coroutine (see [`EventRun`]): each `agent.on_timeout`
//      wait suspends it until the reactor's timer fires, so the loop never
//      blocks on handler I/O — strictly single-threaded; the old
//      fire-and-forget background thread is gone. A handler calling
//      `agent.bash` runs it **cooperatively** the same way: on the reactor
//      `_step` polls are non-blocking and the pump suspends for a cadence
//      between idle steps, so a long-running command yields
//      [`EventStep::Waiting`] all the way through and the loop stays live
//      (asks auto-deny — no ask UI in a background handler);
//   5. driving the loop — `agent.trigger(...)` forces a new inference, and an
//      array argument **replaces** the loop's in-memory history first (a
//      compacted history handed back): the write side of compaction.
//
// Two primitives are enough to steer the agent, and composing them is the
// user's job, not the runtime's: the **system prompt** says what the agent
// should do, and a **reactive policy table** — the seccomp policy
// `agent.bash` takes — says what its commands may do, deciding per syscall at
// runtime. Grouping those two into a named, switchable pair *is* modelled, but
// only as a Lua mechanism (`lua/lib/mode.lua` → `agent.mode`):
// `agent.mode.set(name)` overwrites `agent.mcps` and
// `agent.llm.system_prompt`, both of which Rust re-reads per request, so a
// switch is live without a restart. The same goes for
// compaction: Rust only supplies the event (read), the trigger (force an
// inference), and the history replacement (write) — what to summarize and
// how is Lua's decision.
//
// Persistence is the same deal with a default: the loop archives every
// history message to an append-only, block-compressed conversation log on
// disk (`crate::memory`) shared behind a process-wide mutex
// ([`bind_memory`] — path and on/off from `agent.llm.memory`), flushing
// at turn boundaries and on exit. Lua reads and writes the same store
// through `agent.memory.append / latest / flush / path`. The archive is a
// raw append-only transcript: compaction shrinks only the *in-memory*
// history, never what was logged.
//
// Rust **never caches** the registry. Every request reindexes `agent.mcps`
// (the live table) and every tool call runs on the config VM itself — so an
// config edit shows up on the very next request, with no stale Rust state,
// and whatever a tool decided (a trusted path, a trusted server) is still there
// on the next one. The only Rust state is the config VM, and the process is
// single-threaded, so it never has to cross a thread. mlua is built without the
// `send` feature (Cargo.toml is frozen), which is what makes that a constraint
// rather than a choice: a `Lua` is not `Send`, and a tool is therefore a
// coroutine the event loop steps, not work handed to a thread of its own.

// The runtime machinery for the Lua configuration — the built-in defaults,
// which a user's copy then edits — lives in the entry script
// `lua/init.lua`, which [`load_init`] runs on every VM (so it is always present
// by the time anything reads `agent.llm`). It requires the driver itself
// (`require("driver")`) for the `agent.bash` / `agent.memory` half of the
// namespace; the `agent.*` namespace itself comes from `lua/lib/`. Its
// assignments are `or`-guarded, so re-loading never clobbers user values — which
// is also why a config assigns `agent.llm.<field>` rather than replacing the
// table: the keys it does not mention (`memory`) have to survive.
//
// One piece of the surface is *not* Lua at all: `agent.llm.usage`, the read-only
// token counts of the last request, is written by the loop (see [`record_usage`])
// and seeded into every VM.

/// Where the user's configuration lives: `~/.config/agent/init.lua`, and
/// nowhere else. `None` when it does not exist, which is the normal case — the
/// built-ins in the shipped `lua/init.lua` are a working agent on their own.
///
/// One location, deliberately. This used to be `./agent.lua` first and
/// `~/.config/agent/agent.lua` second, which made *which* config was in force
/// depend on the directory you happened to launch from — so a stray `agent.lua`
/// in a checkout silently shadowed the real one, and `/reload` named a path that
/// had nothing to do with the other. A single home-directory path answers "what
/// is configured" without asking where you are standing.
///
/// The name matches the shipped entry script's on purpose: it is the same *kind*
/// of file — a chunk of Lua layered over the defaults — and the two cannot be
/// confused at runtime, because the user's lives outside the tree the loader
/// searches. Error messages name the file they came from, which is the only
/// place the two `init.lua` names appear side by side.
pub fn config_path() -> Option<std::path::PathBuf> {
    config_path_in(std::env::var_os("HOME").map(std::path::PathBuf::from))
}

/// Where a VM's configuration comes from.
///
/// The split is not tidiness: one of these reads and writes the invoking user's
/// home directory, and a test suite that did that by accident would be testing
/// the machine rather than the code. So the home-directory path is opt-in, and
/// [`ConfigSource::Tree`] is what every test gets.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ConfigSource {
    /// The shipped `lua/init.lua`, run where it lies. Touches no `$HOME`.
    #[default]
    Tree,
    /// The user's `~/.config/agent/init.lua`, seeded from the shipped one the
    /// first time. What the agent binaries run on.
    UserHome(Option<std::path::PathBuf>),
}

/// How a VM's configuration came to be, so the caller can say so at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigOrigin {
    /// The shipped `init.lua` was run directly; no user config is involved.
    Tree,
    /// The user's `init.lua` already existed and was run.
    Existing,
    /// The user's `init.lua` did not exist, so the shipped one was copied there
    /// and run. It is now *theirs* to edit.
    Seeded,
}

/// The user's configuration file, seeded from the tree's `init.lua` when it does
/// not exist yet.
///
/// This is the difference between a program that ships a configuration file and
/// one that ships a *template*: after the first run the file at
/// `~/.config/agent/init.lua` is the agent's configuration, and the copy beside
/// the binary is only what it was seeded from. Editing it is the supported way
/// to configure anything, and `/reload` re-reads it.
///
/// The consequence to be aware of: upgrading the agent does **not** update a
/// config that has already been seeded, because the user's file is now the
/// authority. Delete it to be re-seeded from whatever ships next.
///
/// A home that cannot be written (a read-only `$HOME`, a container running as
/// nobody) is not fatal: the tree's own `init.lua` is run instead and the caller
/// is told, because an agent with its defaults beats an agent that will not
/// start.
pub fn ensure_config(
    tree: &Path,
    home: Option<&std::path::Path>,
) -> (std::path::PathBuf, ConfigOrigin) {
    let shipped = tree.join("init.lua");
    let Some(home) = home else {
        return (shipped, ConfigOrigin::Tree);
    };
    let dir = home.join(".config").join("agent");
    let path = dir.join("init.lua");
    if path.is_file() {
        return (path, ConfigOrigin::Existing);
    }
    if let Err(why) = std::fs::create_dir_all(&dir)
        .and_then(|()| std::fs::copy(&shipped, &path))
    {
        eprintln!(
            "[agent] could not write {} ({why}); using the built-in defaults",
            path.display()
        );
        return (shipped, ConfigOrigin::Tree);
    }
    (path, ConfigOrigin::Seeded)
}

/// [`config_path`] with `$HOME` taken explicitly, so *where* the config lives
/// is assertable without setting an environment variable — the same trick
/// [`lua_dir_in`] plays for the Lua tree, and for the same reason: a test that
/// shells out to the ambient environment tests the machine, not the code.
fn config_path_in(home: Option<std::path::PathBuf>) -> Option<std::path::PathBuf> {
    let p = home?
        .join(".config")
        .join("agent")
        .join("init.lua");
    // `is_file`, not `exists`: a *directory* called `init.lua` would otherwise
    // be taken for the config and then fail at read time, with a message about
    // the file rather than about the directory. The Lua tree's own resolution
    // (`lua_dir_in`) makes the same check for the same reason.
    p.is_file().then_some(p)
}

/// Apply the user's configuration (the contents of that `init.lua`) to `lua`:
/// the shipped entry script is already loaded (by `setup_inner`, via
/// `load_init`), then the user chunk runs on top. A blank source is a no-op
/// (the built-in defaults stand).
pub fn apply_config_source(lua: &Lua, source: &str) -> Result<(), String> {
    if source.trim().is_empty() {
        return Ok(());
    }
    lua.load(source)
        .exec()
        .map_err(|e| format!("config: ~/.config/agent/init.lua: {e}"))?;
    // A config that assigns the whole table (`agent.llm = { ... }`) drops the
    // read-only counters along with anything it did not mention. Put them back
    // now rather than leaving the surface incomplete until the next request
    // happens to record one.
    install_usage(lua).map_err(|e| format!("config: agent.llm.usage: {e}"))?;
    Ok(())
}

/// Load the user's config (see [`config_path`]) into `lua`. Missing
/// file -> `Ok(false)` with the driver defaults in place; loaded -> `Ok(true)`.
pub fn load_config_file(lua: &Lua) -> Result<bool, String> {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let (path, origin) = ensure_config(&lua_dir(), home.as_deref());
    if origin == ConfigOrigin::Tree {
        return Ok(false);
    }
    let source = std::fs::read_to_string(&path)
        .map_err(|e| format!("config: read {}: {e}", path.display()))?;
    apply_config_source(lua, &source)?;
    Ok(true)
}

/// The LLM endpoint the agent talks to, read from `agent.llm` (the Lua
/// configuration, replacing the AGENT_BASE_URL / AGENT_MODEL / AGENT_API_KEY
/// environment variables).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmConfig {
    pub base_url: String,
    pub api_key: String,
    pub model: String,
}

/// Read `agent.llm.{base_url, model, api_key}`, falling back per-field to the
/// defaults both `lua/init.lua` and api.rs's old `from_env` agree on.
pub fn llm_config(lua: &Lua) -> Result<LlmConfig, String> {
    let agent: Table = lua
        .globals()
        .get("agent")
        .map_err(|e| format!("config: agent table: {e}"))?;
    let mut llm = LlmConfig {
        base_url: "https://api.openai.com/v1".to_string(),
        api_key: String::new(),
        model: "gpt-4o-mini".to_string(),
    };
    if let Ok(t) = agent.get::<Table>("llm") {
        llm.base_url = t.get("base_url").unwrap_or(llm.base_url);
        llm.api_key = t.get("api_key").unwrap_or(llm.api_key);
        llm.model = t.get("model").unwrap_or(llm.model);
    }
    Ok(llm)
}

/// The system prompt the agent sends as the leading `system` message of every
/// request: `agent.llm.system_prompt` (`""` — the default — means none, so
/// requests start with the conversation itself).
///
/// Read per request off the live config VM, like the tool registry: editing it
/// in the user's config, and reloading changes what the model is told next turn.
pub fn system_prompt(lua: &Lua) -> Result<String, String> {
    let agent: Table = lua
        .globals()
        .get("agent")
        .map_err(|e| format!("config: agent table: {e}"))?;
    let config: Table = agent.get("llm").map_err(|e| format!("config: agent.llm: {e}"))?;
    Ok(config.get("system_prompt").unwrap_or_default())
}

/// One tool advertised by `agent.mcps`, at lib level — the bins translate it
/// into their own `api::ToolDef` (api.rs lives per-binary).
#[derive(Debug, Clone)]
pub struct McpToolDef {
    pub name: String,
    pub description: String,
    /// The tool's advertised `inputSchema`, already a JSON object schema.
    pub parameters: serde_json::Value,
}

/// The name a tool is advertised and called by: `{connection}.{tool}`.
///
/// Connections are a namespace, and the name the model sees has to carry it.
/// A bare `list_issues` from two MCP servers is not one tool, it is two tools
/// with one name — and the registry resolves a bare name by scanning every
/// connection and taking the first hit, so the loser is unreachable rather than
/// merely ambiguous. Qualifying at the point of advertisement means the
/// collision cannot be expressed.
///
/// Split on the **first** dot only, so a tool whose own name contains a dot
/// (`github.create_issue.comment`, say) survives the round trip.
pub(crate) fn qualified_name(conn: &str, tool: &str) -> String {
    format!("{conn}.{tool}")
}

/// Split an advertised name back into `(connection, tool)`, or `None` when it is
/// not qualified. The inverse of [`qualified_name`].
fn split_qualified(name: &str) -> Option<(&str, &str)> {
    name.split_once('.')
        .filter(|(conn, tool)| !conn.is_empty() && !tool.is_empty())
}

/// Reindex `agent.mcps` in `lua`: read the live registry and return one
/// [`McpToolDef`] per registered tool, sorted by name for a stable order.
///
/// Called **per request** and never cached — see the section docs. The result
/// reflects whatever the table holds at that moment (a hand-built connection
/// from `agent.utils.tool`, or one `agent.mcp` opened), so the caller re-derives
/// its advertised tool list on every request instead of keeping a Rust-side
/// snapshot.
pub fn mcps_tool_defs(lua: &Lua) -> Result<Vec<McpToolDef>, String> {
    let agent: Table = lua
        .globals()
        .get("agent")
        .map_err(|e| format!("mcps: agent table: {e}"))?;
    let mcps: Table = agent
        .get("mcps")
        .map_err(|e| format!("mcps: agent.mcps: {e}"))?;
    let mut defs = Vec::new();
    for pair in mcps.pairs::<String, Table>() {
        let (conn_name, conn) = pair.map_err(|e| format!("mcps: conn: {e}"))?;
        let tools: Table = conn
            .get("tools")
            .map_err(|e| format!("mcps: {conn_name}.tools: {e}"))?;
        for pair in tools.pairs::<String, Table>() {
            let (tool_name, tool) = pair.map_err(|e| format!("mcps: tool: {e}"))?;
            let name = qualified_name(&conn_name, &tool_name);
            let description: String = tool.get("description").unwrap_or_default();
            let signature: mlua::Value = tool.get("signature").unwrap_or(mlua::Value::Nil);
            let parameters = crate::mcp::lua_to_json( &signature)
                .map_err(|e| format!("mcps: {name} signature: {e}"))?;
            defs.push(McpToolDef {
                name,
                description,
                parameters,
            });
        }
    }
    defs.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(defs)
}

/// Invoke a tool registered in `agent.mcps` on an already-configured VM (the
/// user configuration applied).
///
/// Returns `Ok(None)` when `name` is not in the registry — the caller's cue to
/// refuse it (the agent loop additionally gates on what the request offered);
/// `Ok(Some((body, content)))` with the MCP-shaped result
/// (`{ok, result, error, denied}`) as JSON text; `Err` for JSON / VM failures.
pub fn invoke_tool(
    lua: &Lua,
    name: &str,
    arguments: &str,
) -> Result<Option<(String, String)>, String> {
    invoke_tool_asking(lua, name, arguments, None)
}

/// [`invoke_tool`], answering any question the tool asks with `on_ask` — the
/// same wiring [`ToolRun`] gives the TUI, driven to completion right here
/// instead of by the event loop.
///
/// This is the **blocking** driver: for tests, the headless probe, and any
/// caller with no reactor to step a coroutine. The tool still runs as a Lua
/// coroutine on `lua` (that is what lets it ask at all), but each ask is
/// answered immediately by `on_ask` — or denied, with no handler, exactly as
/// `agent.api.ask_user` denies when no one is there. A sandbox's cooperative
/// cadence waits are pumped here by the same immediate resume, so a long command
/// is waited out rather than slept through.
pub fn invoke_tool_asking(
    lua: &Lua,
    name: &str,
    arguments: &str,
    on_ask: Option<AskHandler>,
) -> Result<Option<(String, String)>, String> {
    // Nobody is going to give this coroutine slices: it is being driven to
    // completion right here, on this thread, with no reactor in between. So the
    // VM is *not* marked reactor-driven for the call — a sandbox run inside the
    // tool then blocks in `agent.api.step` as its wait, which is the only way a
    // reactor-less driver can make progress. (The TUI drives the same tool with
    // `ToolRun` directly, where the marker is right and the loop is the reactor.)
    // Restored afterwards, so a tool that switched modes or armed a timer is
    // unaffected either way.
    let agent: Table = lua
        .globals()
        .get("agent")
        .map_err(|e| format!("config: {name}: agent table: {e}"))?;
    let was_reactor = agent.get::<mlua::Value>("__on_reactor").ok();
    agent
        .set("__on_reactor", false)
        .map_err(|e| format!("config: {name}: reactor marker: {e}"))?;
    let driven = drive_blocking(lua, name, arguments, on_ask);
    match &was_reactor {
        Some(v) => {
            agent
                .set("__on_reactor", v.clone())
                .map_err(|e| format!("config: {name}: reactor restore: {e}"))?;
        }
        None => {
            let _ = agent.set("__on_reactor", mlua::Value::Nil);
        }
    }
    driven
}

/// The blocking drive loop, factored out so the marker handling above can wrap
/// it. Returns the same `(body, content)` shape as before.
fn drive_blocking(
    lua: &Lua,
    name: &str,
    arguments: &str,
    on_ask: Option<AskHandler>,
) -> Result<Option<(String, String)>, String> {
    let Some((mut run, mut step)) = ToolRun::start(lua, name, arguments)? else {
        return Ok(None);
    };
    loop {
        match step {
            ToolStep::Returned(text) => return Ok(Some((text.clone(), text))),
            ToolStep::Ask { text, always } => {
                let verdict = match &on_ask {
                    Some(h) => verdict_to_lua(lua, &h(&text, always)),
                    // Nobody to ask: a tool must never hang on an orphaned
                    // question, so this is a denial.
                    None => mlua::Value::Boolean(false),
                };
                step = run
                    .answer(verdict)
                    .map_err(|e| format!("config: {name}: {e}"))?;
            }
            ToolStep::Waiting { .. } => {
                step = run
                    .wait()
                    .map_err(|e| format!("config: {name}: {e}"))?;
            }
        }
    }
}

/// An [`AskAnswer`] as the value a yield site receives — the same normalization
/// `agent.api.ask_user` does, so a tool cannot tell which driver answered it:
/// the TUI's loop builds one and hands it to [`ToolRun::answer`], and
/// `invoke_tool_asking` does the same for the blocking driver.
pub fn verdict_to_lua(lua: &Lua, answer: &AskAnswer) -> mlua::Value {
    let table = lua.create_table().expect("verdict table");
    match answer {
        AskAnswer::Allow => mlua::Value::Boolean(true),
        AskAnswer::Deny(reason) => match reason {
            None => mlua::Value::Boolean(false),
            Some(why) => {
                table
                    .set("__agent_verdict", "deny")
                    .and_then(|()| table.set("reason", why.as_str()))
                    .expect("verdict fields");
                mlua::Value::Table(table)
            }
        },
        AskAnswer::AllowAndTrust => {
            table
                .set("__agent_verdict", "allow")
                .and_then(|()| table.set("trust", true))
                .expect("verdict fields");
            mlua::Value::Table(table)
        }
    }
}

/// [`invoke_tool`] on a fresh, thread-safe VM: loads the user configuration
/// (the entry script + any user config), then invokes. Used by the TUI's
/// background tool threads, so the VM lives and dies here — it never crosses
/// threads afterwards (mlua is built without `send`).
///
/// With no ask handler an asking policy auto-denies (see
/// [`invoke_mcp_tool_with_asks`]), so this is the headless entry point.
pub fn invoke_mcp_tool(
    name: &str,
    arguments: &str,
    sink: Option<&PanelSink>,
) -> Result<Option<(String, String)>, String> {
    invoke_mcp_tool_with_asks(name, arguments, sink, None, &user_config())
}

/// [`invoke_mcp_tool`] whose VM carries a user-permission ask handler, so a
/// tool that drives a sandbox can put its policy's questions to the user:
/// `agent.api.ask_user` on that VM calls `on_ask` and blocks for the verdict,
/// exactly as the TUI's tool thread does. The shell's panel-driving wrapper
/// lives in Lua now (`lua/bash_tool.lua`), so *every* tool gets this, not just
/// the shell.
///
/// `Ok(None)` still means "no such tool in `agent.mcps`": the registry is the
/// only place a tool can come from, so the caller has nothing to fall back to.
pub fn invoke_mcp_tool_with_asks(
    name: &str,
    arguments: &str,
    sink: Option<&PanelSink>,
    on_ask: Option<AskHandler>,
    config: &ConfigSource,
) -> Result<Option<(String, String)>, String> {
    let handler = on_ask.clone();
    // `config` is a parameter rather than a guess: a tool invoked on its own
    // should see the same configuration the agent does, but a test asserting on
    // tool behaviour must not depend on whoever is running it.
    let (lua, _) =
        new_vm_with_ask_from(sink, on_ask, config).map_err(|e| format!("config: vm: {e}"))?;
    // The handler goes to the *driver*, not only to the VM: a question the tool
    // raises is a yield the driver answers. It is installed on the VM as well
    // (`agent.api.ask_user`), for the Lua code that asks by calling it directly
    // rather than by yielding — the shell tool's own ask handler, outside a
    // reactor context.
    invoke_tool_asking(&lua, name, arguments, handler)
}

/// One command a Lua handler sends the agent loop. The loop (the TUI's `run`)
/// consumes these on its idle select — the compaction primitives are how Lua
/// drives the loop: `on_event("turn_completed")` hears that a turn finished
/// (the conversation travels in the event payload, the **read** side), and
/// `agent.trigger` starts the next inference, optionally carrying a replaced
/// history (the **write** side).
#[derive(Debug, Clone)]
pub enum AgentCommand {
    /// Force a new inference now. `history` replaces the loop's in-memory
    /// conversation before the turn runs (a compaction replacement, divided
    /// into a summary message + recent tail); `user` behaves like a submitted
    /// user message pushed onto the history. At most one of the two is set.
    RunTurn {
        history: Option<Vec<serde_json::Value>>,
        user: Option<String>,
    },
    /// Change the input line: [`InputOp`].
    Input(InputOp),
}

/// What Lua may do to the input line.
///
/// The input box is loop state — a `String` on the `App` — and the `key` event is
/// the only thing a config has to change it from. Until this existed the action
/// vocabulary was the sole route to it, which meant the set of things a key
/// could do was frozen into [`crate::tui::Action`] whether a user wanted it or
/// not: there was no way for a binding to insert text, so a newline had to be
/// `Action::Newline` and nothing else could ever type into the box on demand.
///
/// Append-only, and deliberately so. There is no cursor, so "insert" means "at
/// the end", and a primitive that pretended otherwise would be inventing a
/// position model the widget does not have. `Backspace` is the mirror of
/// `Append` and the two together are enough to build anything a key table
/// actually needs — a leader key inserting a snippet, a chord typing a
/// character — without a second primitive for "delete a word".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputOp {
    /// Append text to the input line.
    Append(String),
    /// Remove the last character, if there is one.
    Backspace,
    /// Empty the line, as `Ctrl+u` in readline does.
    Clear,
}

/// The channel trigger commands ride to the agent loop: `agent.trigger` sends
/// an [`AgentCommand`] here; the loop's idle select drains it. Bound once at
/// startup by the TUI ([`bind_trigger_channel`]); unbound — a Lua `trigger`
/// that returns `false` instead of queueing — in the probe and tests, which
/// have no loop to drive.
static TRIGGER_TX: OnceLock<mpsc::UnboundedSender<AgentCommand>> = OnceLock::new();

/// Bind the trigger channel the agent loop drains (see [`AgentCommand`]).
/// Returns `None` when already bound — the TUI binds once at startup.
pub fn bind_trigger_channel(tx: mpsc::UnboundedSender<AgentCommand>) -> Option<()> {
    TRIGGER_TX.set(tx).ok()
}

/// Fire a registered event and hand back what its handler returned, as a string.
///
/// This exists for the one event whose *return value is the answer*: `key`, where
/// a handler returns the name of the action the key should perform, or nothing to
/// leave the key to its default binding. Every other event ignores the return,
/// and goes through [`fire_event_on_vm`] instead — which is the honest shape for
/// a notification, and keeps "this event is a question" out of the generic path.
///
/// A handler that returns something other than a string or nil is an error: the
/// caller has to be able to tell "no answer" from "a badly-typed answer", and
/// quietly treating the second as the first is how a binding silently dies.
///
/// Runs as a plain call, like [`fire_event_on_vm`]: a keypress handler must not
/// be able to yield. A `key` handler that slept would be holding up the only
/// thread that reads input, and there is no reactor behind it to resume on.
pub fn fire_event_returning(
    lua: &Lua,
    name: &str,
    payload: &serde_json::Value,
) -> Result<Option<String>, String> {
    let agent: Table = lua
        .globals()
        .get("agent")
        .map_err(|e| format!("event: agent table: {e}"))?;
    let events: Table = match agent.get("_events") {
        Ok(t) => t,
        // No registrations on this VM: events are opt-in, so nothing to ask.
        Err(_) => return Ok(None),
    };
    let handler: mlua::Function = match events.get(name) {
        Ok(f) => f,
        Err(_) => return Ok(None), // no handler for this event: the default stands
    };
    let payload_lua =
        crate::mcp::json_to_lua(lua, payload).map_err(|e| format!("event: payload: {e}"))?;
    let answer: mlua::Value = handler
        .call(payload_lua)
        .map_err(|e| format!("event {name}: {e}"))?;
    match answer {
        mlua::Value::Nil => Ok(None),
        mlua::Value::String(s) => Ok(Some(s.to_string_lossy().to_string())),
        mlua::Value::Boolean(b) if !b => Ok(None),
        other => Err(format!(
            "event {name}: a handler must return an action name or nil, got {}",
            other.type_name()
        )),
    }
}

/// Fire a registered event on `lua`, which must already have the user's
/// configuration applied (entry script + user config, whose top-level
/// `agent.on_event(...)` calls registered the handlers). The handler runs in
/// the calling thread as a plain call — no coroutine, no reactor; the TUI drives
/// its own handler through [`EventRun`] instead, so it can yield.
///
/// Returns whether a handler was registered and ran (events are opt-in, so
/// `false` is normal), and the handler's own error otherwise.
pub fn fire_event_on_vm(lua: &Lua, name: &str, payload: &serde_json::Value) -> Result<bool, String> {
    let agent: Table = lua
        .globals()
        .get("agent")
        .map_err(|e| format!("event: agent table: {e}"))?;
    let events: Table = match agent.get("_events") {
        Ok(t) => t,
        // No registrations on this VM: events are opt-in, so nothing to fire.
        Err(_) => return Ok(false),
    };
    let handler: mlua::Function = match events.get(name) {
        Ok(f) => f,
        Err(_) => return Ok(false), // no handler for this event: opt-in
    };
    let payload_lua =
        crate::mcp::json_to_lua(lua, payload).map_err(|e| format!("event: payload: {e}"))?;
    handler
        .call::<()>(payload_lua)
        .map(|_| true)
        .map_err(|e| format!("event {name}: {e}"))
}

/// One step of a reactor-driven event handler coroutine ([`EventRun`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventStep {
    /// The handler returned.
    Returned,
    /// The handler suspended on an `agent.on_timeout(ms, ...)` wait; the
    /// reactor must resume it after `ms` milliseconds (it passes `true` back
    /// into the yield site).
    Waiting { ms: u64 },
}

/// A `turn_completed`-style event handler driven **cooperatively** on the
/// agent's single reactor thread — the strictly single-threaded successor to
/// the fire-and-forget background thread.
///
/// The handler runs as a Lua coroutine **on the agent's own configuration VM**
/// (the same one the loop reads the system prompt and the tool registry from),
/// not on a throwaway one. That is what lets a handler *change* the agent rather
/// than merely watch it: a mode it switches, a setting it writes, and a flag it
/// arms are all still there when the turn it triggers runs — and when the next
/// event arrives. It is also why the coroutine may span turns: `Lua` state
/// outlives each `coroutine.resume`, so a handler suspended on a timer resumes
/// with everything it had.
///
/// Every `agent.on_timeout(ms, ...)` wait yields a
/// `{ __agent_await = "timeout", ms = ms }` request to the driver, which decodes
/// it into [`EventStep::Waiting`]; the caller (the TUI loop) arms a reactor timer
/// and calls [`EventRun::step`] when it fires. The `Lua` state never leaves the
/// thread that created it (mlua here is built without the `send` feature). A
/// handler that calls `coroutine.yield` directly yields an undecodable value and
/// errors.
pub struct EventRun<'lua> {
    lua: &'lua Lua,
    thread: mlua::Thread,
}

impl<'lua> EventRun<'lua> {
    /// Resume the handler for `name` on `lua` for the first time, with
    /// `payload` as its argument. `Ok(None)` when no handler is registered for
    /// `name` (events are opt-in).
    pub fn start(
        lua: &'lua Lua,
        name: &str,
        payload: &serde_json::Value,
    ) -> Result<Option<(EventRun<'lua>, EventStep)>, String> {
        let agent: Table = lua
            .globals()
            .get("agent")
            .map_err(|e| format!("event: agent table: {e}"))?;
        let events: Table = match agent.get("_events") {
            Ok(t) => t,
            // No init script / no registrations on this VM: events are
            // opt-in, so there is nothing to fire.
            Err(_) => return Ok(None),
        };
        let handler: mlua::Function = match events.get(name) {
            Ok(f) => f,
            Err(_) => return Ok(None), // no handler for this event: opt-in
        };
        let payload_lua =
            crate::mcp::json_to_lua(lua, payload).map_err(|e| format!("event: payload: {e}"))?;
        // Mark this VM as reactor-driven: `agent.on_timeout` now suspends the
        // running coroutine instead of falling back to a thread sleep.
        agent
            .set("__on_reactor", true)
            .map_err(|e| format!("event: reactor marker: {e}"))?;
        let thread = lua
            .create_thread(handler)
            .map_err(|e| format!("event: coroutine: {e}"))?;
        let mut run = EventRun { lua, thread };
        let step = run
            .resume_with(Some(payload_lua))
            .map_err(|e| format!("event {name}: {e}"))?;
        Ok(Some((run, step)))
    }

    /// Resume the suspension: the reactor's timer for the last
    /// [`EventStep::Waiting`] fired. `true` lands back at the yielding
    /// `agent.on_timeout` call site.
    pub fn step(&mut self) -> Result<EventStep, String> {
        self.resume_with(Some(mlua::Value::Boolean(true)))
    }

    /// The VM the handler runs on — the agent's own config VM, borrowed for as
    /// long as the run lasts (tests inspect its globals afterwards).
    pub fn lua(&self) -> &Lua {
        self.lua
    }

    /// One resume: the first call lands `arg` as the handler function's
    /// argument; later calls land it as the value of the last `coroutine.yield`
    /// (`None` resumes with no value at all).
    fn resume_with(&mut self, arg: Option<mlua::Value>) -> Result<EventStep, String> {
        let res: mlua::Value = self.thread.resume(arg).map_err(err_to_event)?;
        match self.thread.status() {
            mlua::thread::ThreadStatus::Resumable => decode_await(res),
            _ => Ok(EventStep::Returned),
        }
    }
}

fn err_to_event(e: mlua::Error) -> String {
    format!("event handler: {e}")
}

// ---------------------------------------------------------------------------
// A tool call, driven cooperatively on the agent's single reactor thread
// ---------------------------------------------------------------------------

/// One step of a reactor-driven tool call coroutine ([`ToolRun`]).
#[derive(Debug, Clone, PartialEq)]
pub enum ToolStep {
    /// The tool asked the user a question. `text` is what the prompt shows and
    /// `always` is whether it may offer `[a]lways` — Lua's flag, carried
    /// through untouched. Resume with the verdict (see [`ToolRun::answer`]).
    Ask { text: String, always: bool },
    /// The tool suspended on a reactor wait: an `agent.on_timeout` inside the
    /// tool, or the sandbox's own cooperative cadence between idle steps (the
    /// drive loop in `lua/lib/bash.lua` yields one every time `agent.api.step`
    /// has nothing ready). Resume after `ms` — nothing is delivered to the
    /// yield site.
    Waiting { ms: u64 },
    /// The tool returned: its result value, already encoded as the MCP JSON
    /// text that becomes the tool result in the conversation.
    Returned(String),
}

/// A tool call driven **cooperatively** on the agent's single reactor thread,
/// on the agent's own configuration VM — the same [`EventRun`] shape, for the
/// other kind of Lua code that used to get a thread of its own.
///
/// Two things follow from running on that VM rather than a throwaway one. State
/// a tool writes is still there next call: a path trusted with `[a]lways` is
/// remembered, a mode a tool switches persists, a counter a tool increments
/// accumulates. And there is no second VM to build, so the config is parsed
/// once per process instead of once per tool call.
///
/// The coroutine is what makes a *question* possible at all: a tool callback is
/// reached across the mlua boundary, where `coroutine.yield` cannot cross, so
/// the callback runs in a Lua thread that this type owns and steps. The VM is
/// marked reactor-driven, so a sandbox run inside the tool yields its cadence
/// ([`ToolStep::Waiting`]) instead of blocking the loop in `agent.api.step`.
pub struct ToolRun<'lua> {
    lua: &'lua Lua,
    thread: mlua::Thread,
    name: String,
}

impl<'lua> ToolRun<'lua> {
    /// Begin the named tool from `agent.mcps` on `lua`, with `arguments` as its
    /// single argument. `Ok(None)` when the registry holds no such tool — the
    /// registry is the only place a tool can come from, so there is nothing to
    /// fall back to.
    pub fn start(
        lua: &'lua Lua,
        name: &str,
        arguments: &str,
    ) -> Result<Option<(ToolRun<'lua>, ToolStep)>, String> {
        let Some(call) = lookup_tool(lua, name)? else {
            return Ok(None);
        };
        let args_json: serde_json::Value = serde_json::from_str(arguments)
            .map_err(|e| format!("config: {name}: bad arguments JSON: {e}"))?;
        let args_lua = crate::mcp::json_to_lua(lua, &args_json)
            .map_err(|e| format!("config: {name}: arguments decode: {e}"))?;
        // Same marker `EventRun::start` sets: on this VM `agent.on_timeout` and
        // the sandbox pump suspend for the reactor instead of sleeping a thread.
        let agent: Table = lua
            .globals()
            .get("agent")
            .map_err(|e| format!("config: {name}: agent table: {e}"))?;
        agent
            .set("__on_reactor", true)
            .map_err(|e| format!("config: {name}: reactor marker: {e}"))?;
        let thread = lua
            .create_thread(call)
            .map_err(|e| format!("config: {name}: coroutine: {e}"))?;
        let mut run = ToolRun {
            lua,
            thread,
            name: name.to_string(),
        };
        let step = run
            .resume_with(Some(args_lua))
            .map_err(|e| format!("config: {name}: {e}"))?;
        Ok(Some((run, step)))
    }

    /// Answer the question from the last [`ToolStep::Ask`]. `verdict` is what
    /// `agent.api.ask_user` would have returned: `true`, `false`, or a denial
    /// table carrying a reason. It is delivered to the yield site, so the asking
    /// code resumes exactly as a plain `yes` would have.
    pub fn answer(&mut self, verdict: mlua::Value) -> Result<ToolStep, String> {
        self.resume_with(Some(verdict))
    }

    /// Resume a [`ToolStep::Waiting`] wait. Nothing lands at the yield site, so
    /// this takes no value.
    pub fn wait(&mut self) -> Result<ToolStep, String> {
        self.resume_with(None)
    }

    /// The VM the tool runs on — the agent's own config VM, borrowed for as
    /// long as the call lasts.
    pub fn lua(&self) -> &Lua {
        self.lua
    }

    /// The tool's name, for error messages.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// One resume: the first lands `arg` as the callback's argument, later ones
    /// at the value of the last `coroutine.yield`.
    fn resume_with(&mut self, arg: Option<mlua::Value>) -> Result<ToolStep, String> {
        let res: mlua::Value = self
            .thread
            .resume(arg)
            .map_err(|e| format!("config: {}: {e}", self.name))?;
        match self.thread.status() {
            mlua::thread::ThreadStatus::Resumable => decode_tool_ask(res),
            // Dead: the values are the callback's returns, and a tool returns
            // the one result value the MCP shape defines.
            _ => {
                let json = crate::mcp::lua_to_json( &res)
                    .map_err(|e| format!("config: {}: result encode: {e}", self.name))?;
                let text =
                    serde_json::to_string(&json).map_err(|e| format!("config: {}: {e}", self.name))?;
                Ok(ToolStep::Returned(text))
            }
        }
    }
}

/// Decode one yield from a tool coroutine. Two shapes are legal and they are
/// told apart by the await tag: `agent.on_timeout` and the sandbox's cadence
/// yield `{ __agent_await = "timeout", ms = ms }`, and an *ask* — which is
/// whatever `agent.ask`'s `raise_ask` yields, either a bare text or the ask
/// table `ask.for_syscall` builds (`description`, and `always` when there is a
/// path to remember). Anything else is a tool yielding for its own reasons,
/// which nothing can answer, so it is an error.
fn decode_tool_ask(yielded: mlua::Value) -> Result<ToolStep, String> {
    if let mlua::Value::Table(t) = &yielded {
        if let Ok(Some(tag)) = t.get::<Option<String>>("__agent_await") {
            return match tag.as_str() {
                "timeout" => {
                    let ms: i64 = t
                        .get("ms")
                        .map_err(|e| format!("tool: await timeout ms: {e}"))?;
                    Ok(ToolStep::Waiting {
                        ms: ms.max(0) as u64,
                    })
                }
                other => Err(format!("tool: unknown await request {other:?}")),
            };
        }
        // An ask table: `description` names the question, `always` says whether
        // the prompt may offer to remember it. Both are optional, because a
        // hand-built ask may carry neither.
        let text = match t.get::<mlua::Value>("description") {
            Ok(mlua::Value::String(s)) => s.to_string_lossy().to_string(),
            Ok(mlua::Value::Nil) | Err(_) => String::new(),
            Ok(other) => other
                .to_string()
                .map_err(|e| format!("tool: ask description: {e}"))?,
        };
        let always = matches!(t.get::<mlua::Value>("always"), Ok(mlua::Value::Boolean(true)));
        return Ok(ToolStep::Ask { text, always });
    }
    // A bare string is the other ask shape: the question, with nothing to
    // remember and so no `[a]lways` on offer.
    match yielded {
        mlua::Value::String(s) => Ok(ToolStep::Ask {
            text: s.to_string_lossy().to_string(),
            always: false,
        }),
        mlua::Value::Nil => Ok(ToolStep::Ask {
            text: String::new(),
            always: false,
        }),
        other => Err(format!(
            "tool yielded an unsupported value {} (only agent.ask and \
             agent.on_timeout yield inside a tool)",
            other.type_name()
        )),
    }
}

/// The callable a connection advertises under `name`, or `None` when the
/// registry holds no such tool. A tool object is a callable table: it carries a
/// `callback` function (what `agent.utils.tool` builds; `agent.mcp` produced ones
/// fall back to their `__call` metamethod, which routes through the connection).
/// The callable behind an advertised name, or `None` when the registry holds no
/// such tool.
///
/// The name is always `{connection}.{tool}` — see [`qualified_name`]. There is
/// deliberately no bare-name fallback: the advertisement qualifies, so accepting
/// an unqualified name here would be a way back to the collision the
/// qualification exists to prevent, and a name the model was never shown should
/// not resolve at all.
fn lookup_tool(lua: &Lua, name: &str) -> Result<Option<mlua::Function>, String> {
    let agent: Table = lua
        .globals()
        .get("agent")
        .map_err(|e| format!("config: agent table: {e}"))?;
    let mcps: Table = match agent.get("mcps") {
        Ok(t) => t,
        Err(_) => return Ok(None),
    };
    let Some((conn_name, tool_name)) = split_qualified(name) else {
        // Not a name this agent ever advertises. Refused rather than guessed at.
        return Ok(None);
    };
    let Ok(conn) = mcps.get::<Table>(conn_name) else {
        return Ok(None);
    };
    // A connection holds its tools in `conn.tools[name]`; `agent.mcp` also
    // mirrors the same tables as `conn[name]` for Lua callers. Either is a hit,
    // so a hand-built connection needs nothing but its `tools` table.
    let tool = match conn
        .get::<Table>("tools")
        .and_then(|tools| tools.get::<mlua::Value>(tool_name))
    {
        Ok(mlua::Value::Table(t)) => t,
        _ => match conn.get::<mlua::Value>(tool_name) {
            Ok(mlua::Value::Table(t)) => t,
            _ => return Ok(None),
        },
    };
    let call = match tool.get::<mlua::Function>("callback").ok() {
        Some(cb) => cb,
        None => {
            let mt = tool
                .metatable()
                .ok_or_else(|| format!("config: {name}: tool has no callback or __call"))?;
            mt.get("__call")
                .map_err(|e| format!("config: {name}: __call: {e}"))?
        }
    };
    Ok(Some(call))
}

/// Decode an `agent.on_timeout` yield from the reactor-driven coroutine: the
/// handler called `coroutine.yield({ __agent_await = "timeout", ms = ms })`
/// (see `agent.on_timeout` in driver.lua). Any other yielded value is an
/// error — user code must not yield directly inside an event handler.
fn decode_await(yielded: mlua::Value) -> Result<EventStep, String> {
    let mlua::Value::Table(t) = &yielded else {
        return Err(format!(
            "event handler: yielded an unsupported value {} (only \
             agent.on_timeout yields inside a handler)",
            yielded.type_name()
        ));
    };
    let tag: Option<String> = t
        .get("__agent_await")
        .map_err(|e| format!("event handler: await table: {e}"))?;
    match tag.as_deref() {
        Some("timeout") => {
            let ms: i64 = t
                .get("ms")
                .map_err(|e| format!("event handler: await timeout ms: {e}"))?;
            Ok(EventStep::Waiting {
                ms: ms.max(0) as u64,
            })
        }
        other => Err(format!("event handler: unknown await request {other:?}")),
    }
}

fn err_to_mlua(e: anyhow::Error) -> mlua::Error {
    mlua::Error::RuntimeError(format!("{e:#}"))
}

/// `agent.trigger(...) -> boolean` — force the agent loop to run a new
/// inference. With no argument: a continuation of the current conversation.
/// With a string: the text behaves like a submitted user message. With an
/// array of message tables: the array **replaces** the loop's in-memory
/// history (the write side of compaction) before the turn runs — usually a
/// summary message + the recent tail, exactly the "compacted history" a
/// `turn_completed` handler computed from the event payload.
///
/// The command is queued on the loop's trigger channel (see
/// [`AgentCommand`]) and the loop starts it at the next idle moment. Returns
/// `true` when queued; `false` when no loop is bound to the channel (the
/// headless probe, tests) so Lua can decide what that means.
/// `agent.api.input_insert(text)` / `input_backspace()` / `input_clear()` — change
/// the input line from Lua.
///
/// The route that makes the `key` event more than a picker. A handler that could
/// only *name* an action had a closed vocabulary baked into Rust, so "insert a
/// newline" had to be an action whether or not anyone wanted it, and nothing else
/// could ever type into the box on demand. With this, a binding can do whatever
/// Lua can do to the line, and the shipped table is free to stop treating
/// `newline` as special.
///
/// Returns `true` when queued and `false` when no loop is attached — the same
/// contract as [`agent.trigger`](crate::lua), and for the same reason: a binding
/// that silently dropped its own edit would look like a key that does nothing.
///
/// Ungated, unlike a key *binding*: the letter rule ("a bare letter is a
/// character first") governs which key may mean a command, and this is already
/// inside a command. So a chord bound to `input_insert("0")` inserts a `0`
/// mid-sentence, which is what a leader key is for.
fn lua_input_op(op: InputOp) -> mlua::Result<bool> {
    match TRIGGER_TX.get() {
        Some(tx) => tx
            .send(AgentCommand::Input(op))
            .map_err(|_| mlua::Error::RuntimeError("agent.api.input_*: the agent loop is gone".into()))
            .map(|_| true),
        None => Ok(false),
    }
}

fn lua_trigger(_: &Lua, args: mlua::MultiValue) -> mlua::Result<bool> {
    let cmd = match args.into_iter().next() {
        None => AgentCommand::RunTurn {
            history: None,
            user: None,
        },
        Some(mlua::Value::String(s)) => AgentCommand::RunTurn {
            history: None,
            user: Some(s.to_str()?.to_string()),
        },
        Some(mlua::Value::Table(t)) => {
            let json = crate::mcp::lua_to_json( &mlua::Value::Table(t)).map_err(|e| {
                mlua::Error::RuntimeError(format!("agent.trigger: history decode: {e}"))
            })?;
            match json {
                // The history replacement must be an array of messages.
                serde_json::Value::Array(items) => AgentCommand::RunTurn {
                    history: Some(items),
                    user: None,
                },
                other => {
                    return Err(mlua::Error::RuntimeError(format!(
                        "agent.trigger: expected an array of messages, got {}",
                        json_kind(&other)
                    )));
                }
            }
        }
        Some(v) => {
            return Err(mlua::Error::RuntimeError(format!(
                "agent.trigger: expected nothing, a string, or an array of messages, got {}",
                v.type_name()
            )));
        }
    };
    match TRIGGER_TX.get() {
        Some(tx) => tx
            .send(cmd)
            .map_err(|_| mlua::Error::RuntimeError("agent.trigger: the agent loop is gone".into()))
            .map(|_| true),
        None => Ok(false),
    }
}

/// `agent.api.ask_user(text, always)`: put a question to the user and wait for
/// the verdict. This is the *tool-side* half of the ask protocol — a registered
/// `agent.mcps` tool whose callback drives a sandbox (the shipped `bash`) needs
/// its policy's asks answered by whoever is running the tool. It is not a
/// blocking call: the tool yields, which hands the question to the event loop
/// and parks the tracee's syscall frozen, and the loop resumes the same
/// coroutine with the answer once you have given one.
///
/// Returns the value the ask protocol accepts ([`AskAnswer`] mapped to the
/// wire shape `agent.ask` normalizes): `true` to allow the frozen syscall run,
/// `false` to deny it with no reason, or a deny verdict carrying the reason the
/// user-side handler gave. With no handler bound — headless runs, tests, the
/// probe — it auto-denies with a bare `false`, so an asking policy always
/// terminates instead of waiting on a user who cannot answer.
///
/// The Lua-side entry point is `agent.ask` (yield-based, for policies driven
/// from the event loop) and `agent.api.ask_user` (this one, for tools); a tool
/// callback wires the two with `stream:run(function(a) … end)`, which is what
/// `lua/bash_tool.lua` does.
fn lua_ask_user(
    on_ask: Option<AskHandler>,
) -> impl Fn(&Lua, (String, Option<bool>)) -> mlua::Result<mlua::Value> {
    move |lua: &Lua, (text, always): (String, Option<bool>)| match &on_ask {
        // Headless: nobody to ask, so the ask denies and the run stays
        // read-only. An "always" nobody can give is not an allow.
        None => Ok(mlua::Value::Boolean(false)),
        Some(ask) => Ok(match ask(&text, always.unwrap_or(false)) {
            AskAnswer::Allow => mlua::Value::Boolean(true),
            AskAnswer::AllowAndTrust => {
                // A table, because the flag has to travel with the answer: the
                // asking side (which knows the path) is the one that acts on it.
                let t = lua.create_table()?;
                t.set("__agent_verdict", "allow")?;
                t.set("trust", true)?;
                mlua::Value::Table(t)
            }
            AskAnswer::Deny(None) => mlua::Value::Boolean(false),
            AskAnswer::Deny(Some(reason)) => {
                let t = lua.create_table()?;
                t.set("__agent_verdict", "deny")?;
                t.set("reason", reason)?;
                mlua::Value::Table(t)
            }
        }),
    }
}

/// The Lua-facing name of a JSON value, for the `agent.trigger` argument error.
fn json_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

// ---------------------------------------------------------------------------
// Conversation log (`agent.memory`): the save-to-disk side of the agent.
// One `crate::memory::Memory` is opened by the TUI (or probe) at startup and
// shared behind a process-wide mutex; the loop archives every history message
// through [`memory_append_many`] (a watermark — each message exactly once),
// flushes at turn boundaries and on exit, and Lua reaches the same store via
// the `agent.memory` primitives in `lua/init.lua`.
// ---------------------------------------------------------------------------

/// The shared conversation log: the loop writes it, Lua reads/writes it
/// through `agent.memory`. Bound once at startup by the TUI
/// ([`bind_memory`]) — the path and on/off switch come from
/// `agent.llm.memory` — and shared behind a mutex, because the loop and the
/// tool/event coroutines it drives reach it from both sides. Unbound (tests, or
/// `enabled = false`): the loop's archive is a no-op and `agent.memory.append` /
/// `latest` / `flush` raise "no log open".
static MEMORY: OnceLock<Arc<Mutex<Memory>>> = OnceLock::new();

/// Bind the process-wide conversation log (see `MEMORY`). Returns `None`
/// when already bound. Like the trigger channel, this is a startup decision:
/// `/reload` re-reads the user config but cannot rebind the store.
pub fn bind_memory(mem: Arc<Mutex<Memory>>) -> Option<()> {
    MEMORY.set(mem).ok()
}

/// Whether a conversation log is open. The loop checks this before archiving,
/// so a disabled store costs nothing and logs nothing.
pub fn memory_is_bound() -> bool {
    MEMORY.get().is_some()
}

/// The `agent.llm.memory` settings: whether the conversation log is open at
/// all and where it lives. Defaults: enabled, `~/.config/agent/history.amem`
/// (else `./history.amem` when HOME is unset).
#[derive(Debug, Clone)]
pub struct MemoryConfig {
    /// `false` (`agent.llm.memory.enabled = false`): no log opens, the
    /// loop archives nothing, `agent.memory` actions raise "no log open".
    pub enabled: bool,
    /// Where the append-only log lives (`agent.llm.memory.path`).
    pub path: PathBuf,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        MemoryConfig {
            enabled: true,
            path: default_memory_path(),
        }
    }
}

fn default_memory_path() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) => Path::new(&home)
            .join(".config")
            .join("agent")
            .join("history.amem"),
        None => PathBuf::from("history.amem"),
    }
}

/// Read `agent.llm.memory` from the config VM (fields absent -> defaults).
pub fn memory_config(lua: &Lua) -> Result<MemoryConfig, String> {
    let agent: Table = lua
        .globals()
        .get("agent")
        .map_err(|e| format!("memory config: agent table: {e}"))?;
    let config: Table = agent
        .get("llm")
        .map_err(|e| format!("memory config: agent.llm: {e}"))?;
    let mut cfg = MemoryConfig::default();
    let Ok(t) = config.get::<Table>("memory") else {
        return Ok(cfg); // not configured: defaults
    };
    if let Some(enabled) =
        opts_bool(&t, "enabled").map_err(|e| format!("memory config: enabled: {e}"))?
    {
        cfg.enabled = enabled;
    }
    if let Ok(p) = t.get::<String>("path") {
        cfg.path = PathBuf::from(p);
    }
    Ok(cfg)
}

/// The on-disk location of the open log, when one is bound.
pub fn memory_path() -> Option<PathBuf> {
    MEMORY
        .get()
        .map(|m| m.lock().map(|g| g.path().to_path_buf()).unwrap_or_default())
}

/// Append one JSON message (a string) to the conversation log; returns the
/// message's sequence number. Raises when no log is open or the append fails.
pub fn memory_append(json: &str) -> Result<u64, String> {
    let mut mem = MEMORY
        .get()
        .ok_or_else(|| "agent.memory: no log open (agent.llm.memory?)".to_string())?
        .lock()
        .map_err(|_| "agent.memory: log mutex poisoned".to_string())?;
    mem.append(json)
        .map_err(|e| format!("agent.memory: append: {e}"))
}

/// Append several history messages in one lock — the loop's watermark
/// archive. The values are already JSON (they came from the history), so this
/// is a pure serialize-and-append. Returns the last appended sequence.
pub fn memory_append_many(messages: &[serde_json::Value]) -> Result<u64, String> {
    let mut mem = MEMORY
        .get()
        .ok_or_else(|| "agent.memory: no log open (agent.llm.memory?)".to_string())?
        .lock()
        .map_err(|_| "agent.memory: log mutex poisoned".to_string())?;
    let mut seq = 0;
    for m in messages {
        let text = serde_json::to_string(m).map_err(|e| format!("agent.memory: encode: {e}"))?;
        seq = mem
            .append(&text)
            .map_err(|e| format!("agent.memory: append: {e}"))?;
    }
    Ok(seq)
}

/// The newest `n` messages as JSON lines (oldest → newest).
pub fn memory_latest(n: usize) -> Result<Vec<String>, String> {
    let mut mem = MEMORY
        .get()
        .ok_or_else(|| "agent.memory: no log open (agent.llm.memory?)".to_string())?
        .lock()
        .map_err(|_| "agent.memory: log mutex poisoned".to_string())?;
    mem.latest(n)
        .map_err(|e| format!("agent.memory: latest: {e}"))
}

/// Seal buffered messages into the on-disk log now (group commit). With no
/// open log this is a no-op (`Ok(())`), so exit paths need not branch.
pub fn memory_flush() -> Result<(), String> {
    let Some(mem) = MEMORY.get() else {
        return Ok(());
    };
    let mut mem = mem
        .lock()
        .map_err(|_| "agent.memory: log mutex poisoned".to_string())?;
    mem.flush().map_err(|e| format!("agent.memory: flush: {e}"))
}

/// `agent.api.memory_path() -> string | nil` — the open log's location; `nil`
/// when none is open (disabled or unbound). Informational, so it returns nil
/// rather than raising like the actions do.
fn lua_memory_path(_: &Lua, (): ()) -> mlua::Result<Option<String>> {
    Ok(memory_path().map(|p| p.display().to_string()))
}

/// `agent.api.memory_append(message) -> seq` — `message` is a JSON string or a
/// table (encoded automatically, so history messages round-trip as written).
fn lua_memory_append(_: &Lua, msg: mlua::Value) -> mlua::Result<u64> {
    let text = match msg {
        mlua::Value::String(s) => s.to_str()?.to_string(),
        other => {
            let json = crate::mcp::lua_to_json( &other).map_err(|e| {
                mlua::Error::RuntimeError(format!("agent.memory.append: encode: {e}"))
            })?;
            serde_json::to_string(&json).map_err(|e| {
                mlua::Error::RuntimeError(format!("agent.memory.append: encode: {e}"))
            })?
        }
    };
    memory_append(&text).map_err(mlua::Error::RuntimeError)
}

/// `agent.api.memory_latest(n) -> array` — the newest `n` messages, JSON strings.
fn lua_memory_latest(lua: &Lua, n: usize) -> mlua::Result<Table> {
    let msgs = memory_latest(n).map_err(mlua::Error::RuntimeError)?;
    let t = lua.create_table()?;
    for (i, m) in msgs.iter().enumerate() {
        t.set(i + 1, m.clone())?;
    }
    Ok(t)
}

/// `agent.api.memory_flush() -> true` — seal buffered messages to disk now.
fn lua_memory_flush(_: &Lua, (): ()) -> mlua::Result<bool> {
    memory_flush().map_err(mlua::Error::RuntimeError)?;
    Ok(true)
}

// ---------------------------------------------------------------------------
// Rust primitives called from Lua (never yield — see module docs)
// ---------------------------------------------------------------------------

/// `agent.api.spawn(cmdline, mask?) -> handle`.
///
/// Every *masked* syscall surfaces as a frozen [`Step::Blocked`] — the
/// decider always returns `Ask` — so decisions land entirely in Lua policy.
///
/// `mask` is the list of syscall names whose syscalls the filter traps:
/// anything not listed is not intercepted at all and runs straight through
/// the kernel under its default (allow). The engine always additionally
/// traps the fork family and auto-allows those it did not name (pid
/// bookkeeping). `nil`/absent = an **empty** mask — nothing is intercepted
/// except the engine's always-on fork family, which runs free: a raw
/// `agent.api.spawn(cmdline)` driver observes a plain run, not an ask loop.
/// An unknown name is a runtime error, so a policy typo cannot silently
/// trace nothing.
fn lua_spawn(
    _: &Lua,
    (cmdline, mask): (String, Option<Vec<String>>),
) -> mlua::Result<SandboxHandle> {
    let mut nrs: Vec<i32> = Vec::new();
    if let Some(names) = mask {
        nrs.reserve(names.len());
        for name in names {
            let Some(nr) = seccomp::syscall_nr(&name) else {
                return Err(mlua::Error::RuntimeError(format!(
                    "agent.api.spawn: unknown syscall name in mask: {name:?}"
                )));
            };
            nrs.push(nr);
        }
    }
    let sb = seccomp::Sandbox::spawn("bash", &["-c", &cmdline], |_| Verdict::Ask, &nrs);
    let sb = sb.map_err(err_to_mlua)?;
    Ok(SandboxHandle(Rc::new(RefCell::new(sb))))
}

/// `agent.api.step(handle) -> step table` — one poll round + one non-blocking
/// engine step (mirrors `Sandbox::pump`'s poll loop, stopping at `Blocked`).
///
/// The poll is non-blocking (timeout 0) on a reactor-driven VM — an event
/// handler, where a blocking poll would freeze the loop; the pump suspends
/// between idle steps instead. Plain VMs keep the blocking poll.
///
/// Returns `{kind="blocked", syscall={..}}` (the asking thread is parked in
/// the kernel's notification wait), `{kind="output", stream, data}`,
/// `{kind="idle"}` (poll timed out; caller just loops), or
/// `{kind="finished", result={..}}`.
fn lua_step(lua: &Lua, handle: AnyUserData) -> mlua::Result<Table> {
    let h = handle.borrow::<SandboxHandle>()?;
    let mut sb = h.0.borrow_mut();
    let slots = sb.poll_slots();
    if slots.is_empty() {
        // Nothing left to wait on: only the completion path remains.
        return match sb.step(0).map_err(err_to_mlua)? {
            Step::Finished(r) => finished_table(lua, r),
            other => Err(mlua::Error::RuntimeError(format!(
                "agent.api.step: tree gone but step returned {other:?}"
            ))),
        };
    }
    let mut pfds: Vec<libc::pollfd> = slots.iter().map(|(_, p)| *p).collect();
    // On a reactor-driven VM (an event handler, see [`EventRun`]) every step
    // must stay non-blocking: the pump's `drive` yields a cooperative cadence
    // between idle steps, so a poll(0) keeps each slice microsecond-sized and
    // the event loop live. Tool threads and headless runs keep the blocking
    // poll — there the poll *is* the wait.
    let timeout = if lua
        .globals()
        .get::<Table>("agent")
        .and_then(|a| a.get::<bool>("__on_reactor"))
        .unwrap_or(false)
    {
        0
    } else {
        seccomp::DEFAULT_POLL_TIMEOUT_MS
    };
    let pr = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, timeout) };
    if pr == -1 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EINTR) {
            return idle_table(lua);
        }
        return Err(mlua::Error::RuntimeError(format!("agent.api.step: poll: {e}")));
    }
    if pr == 0 {
        return idle_table(lua);
    }
    let mut listener_revents = 0i16;
    for (k, p) in pfds.iter().enumerate() {
        if p.revents != 0 && slots[k].0 == FdSlot::Listener {
            listener_revents = p.revents;
        }
    }
    let step_res = sb.step(listener_revents).map_err(err_to_mlua)?;
    match step_res {
        Step::Blocked { syscall, .. } => {
            // Freeze every tree process *except* the asker before the string
            // deref + path resolution below: with the siblings SIGSTOP'd,
            // nothing can rewrite a symlink or the tracee's memory between
            // the policy's check and the kernel's own resolution of the
            // syscall — the TOCTOU gate. The asker is deliberately left to
            // the kernel's own park (a full-tree freeze would interrupt its
            // notification wait, discard the notification, and re-ask
            // forever). Thaw happens in `agent.api.decide` →
            // `Sandbox::resolve_ask_frozen`, once the allowed syscall has
            // executed; a raw `_step` consumer that never decides is released
            // by the resume() at the top of the next blocked step.
            sb.resume();
            sb.freeze_others(syscall.pid);
            let t = lua.create_table()?;
            t.set("kind", "blocked")?;
            t.set("syscall", syscall_into_table(lua, &syscall)?)?;
            Ok(t)
        }
        Step::Event(CoroutineEvent::Output { stream, data }) => {
            let t = lua.create_table()?;
            t.set("kind", "output")?;
            t.set(
                "stream",
                match stream {
                    seccomp::Stream::Stdout => "stdout",
                    seccomp::Stream::Stderr => "stderr",
                },
            )?;
            t.set("data", lua.create_string(&data)?)?;
            Ok(t)
        }
        // A decided syscall is only emitted for direct Allow/Deny decider
        // verdicts; the always-Ask decider never produces one.
        Step::Event(CoroutineEvent::Decided { .. }) => idle_table(lua),
        Step::Idle => idle_table(lua),
        Step::Finished(r) => finished_table(lua, r),
    }
}

/// `agent.api.decide(handle, verdict)` — resolve the pending syscall ask.
/// `true` → Allow (CONTINUE), `false` → Deny (final: tree is SIGKILLed).
fn lua_decide(_: &Lua, (handle, verdict): (AnyUserData, bool)) -> mlua::Result<()> {
    let h = handle.borrow::<SandboxHandle>()?;
    let mut sb = h.0.borrow_mut();
    // The tree is frozen from `lua_step`'s Blocked arm (siblings SIGSTOP'd,
    // asker parked on its notification). `resolve_ask_frozen` answers the
    // ask and — for an Allow — holds the siblings until the allowed syscall
    // has executed before thawing, so the filesystem the policy resolved
    // against is still the one the kernel resolves. A Deny SIGKILLs the whole
    // tree inside resolve_ask; nothing is thawed.
    let verdict = if verdict {
        Verdict::Allow
    } else {
        Verdict::Deny(libc::EPERM)
    };
    sb.resolve_ask_frozen(verdict).map_err(err_to_mlua)?;
    Ok(())
}

/// `agent.api.kill(handle)` — SIGKILL the whole tree (idempotent; used for
/// interrupt/cancel and by the Lua driver's error paths).
fn lua_kill(_: &Lua, handle: AnyUserData) -> mlua::Result<()> {
    let h = handle.borrow::<SandboxHandle>()?;
    h.0.borrow_mut().kill_tree();
    Ok(())
}

/// `agent.api.write(handle, data)` — feed bytes to the tracee's stdin pipe.
/// Non-blocking: what the pipe can take is written immediately, the rest is
/// queued and flushed by the engine once it reports `POLLOUT`; input after
/// EOF is dropped (see `Sandbox::queue_stdin`).
fn lua_write_stdin(_: &Lua, (handle, data): (AnyUserData, mlua::LuaString)) -> mlua::Result<()> {
    let h = handle.borrow::<SandboxHandle>()?;
    let bytes = data.as_bytes();
    h.0.borrow_mut().queue_stdin(&bytes).map_err(err_to_mlua)
}

/// `agent.api.close_stdin(handle)` — close the tracee's stdin write end; its next
/// `read(0)` sees EOF once all copies are gone.
fn lua_close_stdin(_: &Lua, handle: AnyUserData) -> mlua::Result<()> {
    let h = handle.borrow::<SandboxHandle>()?;
    h.0.borrow_mut().close_stdin();
    Ok(())
}

// ---------------------------------------------------------------------------
// Lua value helpers
// ---------------------------------------------------------------------------

fn idle_table(lua: &Lua) -> mlua::Result<Table> {
    let t = lua.create_table()?;
    t.set("kind", "idle")?;
    Ok(t)
}

/// The caller's `/proc/<pid>/cmdline` — NUL-separated argv joined with spaces
/// (the `ps`-style view), `""` when it can't be read (process exited, or not
/// ours). Resolved fresh per call, no caching: syscall tables die with the
/// run and the read is microsecond-scale, which is what lets the policy
/// callback — and the ask it raises — name *who* is asking.
fn proc_cmdline(pid: i32) -> String {
    let raw = match std::fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(b) => b,
        Err(_) => return String::new(),
    };
    let mut args = Vec::new();
    for part in raw.split(|b| *b == 0) {
        if !part.is_empty() {
            args.push(String::from_utf8_lossy(part).into_owned());
        }
    }
    args.join(" ")
}

/// The intercepted syscall, as the policy callback receives it: `{name, nr,
/// pid, cmdline, args, str, addr}`. `cmdline` is the caller's
/// `/proc/<pid>/cmdline` (argv joined with spaces; `""` when unreadable) —
/// the callback's window into *who* is making the request. `str` holds the
/// C-string args (pathnames) read from the caller's memory, 1-based and
/// aligned with `args` — the window into *what file* is being touched. Each
/// one is resolved to the actual path as far as the filesystem allows (see
/// [`resolve_path`]) — which is what file-based ask-and-remember decides on.
fn syscall_into_table(lua: &Lua, s: &seccomp::Syscall) -> mlua::Result<Table> {
    let t = lua.create_table()?;
    let name = s.name();
    t.set("name", name.as_str())?;
    t.set("nr", s.nr as i64)?;
    t.set("pid", s.pid as i64)?;
    t.set("cmdline", proc_cmdline(s.pid))?;
    let args = lua.create_table()?;
    // u64 -> f64 is lossy for pointer-sized args; documented in module docs.
    for (i, arg) in s.args.iter().enumerate() {
        args.raw_set((i as i64) + 1, *arg as f64)?;
    }
    t.set("args", args)?;
    // `sys.addr`: the endpoint each naming syscall wants, decoded out of the
    // caller's memory (see `read_sockaddr`). 1-based, aligned with `args`.
    let addrs = lua.create_table()?;
    if let Some(positions) = sockaddr_positions(&name) {
        for &p in positions {
            // The sockaddr's own length is the next argument: `connect(fd, addr,
            // addrlen)`. Read it when the syscall has one, and fall back to the
            // family's own size when it does not (so a bogus 0 cannot shrink the
            // read below the family header).
            let len = s.args.get(p + 1).copied().unwrap_or(28);
            if let Some(t) = endpoint_into_lua(lua, s.pid, s.args[p], len)? {
                addrs.raw_set((p as i64) + 1, t)?;
            }
        }
    }
    t.set("addr", addrs)?;
    let strs = lua.create_table()?;
    if let Some(positions) = cstring_positions(&name) {
        let cwd = tracee_cwd(s.pid);
        for &p in positions {
            if let Some(text) = read_cstr(s.pid, s.args[p], CSTRING_CAP) {
                let text = if cwd_resolution_ok(&name, p, s.args) {
                    resolve_path(cwd.as_deref(), &text)
                } else {
                    // Relative to a caller-held dirfd we cannot see: the name
                    // passes through unresolved rather than mis-resolved.
                    text
                };
                strs.raw_set((p as i64) + 1, text)?;
            }
        }
    }
    t.set("str", strs)?;
    Ok(t)
}

/// Max bytes to dereference per C-string syscall arg (PATH_MAX is 4096).
const CSTRING_CAP: usize = 4096;

/// The syscalls whose arguments are C strings, and which 0-based `args`
/// positions hold them — the `sys.str` dereference map. Only positions that
/// are *input* strings are listed (never `getcwd`'s out-buffer, never fd
/// slots). Positions are 1-based in Lua, aligned with `args`.
const CSTRING_ARGS: &[(&str, &[usize])] = &[
    ("execve", &[0]),
    ("execveat", &[1]),
    ("open", &[0]),
    ("creat", &[0]),
    ("openat", &[1]),
    ("openat2", &[1]),
    ("stat", &[0]),
    ("lstat", &[0]),
    ("newfstatat", &[1]),
    ("access", &[0]),
    ("faccessat", &[1]),
    ("readlink", &[0]),
    ("readlinkat", &[1]),
    ("unlink", &[0]),
    ("unlinkat", &[1]),
    ("rmdir", &[0]),
    ("mkdir", &[0]),
    ("mkdirat", &[1]),
    ("rename", &[0, 1]),
    // renameat(olddirfd, oldpath, newdirfd, newpath): the strings are 1 and 3.
    // Slot 2 is *newdirfd* — a small integer, not a pointer — and reading it as
    // a C string is how the second path came back nil for every rename, which
    // is why nothing had ever asked about one.
    ("renameat", &[1, 3]),
    ("renameat2", &[1, 3]),
    ("chdir", &[0]),
    ("chroot", &[0]),
    ("chmod", &[0]),
    ("fchmodat", &[1]),
    ("chown", &[0]),
    ("fchownat", &[1]),
    ("lchown", &[0]),
    ("truncate", &[0]),
    ("statfs", &[0]),
    ("link", &[0, 1]),
    // linkat(olddirfd, oldpath, newdirfd, newpath, flags): the same shape.
    ("linkat", &[1, 3]),
    ("symlink", &[0, 1]),
    // symlinkat(target, newdirfd, linkpath): the strings are 0 and 2.
    ("symlinkat", &[0, 2]),
    ("mount", &[0, 1, 2, 3]),
    ("umount2", &[0]),
    ("utime", &[0]),
    ("utimensat", &[1]),
    ("getxattr", &[0, 1]),
    ("lgetxattr", &[0, 1]),
    ("setxattr", &[0, 1]),
    ("lsetxattr", &[0, 1]),
    // removexattr(path, name): the name is a string argument too, and without
    // it a policy gating the call cannot say *which* attribute was removed —
    // which is the whole difference between `setcap -r` and an app tidying up
    // its own `user.*` metadata.
    ("removexattr", &[0, 1]),
    ("lremovexattr", &[0, 1]),
    ("inotify_add_watch", &[1]),
    ("name_to_handle_at", &[1]),
];

/// The `sys.addr` positions for a syscall name: the `struct sockaddr *` each one
/// takes, 0-based, mirroring [`CSTRING_ARGS`].
///
/// These are the calls that *name an endpoint* in a way a policy can read and
/// ask about — `connect` (the target it wants to reach) and `bind` (the address
/// it wants to listen on). `sendto` is the same shape and belongs here too; it
/// is listed so a policy that cares about UDP egress only has to name it.
const SOCKADDR_ARGS: &[(&str, &[usize])] = &[
    ("connect", &[1]),
    ("bind", &[1]),
    ("sendto", &[1]),
];

/// The `sys.addr` positions for a syscall name (`None` = it names no address).
fn sockaddr_positions(name: &str) -> Option<&'static [usize]> {
    SOCKADDR_ARGS
        .iter()
        .find(|&&(n, _)| n == name)
        .map(|&(_, p)| p)
}

/// A named endpoint, read out of a `struct sockaddr` in the caller's memory.
///
/// `sockaddr` is *binary*, not a C string, so [`read_cstr`] cannot be used on it
/// (it would stop at the first zero byte — which for an IPv4 address is usually
/// byte one). This reads the fixed-size header instead: the family, then the
/// family-specific body, and renders an address the policy (and the user) can
/// read. `port` is `nil` for a family with no port.
struct Endpoint {
    family: &'static str,
    ip: Option<String>,
    port: Option<u16>,
    /// `AF_UNIX` has a NUL-terminated path where an address would be.
    path: Option<String>,
}

/// Read one `struct sockaddr` at `addr` in the caller's address space. The target
/// thread is frozen on the notification wait, so the bytes are stable while we
/// read; the same attach-permission a same-uid child grants covers this, and an
/// unreadable address is `None` rather than an error — a policy can then ask
/// about a call it cannot describe instead of waving it through.
fn read_sockaddr(pid: i32, addr: u64, len: u64) -> Option<Endpoint> {
    if addr == 0 {
        return None;
    }
    // The family is the first 2 bytes; the rest is family-specific. Read the
    // largest body any family we handle needs (AF_INET6), bounded by the
    // caller's own `len` so a short buffer is not over-read.
    let want = len.clamp(2, 28) as usize;
    let mut buf = vec![0u8; want];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: want,
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: want,
    };
    // SAFETY: `buf` is valid for `want` bytes; `addr` is a best-effort userland
    // pointer into the frozen target, which the kernel validates.
    let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if n < 2 {
        return None;
    }
    let family = u16::from_ne_bytes([buf[0], buf[1]]);
    match family {
        // AF_INET: sa_data[0..2] is sin_port (big-endian), [2..6] is sin_addr.
        2 if buf.len() >= 8 => Some(Endpoint {
            family: "inet",
            ip: Some(format!(
                "{}.{}.{}.{}",
                buf[4], buf[5], buf[6], buf[7]
            )),
            port: Some(u16::from_be_bytes([buf[2], buf[3]])),
            path: None,
        }),
        // AF_INET6: sin6_port then a 16-byte address plus a scope id.
        10 if buf.len() >= 24 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[4..20]);
            let scope = u32::from_ne_bytes([buf[20], buf[21], buf[22], buf[23]]);
            Some(Endpoint {
                family: "inet6",
                ip: Some(render_ipv6(&octets, scope)),
                port: Some(u16::from_be_bytes([buf[2], buf[3]])),
                path: None,
            })
        }
        // AF_UNIX: a NUL-terminated path in the same place an address would be.
        1 => {
            let body = &buf[2..];
            let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
            Some(Endpoint {
                family: "unix",
                ip: None,
                port: None,
                path: Some(String::from_utf8_lossy(&body[..end]).into_owned()),
            })
        }
        // A family we do not decode: report the number rather than guessing.
        other => Some(Endpoint {
            family: "other",
            ip: None,
            port: None,
            path: Some(format!("af{}", other)),
        }),
    }
}

/// An IPv6 address in the canonical form, with a zone suffix when the caller set
/// a scope (a link-local address is ambiguous without it).
fn render_ipv6(octets: &[u8; 16], scope: u32) -> String {
    let mut out = String::with_capacity(45);
    for (i, pair) in octets.chunks(2).enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{:x}", u16::from_be_bytes([pair[0], pair[1]])));
    }
    if scope != 0 {
        out.push_str(&format!("%{scope}"));
    }
    out
}

/// The endpoint `sys.addr` carries, as the policy callback receives it:
/// `{ family = "inet"|"inet6"|"unix"|"other", ip = string|nil, port = number|nil,
/// path = string|nil }` — and nothing at all (`nil`) when the syscall names no
/// address or the address could not be read.
fn endpoint_into_lua(lua: &Lua, pid: i32, ptr: u64, len: u64) -> mlua::Result<Option<Table>> {
    let Some(e) = read_sockaddr(pid, ptr, len) else {
        return Ok(None);
    };
    let t = lua.create_table()?;
    t.set("family", e.family)?;
    if let Some(ip) = e.ip {
        t.set("ip", ip)?;
    }
    if let Some(port) = e.port {
        t.set("port", port as i64)?;
    }
    if let Some(path) = e.path {
        t.set("path", path)?;
    }
    Ok(Some(t))
}

/// `sys.addr` positions for a syscall name (`None` = it names no address).
/// The `sys.str` positions for a syscall name (`None` = no C-string args).
fn cstring_positions(name: &str) -> Option<&'static [usize]> {
    CSTRING_ARGS
        .iter()
        .find(|&&(n, _)| n == name)
        .map(|&(_, p)| p)
}

/// Dereference a NUL-terminated C string from the caller's address space —
/// the read side of `sys.str`. `addr` is the raw pointer value the sandbox
/// saw as the syscall arg; the target thread is frozen in the kernel on the
/// notification wait, so the string is stable while we read. `process_vm_readv`
/// needs attach-permission to that pid, which a same-uid child grants; a
/// failed read (process gone, bogus pointer, partial page) yields `None` — an
/// unreadable string never errors the policy, it just arrives as `nil`.
fn read_cstr(pid: i32, addr: u64, cap: usize) -> Option<String> {
    if addr == 0 {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(cap.min(4096));
    let mut cur = addr;
    while out.len() < cap {
        let want = (cap - out.len()).min(4096);
        let mut buf = vec![0u8; want];
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: want,
        };
        let remote = libc::iovec {
            iov_base: cur as *mut libc::c_void,
            iov_len: want,
        };
        // SAFETY: `buf` is valid for `want` bytes; `cur` is a best-effort
        // userland pointer into the frozen target; the kernel validates it.
        let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        if n < 0 {
            return None;
        }
        let n = n as usize;
        if n == 0 {
            return None;
        }
        if let Some(z) = buf[..n].iter().position(|&b| b == 0) {
            out.extend_from_slice(&buf[..z]);
            break;
        }
        out.extend_from_slice(&buf[..n]);
        cur += n as u64;
    }
    if out.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

/// The tracee's working directory at interception time, via
/// `/proc/<pid>/cwd`. The target thread is frozen in the kernel on the
/// notification wait, so its cwd is stable while we read. `None` when
/// unreadable — relative pathnames then fall back to the supervisor's own
/// cwd, or pass through unresolved.
fn tracee_cwd(pid: i32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/cwd")).ok()
}

/// The `args` slot holding the *directory fd* each path argument of a syscall
/// resolves against, as `(path slot, dirfd slot)` pairs, 0-based — the dirfd
/// family: the syscalls whose relative pathnames resolve against a
/// caller-supplied fd instead of the cwd (`openat`, `newfstatat`, `renameat`,
/// `execveat`, ...).
///
/// **Per path, not per syscall.** The two-path `*at` calls have *two* dirfds,
/// and one slot for the syscall resolves a rename's target against the
/// *source's* directory — which is a wrong answer rather than a missing one, and
/// the kind that only shows up once a command bothers to open a directory and
/// rename into it.
///
/// A path with no pair here is cwd-relative and resolves as one. `symlinkat`
/// relies on that: its target (slot 0) is cwd-relative, while its linkpath
/// (slot 2) sits behind the fd in slot 1.
const DIRFD_FOR_PATH: &[(&str, &[(usize, usize)])] = &[
    ("execveat", &[(1, 0)]),
    ("openat", &[(1, 0)]),
    ("openat2", &[(1, 0)]),
    ("newfstatat", &[(1, 0)]),
    ("faccessat", &[(1, 0)]),
    ("readlinkat", &[(1, 0)]),
    ("unlinkat", &[(1, 0)]),
    ("mkdirat", &[(1, 0)]),
    ("renameat", &[(1, 0), (3, 2)]),
    ("renameat2", &[(1, 0), (3, 2)]),
    ("linkat", &[(1, 0), (3, 2)]),
    ("symlinkat", &[(2, 1)]),
    ("utimensat", &[(1, 0)]),
    ("fchmodat", &[(1, 0)]),
    ("fchownat", &[(1, 0)]),
    ("inotify_add_watch", &[(1, 0)]),
    ("name_to_handle_at", &[(1, 0)]),
];

/// The dirfd slot one path argument of `sys_name` resolves against, or `None`
/// when that path is relative to the cwd.
fn dirfd_slot_for(sys_name: &str, path_slot: usize) -> Option<usize> {
    DIRFD_FOR_PATH
        .iter()
        .find(|&&(n, _)| n == sys_name)
        .and_then(|&(_, pairs)| {
            pairs
                .iter()
                .find(|&&(p, _)| p == path_slot)
                .map(|&(_, fd)| fd)
        })
}

/// Whether a relative pathname at arg position `p` may be resolved against the
/// tracee's cwd. Absolute names are context-independent and always resolve.
/// The dirfd family above resolves relative names against an fd slot instead —
/// only `AT_FDCWD` means "the cwd", so anything else passes the name through
/// rather than mis-resolving it against the wrong directory.
fn cwd_resolution_ok(sys_name: &str, p: usize, args: [u64; 6]) -> bool {
    match dirfd_slot_for(sys_name, p) {
        None => true,                                // plain pathname syscall
        Some(f) => args[f] == libc::AT_FDCWD as u64, // the fd slot says "cwd"?
    }
}

/// Resolve `name` (a pathname syscall arg) to the *actual* file or directory
/// it names on disk, from the tracee's filesystem context (`cwd` is the
/// tracee's cwd, see [`tracee_cwd`]):
///
/// 1. relative names are joined to the tracee's cwd (the supervisor's cwd as
///    a last resort);
/// 2. a resolvable path is canonicalized — symlinks chased, `..` collapsed —
///    producing the actual path (this settles an existing file's real identity);
/// 3. when the tail does not exist yet (open-for-create, `unlink`, rename
///    targets, ...) the existing prefix is still chased, but only refinements
///    *over the input* are handed back: a symlinked or `..`-carrying path
///    becomes its actual directory plus the literal tail, and anything that
///    already names that directory (plain absolute paths, plain cwd-relative
///    names) passes the original name through — per the contract, an
///    unresolvable file is reported as the name it was asked by. A *dangling*
///    symlink (target does not exist yet) is followed to where it points, so
///    the intended location still lands, capped like the kernel (40 hops:
///    chains unwind, cycles give up and stay literal);
/// 4. when even the prefix cannot be established the name passes through
///    unchanged — Lua still gets a string it can ask-and-remember on.
///
/// Best-effort and never failing: it only ever returns a *more truthful*
/// string than the raw deref.
fn resolve_path(cwd: Option<&Path>, name: &str) -> String {
    if name.is_empty() {
        return name.to_string();
    }
    if name.starts_with('/') {
        return resolve_joined(Path::new(name), name);
    }
    let Some(base) = cwd
        .map(Path::to_path_buf)
        .or_else(|| std::env::current_dir().ok())
    else {
        return name.to_string();
    };
    let joined = base.join(name);
    resolve_joined(&joined, name)
}

/// Symlink hops to follow while chasing dangling links; past this we stop and
/// keep the current form literal (the kernel's own MAXSYMLINKS is 40).
const MAX_SYMLINK_HOPS: usize = 40;

/// If `cand` is a symlink whose target does not exist (a *dangling* link),
/// return the link's target resolved to an absolute path (relative targets
/// against the link's own directory) — the file the link *intends* to touch.
/// `None` for non-symlinks and for links that exist but are plain files/dirs
/// (those canonicalize fine and never reach here).
fn dangling_target(cand: &Path) -> Option<PathBuf> {
    let meta = std::fs::symlink_metadata(cand).ok()?;
    if !meta.file_type().is_symlink() {
        return None;
    }
    let link = std::fs::read_link(cand).ok()?;
    Some(if link.is_absolute() {
        link
    } else {
        cand.parent()?.join(link)
    })
}

/// The walking core of [`resolve_path`] over an absolute path. `fallback` is
/// the string to pass through when resolution cannot beat it.
fn resolve_joined(joined: &Path, fallback: &str) -> String {
    // Full resolution first: the file exists, chase everything.
    if let Ok(real) = std::fs::canonicalize(joined) {
        return real.to_string_lossy().into_owned();
    }
    // The tail is missing: chase the existing prefix component by component
    // and keep the rest literal, so symlink/`..` chases still apply where
    // they can. A component that is itself a dangling symlink is followed to
    // where it points, so the walk keeps going against the intended target.
    let mut out = PathBuf::from("/");
    let mut pending: std::collections::VecDeque<std::ffi::OsString> = joined
        .components()
        .map(|c| c.as_os_str().to_os_string())
        .collect();
    let mut hops = 0usize;
    let mut literal = false;
    while let Some(seg) = pending.pop_front() {
        let text = seg.to_string_lossy();
        if literal {
            match text.as_ref() {
                ".." => {
                    out.pop();
                }
                "." | "/" => {}
                _ => out.push(&seg),
            }
            continue;
        }
        match text.as_ref() {
            // joined is absolute here (resolve_path made it so) and "." is a
            // no-op — both collapse to nothing.
            "/" | "." => {}
            ".." => {
                out.pop();
            }
            _ => {
                let cand = out.join(&seg);
                match std::fs::canonicalize(&cand) {
                    Ok(p) => out = p,
                    Err(_) => {
                        // Unresolvable so far: within the hop budget, a
                        // dangling symlink rebases the whole walk onto where
                        // it points (its target is absolute, so the pending
                        // walk restarts there and the still-waiting components
                        // follow it).
                        if hops < MAX_SYMLINK_HOPS
                            && let Some(target) = dangling_target(&cand)
                        {
                            hops += 1;
                            let rest: Vec<_> = pending.drain(..).collect();
                            let mut rebase: Vec<_> = target
                                .components()
                                .map(|c| c.as_os_str().to_os_string())
                                .collect();
                            rebase.extend(rest);
                            pending = rebase.into();
                            out = PathBuf::from("/");
                            continue;
                        }
                        // Over budget (cycles) or genuinely missing: keep the
                        // form and go literal from here.
                        out.push(&seg);
                        literal = true;
                    }
                }
            }
        }
    }
    let resolved = out.to_string_lossy().into_owned();
    // Hand the refined form back only when it reflects the actual filesystem
    // (a symlink or `..` chased, or a relative name made concrete); otherwise
    // pass the original name along unchanged.
    if resolved != joined.to_string_lossy() {
        resolved
    } else {
        fallback.to_string()
    }
}

/// The finished run. stdout/stderr come straight from the engine's capture
/// (already fully drained by `finish_result`), so the Lua driver needs no
/// chunk accumulation of its own.
fn finished_table(lua: &Lua, r: seccomp::SandboxResult) -> mlua::Result<Table> {
    let t = lua.create_table()?;
    t.set("kind", "finished")?;
    let result = lua.create_table()?;
    result.set("stdout", lua.create_string(&r.stdout)?)?;
    result.set("stderr", lua.create_string(&r.stderr)?)?;
    let exit = lua.create_table()?;
    if let Some(code) = r.exit.code {
        exit.set("code", code as i64)?;
    }
    if let Some(sig) = r.exit.signal {
        exit.set("signal", sig as i64)?;
    }
    result.set("exit", exit)?;
    result.set("syscalls", r.syscalls as i64)?;
    result.set("denied", r.denied as i64)?;
    // Always present, so `bash` can read it without a nil check, and true only
    // when the user stopped the run. A killed tree and a command that failed on
    // its own look identical without it — same signal, same exit — and the
    // model reads "you interrupted this" very differently from "this broke".
    result.set("interrupted", r.interrupted)?;
    t.set("result", result)?;
    Ok(t)
}

// `agent.bash` itself is Lua (`lua/lib/bash.lua`); what is left on this side is
// the substrate it drives: `spawn`, `step`, `decide`, `kill`, `write` and
// `close_stdin`, over `seccomp::Sandbox`.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::{FakeHttpServer, FakeRequest, FakeResponse, FakeServerReply};
    use serde_json::json;

    /// Call one of the shipped tools the way the TUI does — on the shipped VM,
    /// with the round's sink and an ask handler — and return the tool's JSON
    /// body plus every question it asked.
    ///
    /// The `fs` tools ask before touching anything, so a test *has* to answer:
    /// `verdict` is what the user would press.
    fn call_tool_asking(
        name: &str,
        args: &str,
        verdict: AskAnswer,
    ) -> (serde_json::Value, Vec<String>) {
        let asked: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let seen = asked.clone();
        let sink = PanelSink::default();
        let (body, _) = invoke_mcp_tool_with_asks(
            name,
            args,
            Some(&sink),
            Some(Rc::new(move |text: &str, _always: bool| {
                seen.borrow_mut().push(text.to_string());
                verdict.clone()
            })),
            &ConfigSource::Tree,
        )
        .expect("invoke")
        .unwrap_or_else(|| panic!("the shipped config registers {name}"));
        let json = serde_json::from_str(&body).expect("tool json");
        let questions = asked.borrow().clone();
        (json, questions)
    }

    /// `call_tool_asking` with the user pressing `[y]es` every time.
    fn tool_allowed(name: &str, args: &str) -> (serde_json::Value, Vec<String>) {
        call_tool_asking(name, args, AskAnswer::Allow)
    }

    /// A fresh LuaJIT VM with the `agent` namespace installed.
    /// One sandboxed run's outcome, as a test sees it: the result table
    /// `agent.bash` returns, decoded. The tool layer (`lua/bash_tool.lua`)
    /// shapes this into the MCP reply the model reads; the tests using this are
    /// about the protocol underneath — masking, asks, denial reasons — so they
    /// talk to `agent.bash` itself.
    #[derive(Debug)]
    struct Run {
        stdout: String,
        /// Decoded for completeness; the tool's reply is where a test that cares
        /// about stderr asserts on it.
        #[allow(dead_code)]
        stderr: String,
        exit_code: Option<i64>,
        exit_signal: Option<i64>,
        syscalls: u64,
        denied: u64,
        denied_reason: Option<String>,
    }

    impl Run {
        /// The run did not exit cleanly: killed by a signal (e.g. a denied
        /// syscall) or a non-zero exit code.
        fn failed(&self) -> bool {
            self.exit_signal.is_some() || self.exit_code.map(|c| c != 0).unwrap_or(false)
        }
    }

    /// Drive one sandboxed `bash -c` run through `agent.bash`, on a fresh VM of
    /// its own, with the policy given as Lua source and, optionally, a
    /// user-permission ask handler. A fresh VM here is the test's own isolation
    /// — the shipped tool does the same call, on the config VM.
    ///
    /// The ask wiring is the shipped tool's, minus the panel: the run is driven
    /// with `s:run(handler)` and the handler hands each question to
    /// `agent.api.ask_user`, which is the primitive the VM's handler (or the
    /// auto-deny, when there is none) answers. Passing a policy *source* rather
    /// than the shipped policy is the point: these tests pin the engine's
    /// contract, which a fixed tool policy could not exercise.
    fn run_bash(
        cmdline: &str,
        policy_src: &str,
        sink: Option<&PanelSink>,
        on_ask: Option<AskHandler>,
    ) -> Result<Run, String> {
        let lua = new_vm_with_ask(sink, on_ask).map_err(|e| format!("lua bash: vm: {e}"))?;
        let chunk = format!(
            r#"
        local policy = (function()
        {policy_src}
        end)()
        local s = agent.bash({cmdline:?}, policy, nil)
        return s:run(function(a)
          return agent.api.ask_user((type(a) == "table" and a.description) or tostring(a))
        end)
        "#
        );
        let r: Table = lua
            .load(&chunk)
            .eval()
            .map_err(|e| format!("lua bash: {e}"))?;
        let text = |key: &str| -> String {
            r.get::<mlua::LuaString>(key)
                .map(|s| String::from_utf8_lossy(s.as_bytes().as_ref()).to_string())
                .unwrap_or_default()
        };
        let exit: Table = r.get("exit").map_err(|e| format!("lua bash: no exit: {e}"))?;
        Ok(Run {
            stdout: text("stdout"),
            stderr: text("stderr"),
            exit_code: exit.get("code").map_err(|e| format!("lua bash: {e}"))?,
            exit_signal: exit.get("signal").map_err(|e| format!("lua bash: {e}"))?,
            syscalls: r.get("syscalls").unwrap_or(0),
            denied: r.get("denied").unwrap_or(0),
            denied_reason: r.get("denied_reason").ok().flatten(),
        })
    }

    fn vm() -> mlua::Lua {
        new_vm().expect("agent VM")
    }

    // -- the `lua/` tree: lib modules, the entry script, and require ---------

    /// The tree every VM loads (the repo's own `lua/`, like the shipped one).
    fn tree() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("lua")
    }

    /// `print` goes to the status bar once a screen is attached, and to stdout
    /// when there is not one — because a TUI owns the terminal, and because a
    /// headless run still has to be debuggable.
    ///
    /// The two branches are mutually exclusive on a process-global, so the
    /// whole test is serialized against the others that touch it.
    #[test]
    fn print_follows_the_screen() {
        let _guard = crate::status::exclusive();
        crate::status::reset();
        let lua = vm();

        // Detached: nothing lands on the status line.
        lua.load(r#"print("to stdout")"#).exec().expect("print");
        assert!(
            crate::status::status_line().get().is_none(),
            "with no screen, print must not become a status"
        );

        // Attached: it becomes the status line, tab-joined like Lua's own.
        crate::status::attach();
        lua.load(r#"print("hello", 42, "world")"#).exec().expect("print");
        assert_eq!(
            crate::status::status_line().get().unwrap().text,
            "hello\t42\tworld",
            "Lua's print semantics: any number of args, joined with tabs"
        );

        // A `__tostring` metamethod is honoured, as `print` requires.
        lua.load(
            r#"
            local t = setmetatable({}, { __tostring = function() return "POINT" end })
            print(t)
        "#,
        )
        .exec()
        .expect("print a table");
        assert_eq!(crate::status::status_line().get().unwrap().text, "POINT");

        // Multi-line print keeps one row: the rest would land on the input box.
        lua.load(r#"print("one\ntwo")"#).exec().expect("print");
        assert_eq!(crate::status::status_line().get().unwrap().text, "one");

        crate::status::reset();
    }

    /// Every `lua/lib/**.lua` is required at VM setup, and a lib module
    /// publishes itself as `agent.<name>`: no require at the use site, and
    /// `package.loaded` holds the same table.
    #[test]
    fn lib_modules_are_loaded_registered_and_cached() {
        let lua = vm();
        let problem: Option<String> = lua
            .load(
                r#"
            for _, name in ipairs({ "utils", "seccomp", "ask", "mode" }) do
              local m = package.loaded[name]
              if type(m) ~= "table" then return name .. " not in package.loaded" end
              if agent[name] ~= m then return "agent." .. name .. " is not the module" end
              if require(name) ~= m then return "require re-ran " .. name end
              local good, err = pcall(m._selftest)
              if not good then return name .. " selftest: " .. tostring(err) end
            end
            -- Usable through the agent namespace, without a require.
            if agent.utils.string.trim("  x  ") ~= "x" then return "trim" end
            return nil
        "#,
            )
            .eval()
            .expect("loader eval");
        assert!(
            problem.is_none(),
            "lua/lib: {}",
            problem.unwrap_or_default()
        );
    }

    /// The lib's answers must match the hand-rolled arithmetic the shipped
    /// policy does today (`flags % 4 ~= 0`, and the `%`-chain that decodes
    /// O_CREAT/O_TRUNC/O_APPEND) over the whole flag range — otherwise
    /// switching `lua/policy.lua` over would silently change what is asked.
    #[test]
    fn seccomp_lib_agrees_with_the_hand_rolled_openat_rule() {
        let lua = vm();
        let problem: Option<String> = lua
            .load(
                r#"
            local sc = agent.seccomp
            -- 1. The ask/allow decision, over every flag value in range.
            for flags = 0, 4096, 7 do
              -- lua/policy.lua: `if sc.check(..., "WRITE") then ask_trust_write(...)`
              if (flags % 4 ~= 0) ~= sc.check("openat", flags, "WRITE") then
                return "write mismatch at " .. flags
              end
            end
            -- 2. The description, over the bits that file's decoder names
            -- (O_WRONLY/O_RDWR + O_CREAT/O_TRUNC/O_APPEND). `describes` is a
            -- superset elsewhere — it also names O_NOCTTY and friends, and
            -- appends unnamed bits in hex — so this is the exact-overlap case.
            local named = { 64, 512, 1024 }
            local names = { "O_CREAT", "O_TRUNC", "O_APPEND" }
            for acc = 1, 2 do
              for mask = 0, 7 do
                local flags = acc
                -- A callable table: `agent.ask("q")` asks, and the helpers hang
            -- off the same table.
            if type(agent.ask) ~= "table" then return "agent.ask" end
            if agent.ask ~= require("ask") then return "not require('ask')" end
            for _, helper in ipairs({ "ask", "of", "denied", "reason", "deny",
                                      "for_syscall", "drive", "build" }) do
              if type(agent.ask[helper]) ~= "function" then return "ask." .. helper end
            end
            local expected = { (acc == 1) and "O_WRONLY" or "O_RDWR" }
                for i = 1, 3 do
                  if math.floor(mask / (2 ^ (i - 1))) % 2 == 1 then
                    flags = flags + named[i]
                    expected[#expected + 1] = names[i]
                  end
                end
                local decoded = table.concat(expected, "|")
                if decoded ~= sc.describes("openat", flags) then
                  return "decode mismatch at " .. flags .. ": " .. decoded ..
                         " vs " .. sc.describes("openat", flags)
                end
              end
            end
            return nil
        "#,
            )
            .eval()
            .expect("equivalence eval");
        assert!(
            problem.is_none(),
            "agent.seccomp vs policy: {}",
            problem.unwrap_or_default()
        );
    }

    /// The bridge is one locked, annotated namespace: `agent.api.<name>` for
    /// every primitive, no `_`-prefixed leftovers on `agent`, reads work, and
    /// every write path is refused.
    #[test]
    fn api_namespace_is_locked_and_annotated() {
        let lua = vm();
        let problem: Option<String> = lua
            .load(
                r#"
            -- Reads work, and the friendly layer is untouched.
            if type(agent.api) ~= "table" then return "agent.api missing" end
            if type(agent.api.step) ~= "function" then return "agent.api.step" end
            if type(agent.bash) ~= "function" then return "agent.bash" end
            -- The old flat names are gone (the user's own fields are not ours).
            for _, name in ipairs({ "_spawn", "_step", "_decide", "_kill",
                                    "_panel_create", "_json_encode", "_memory_flush" }) do
              if agent[name] ~= nil then return "agent." .. name .. " still exists" end
            end
            -- Assignments are refused, and say so.
            local ok, err = pcall(function() agent.api.step = function() end end)
            if ok then return "assignment was allowed" end
            if not tostring(err):find("read%-only") then return "unhelpful error: " .. tostring(err) end
            -- Adding a new key is refused the same way.
            ok = pcall(function() agent.api.sneaky = function() return true end end)
            if ok or agent.api.sneaky ~= nil then return "new key was allowed" end
            -- Replacing a primitive is a no-op, not a takeover.
            local real = agent.api.step
            pcall(function() agent.api.step = function() return "hijacked" end end)
            if agent.api.step ~= real then return "primitive was replaced" end
            -- The metatable is hidden, so the real table cannot be reached.
            if getmetatable(agent.api) ~= false then return "metatable visible" end
            if pcall(setmetatable, agent.api, {}) then return "setmetatable allowed" end
            return nil
        "#,
            )
            .eval()
            .expect("api lock eval");
        assert!(
            problem.is_none(),
            "agent.api: {}",
            problem.unwrap_or_default()
        );
    }

    /// `agent.api_docs` documents the whole bridge: one entry per primitive,
    /// each with a summary — which the loader already enforces at startup, so
    /// this pins the *shape* a consumer (or `agent.help`) can rely on.
    #[test]
    fn api_docs_cover_the_bridge() {
        let lua = vm();
        let (count, problems): (usize, String) = lua
            .load(
                r#"
            local bad, n = {}, 0
            for name, entry in pairs(agent.api_docs) do
              n = n + 1
              if type(entry) ~= "table" or type(entry.summary) ~= "string"
                 or entry.summary == "" then
                bad[#bad + 1] = name
              end
              for _, arg in ipairs(entry.args or {}) do
                if type(arg) ~= "table" or type(arg[1]) ~= "string"
                   or type(arg[2]) ~= "string" or type(arg[3]) ~= "string" then
                  bad[#bad + 1] = name .. ".args"
                end
              end
            end
            return n, table.concat(bad, ",")
        "#,
            )
            .eval()
            .expect("api_docs eval");
        // Every primitive is documented: the VM would not have built otherwise,
        // so the count is the bridge's size.
        assert_eq!(count, 36, "lua/api.lua should annotate all 36 primitives");
        assert!(problems.is_empty(), "malformed annotation entries: {problems}");
    }

    /// A bridge primitive still works through the namespace (the JSON boundary
    /// is the cheapest one to exercise end to end).
    #[test]
    fn api_bridge_functions_still_work() {
        let lua = vm();
        let round: String = lua
            .load(
                r#"
            local text = agent.api.json_encode({ ok = true, items = { 1, 2 } })
            local back = agent.api.json_decode(text)
            return text .. "|" .. tostring(back.ok) .. "|" .. tostring(#back.items)
        "#,
            )
            .eval()
            .expect("json bridge");
        assert_eq!(round, r#"{"items":[1,2],"ok":true}|true|2"#);
    }

    /// The shipped config registers the filesystem connection by name, from the
    /// module: `agent.mcps.fs = require("fs")` is the whole registration.
    #[test]
    fn shipped_config_registers_the_fs_connection_from_the_module() {
        let lua = shipped_vm();
        let problem: Option<String> = lua
            .load(
                r#"
            local conn = agent.mcps.fs
            if type(conn) ~= "table" then return "agent.mcps.fs" end
            if conn.name ~= "fs" then return "connection name: " .. tostring(conn.name) end
            -- The registration *is* the module (one table, not a copy).
            if conn ~= require("fs") then return "not the module" end
            if conn ~= agent.fs then return "agent.fs is not the module" end
            -- The tool set the module ships.
            local names = {}
            for name in pairs(conn.tools) do names[#names + 1] = name end
            table.sort(names)
            if table.concat(names, ",") ~= "apply_patch,hand_to_user,read,write_file" then
              return "tools: " .. table.concat(names, ",")
            end
            -- Each is a callable agent.utils.tool with a description and a schema.
            for name, tool in pairs(conn.tools) do
              if type(tool.description) ~= "string" or tool.description == "" then
                return name .. ": description"
              end
              if type(tool.signature) ~= "table" or tool.signature.type ~= "object" then
                return name .. ": schema"
              end
              if type(tool.callback) ~= "function" then return name .. ": callback" end
            end
            -- The pure diff engine rides along, with no agent config needed.
            if type(agent.fs.patch.apply) ~= "function" then return "patch.apply" end
            if #agent.fs.patch.split("a\nb\n") ~= 3 then return "patch.split" end
            return nil
        "#,
            )
            .eval()
            .expect("fs registration eval");
        assert!(
            problem.is_none(),
            "agent.mcps.fs: {}",
            problem.unwrap_or_default()
        );
    }

    /// The auto-route: a *request* whose response is an event stream. The POST
    /// goes out over the request transport; the `text/event-stream` content-type
    /// then upgrades the body into parsed events on `on_event` — the MCP
    /// streamable-HTTP case, where one endpoint answers with JSON *or* a stream
    /// and the client cannot know in advance. Raw bytes still reach `on_chunk`.
    #[tokio::test]
    async fn http_upgrades_a_request_response_into_events() {
        let fake = FakeHttpServer::start(|_req: FakeRequest| {
            FakeServerReply::StreamEvents(vec![
                // Deliberately split mid-frame: the parser must hold the partial
                // event until the rest arrives.
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":".to_string(),
                "1,\"result\":{\"ok\":true}}\n\n".to_string(),
                "data: bare\n\n".to_string(),
                ": a comment\n\n".to_string(),
            ])
        });
        let lua = vm();
        let problem: Option<String> = eval_reactor(
            &lua,
            &format!(
                r##"
            local events, chunks, done = {{}}, {{}}, nil
            local s = agent.http("POST", "{url}", {{
              body = '{{"jsonrpc":"2.0","id":1,"method":"initialize"}}',
              headers = {{ ["content-type"] = "application/json" }},
              on_chunk = function(c) chunks[#chunks + 1] = c end,
              on_event = function(event, data)
                events[#events + 1] = (event or "message") .. "|" .. data
              end,
              on_done = function(o) done = o end,
            }})
            -- The route is chosen up front from the request...
            if s.route ~= "request" then return "route: " .. tostring(s.route) end
            s:run()
            -- ...and upgraded by the response headers.
            if not s.event_stream then return "no upgrade" end
            if #events ~= 2 then return "#events=" .. #events end
            if events[1] ~= 'message|{{"jsonrpc":"2.0","id":1,"result":{{"ok":true}}}}' then
              return "event 1: " .. events[1]
            end
            if events[2] ~= "message|bare" then return "event 2: " .. events[2] end
            if s.status ~= 200 then return "status: " .. tostring(s.status) end
            if #chunks == 0 then return "on_chunk saw no bytes" end
            -- on_done reports the status *and* how many events arrived.
            if not done or done.status ~= 200 or done.events ~= 2 then
              return "on_done events: " .. tostring(done and done.events)
            end
            return nil
        "##,
                url = fake.url("/mcp")
            ),
        )
        .await
        .expect("upgrade eval");
        assert!(
            problem.is_none(),
            "event-stream upgrade: {}",
            problem.unwrap_or_default()
        );
    }

    /// The runtime is lib modules now: bash (+ verdicts), the panels, the
    /// HTTP transport and the MCP client each live in `lua/lib/<name>.lua`,
    /// are auto-required, and publish themselves on `agent` — the same table
    /// `require` hands back. The embedded driver is down to the cooperative
    /// wait it never gave up.
    #[test]
    fn lib_modules_publish_themselves_on_agent() {
        let lua = vm();
        let problem: Option<String> = lua
            .load(
                r#"
            -- A module with one entry point returns the function itself.
            if agent.mcp ~= require("mcp") then return "agent.mcp" end
            -- A module that publishes several fields returns a table of them.
            local bash, panel, http = require("bash"), require("panel"), require("http")
            for _, pair in ipairs({ { "bash", bash }, { "allow", bash },
                                    { "deny", bash }, { "panel", panel },
                                    { "split_panel", panel }, { "http", http } }) do
              if agent[pair[1]] ~= pair[2][pair[1]] then
                return "agent." .. pair[1] .. " is not the module's"
              end
            end
            -- A pure-library module publishes its own namespace.
            if agent.utils ~= require("utils") then return "agent.utils" end
            if agent.seccomp ~= require("seccomp") then return "agent.seccomp" end
            -- The registry the MCP client registers connections into.
            if type(agent.mcps) ~= "table" then return "agent.mcps" end
            -- `agent.sse` was merged into `agent.http`: one interface, two routes.
            if agent.sse ~= nil then return "agent.sse still exists" end
            -- What the embedded driver still owns: the cooperative wait.
            if type(agent.on_timeout) ~= "function" then return "agent.on_timeout" end
            return nil
        "#,
            )
            .eval()
            .expect("module layout eval");
        assert!(
            problem.is_none(),
            "runtime layout: {}",
            problem.unwrap_or_default()
        );
    }

    /// A mode switch overwrites both halves, and both reaches the runtime the
    /// way it reads them: `system_prompt()` is re-read per request and
    /// `mcps_tool_defs` reindexes `agent.mcps` per request — so a switch is
    /// live without a restart. Connections are shared by reference (the mode
    /// and the registry name the same table); the registry itself is a fresh
    /// copy, so a stray runtime write cannot push back into the mode's spec.
    #[test]
    fn a_mode_switch_overwrites_the_prompt_and_the_tool_registry() {
        let lua = neutral_vm();
        let before = system_prompt(&lua).expect("baseline prompt");
        let problem: Option<String> = lua
            .load(
                r#"
            -- Two connections, one of them the real fs module.
            local fs = require("fs")
            local other = { name = "other", tools = {} }
            agent.mode.new("writing", {
              description = "can edit",
              system_prompt = "MODE PROMPT",
              mcps = { fs = fs, other = other },
            })
            agent.mode.new("bare", {})

            if #agent.mode.names() ~= 2 then return "names" end
            if agent.mode.current() ~= nil then return "starts on the baseline" end

            agent.mode.set("writing")
            if agent.mode.current() ~= "writing" then return "current" end
            if agent.llm.system_prompt ~= "MODE PROMPT" then return "prompt" end
            local keys = {}
            for name in pairs(agent.mcps) do keys[#keys + 1] = name end
            table.sort(keys)
            if table.concat(keys, ",") ~= "fs,other" then
              return "registry: " .. table.concat(keys, ",")
            end
            if not rawequal(agent.mcps.fs, fs) then return "fs is a copy" end
            if not rawequal(agent.mcps.other, other) then return "other is a copy" end
            if rawequal(agent.mcps, agent.mode.mcps()) then return "registry aliased" end
            -- A stray runtime write cannot reach the mode's spec.
            agent.mcps.scratch = { name = "scratch", tools = {} }
            if agent.mode.mcps().scratch ~= nil then return "write leaked into the spec" end

            -- A mode with no mcps yields an empty registry, never nil: Rust
            -- reindexes `agent.mcps` per request and would fail on nil.
            agent.mode.set("bare")
            if agent.llm.system_prompt ~= "" then return "bare prompt" end
            if type(agent.mcps) ~= "table" or next(agent.mcps) ~= nil then
              return "bare registry"
            end

            -- Back to the baseline, both halves.
            agent.mode.set()
            if agent.mode.current() ~= nil then return "current after reset" end
            if agent.llm.system_prompt == "MODE PROMPT" then return "prompt not restored" end
            if pcall(agent.mode.set, "nope") then return "unknown mode accepted" end
            return nil
        "#,
            )
            .eval()
            .expect("mode switch eval");
        assert!(
            problem.is_none(),
            "agent.mode: {}",
            problem.unwrap_or_default()
        );
        // And the prompt half as *Rust* reads it: per request, no restart.
        assert_eq!(
            system_prompt(&lua).expect("prompt after reset"),
            before,
            "the baseline prompt is what Rust sends"
        );
        let defs = mcps_tool_defs(&lua).expect("reindex after reset");
        assert!(
            defs.is_empty(),
            "the baseline registry is what Rust advertises: {:?}",
            defs.iter().map(|d| &d.name).collect::<Vec<_>>()
        );
    }

    /// The switch as the runtime sees it mid-session: register, switch, and the
    /// very next request's tool list *and* system prompt are the mode's.
    #[test]
    fn a_mode_is_live_for_the_next_request() {
        let lua = neutral_vm();
        lua.load(
            r#"
            agent.mode.new("scoped", {
              system_prompt = "SCOPED PROMPT",
              mcps = { fs = require("fs") },
            })
        "#,
        )
        .exec()
        .expect("register");
        // Still the baseline: nothing switched, so nothing changed.
        assert_ne!(system_prompt(&lua).expect("prompt"), "SCOPED PROMPT");
        assert!(
            mcps_tool_defs(&lua).expect("reindex").is_empty(),
            "registering a mode does not activate it"
        );

        lua.load(r#"agent.mode.set("scoped")"#)
            .exec()
            .expect("switch");
        assert_eq!(system_prompt(&lua).expect("prompt"), "SCOPED PROMPT");
        let defs = mcps_tool_defs(&lua).expect("reindex");
        let mut names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            ["fs.apply_patch", "fs.hand_to_user", "fs.read", "fs.write_file"],
            "the mode's tools are what the next request advertises"
        );
    }

    /// Ask once, remember afterwards: the trust table answers the second
    /// question about a path without putting it to the user, and only for what
    /// was trusted.
    ///
    /// Driven through a real sandboxed run, so the trusted path is one the
    /// *engine* resolved (`agent.seccomp.path`) — the trust table matches on that,
    /// not on anything a policy made up.
    #[test]
    fn ask_and_remember_trusts_a_path_for_the_rest_of_the_run() {
        const POLICY: &str = r#"
        local sc, ask = require("seccomp"), require("ask")
        local p = setmetatable({}, { __index = function() return function() return true end end })
        p.openat = function(sys)
          local flags = sc.arg(sys, "openat")
          if sc.is_tty_probe(flags) then return true end
          if sc.check("openat", flags, "WRITE") then
            return ask(ask.for_syscall(sys, "write", sc.describes("openat", flags)))
          end
          return true
        end
        return p
        "#;
        let path = std::env::temp_dir().join(format!("ask-trust-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&path);
        // The same file, opened twice: two questions if nothing is remembered.
        let cmdline = format!("echo one > {0}; echo two > {0}", path.display());
        let watched = path.to_string_lossy().to_string();

        // Headless: an ask auto-denies, so the first open fails and nothing is
        // trusted — the run cannot get past the first redirect.
        let out = run_bash(&cmdline, POLICY, None, None).expect("bash ran");
        assert!(out.denied >= 1, "no handler, so the ask denies: {out:?}");
        assert!(!path.exists(), "and nothing was written");

        // The same run, with a handler that answers "always allow this": the flag
        // rides with the verdict and `ask` — the side that knows the path —
        // records it. Two opens, one question.
        let asked: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let seen = asked.clone();
        let out = run_bash(
            &cmdline,
            POLICY,
            None,
            Some(Rc::new(move |text: &str, _always: bool| {
                seen.borrow_mut().push(text.to_string());
                AskAnswer::AllowAndTrust
            })),
        )
        .expect("bash ran");
        let questions = asked.borrow().clone();
        assert!(
            !questions.is_empty(),
            "the first open is a question: {questions:?}"
        );
        assert!(
            questions[0].contains(&watched),
            "and it names the path that was trusted: {:?}",
            questions[0]
        );
        assert_eq!(
            questions.len(),
            1,
            "the second open of the trusted path is silent: {questions:?}"
        );
        assert_eq!(out.denied, 0, "nothing was denied: {out:?}");
        assert_eq!(
            std::fs::read_to_string(&path).expect("written"),
            "two\n",
            "the whole command ran"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// `ask_trust_write` is the whole decision in one call: trusted already,
    /// asked once if not, and remembered **only** on "always". Two opens of the
    /// same file in one command make the difference visible — a plain yes is for
    /// this time, so it is asked again; an "always" is remembered, so it is not.
    #[test]
    fn ask_trust_write_remembers_only_on_always() {
        const POLICY: &str = r#"
        local sc, ask = require("seccomp"), require("ask")
        local p = setmetatable({}, { __index = function() return function() return true end end })
        p.openat = function(sys)
          local flags = sc.arg(sys, "openat")
          if sc.is_tty_probe(flags) then return true end
          if sc.check("openat", flags, "WRITE") then
            -- One call: trusted? ask? remember an "always"?
            return ask.ask_trust_write(sc.path(sys), "write " .. sc.describes("openat", flags))
          end
          return true
        end
        return p
        "#;
        let path = std::env::temp_dir().join(format!("ask-trust-w-{}.txt", std::process::id()));

        // A plain yes: both opens are allowed, and neither is remembered, so the
        // second open asks again.
        let _ = std::fs::remove_file(&path);
        let cmdline = format!("echo one > {0}; echo two > {0}", path.display());
        let asked: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let seen = asked.clone();
        let out = run_bash(
            &cmdline,
            POLICY,
            None,
            Some(Rc::new(move |text: &str, _always: bool| {
                seen.borrow_mut().push(text.to_string());
                AskAnswer::Allow
            })),
        )
        .expect("bash ran");
        assert_eq!(out.denied, 0, "a yes allows both opens: {out:?}");
        assert_eq!(
            asked.borrow().len(),
            2,
            "a plain yes is for this time, so the second open asks too: {:?}",
            asked.borrow()
        );
        assert_eq!(std::fs::read_to_string(&path).expect("written"), "two\n");
        let _ = std::fs::remove_file(&path);

        // "Always": remembered, so the second open is silent.
        let asked: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let seen = asked.clone();
        let out = run_bash(
            &cmdline,
            POLICY,
            None,
            Some(Rc::new(move |text: &str, _always: bool| {
                seen.borrow_mut().push(text.to_string());
                AskAnswer::AllowAndTrust
            })),
        )
        .expect("bash ran");
        assert_eq!(out.denied, 0, "an always allows both opens: {out:?}");
        assert_eq!(
            asked.borrow().len(),
            1,
            "an always is remembered, so the second open is silent: {:?}",
            asked.borrow()
        );
        assert_eq!(std::fs::read_to_string(&path).expect("written"), "two\n");
        let _ = std::fs::remove_file(&path);

        // A refusal ends the run at the first ask — the engine kills the tracee,
        // so there is no second open to observe. (That a denial is not
        // remembered is pinned at the Lua level, in ask's own self-test: it
        // needs a coroutine, not a dying process.)
        let _ = std::fs::remove_file(&path);
        let asked: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let seen = asked.clone();
        let out = run_bash(
            &cmdline,
            POLICY,
            None,
            Some(Rc::new(move |text: &str, _always: bool| {
                seen.borrow_mut().push(text.to_string());
                AskAnswer::Deny(None)
            })),
        )
        .expect("bash ran");
        assert!(out.denied >= 1, "the refusal stopped the run: {out:?}");
        assert_eq!(
            asked.borrow().len(),
            1,
            "asked once, then the refusal killed the tracee: {:?}",
            asked.borrow()
        );
        assert!(!path.exists(), "and nothing was written");
    }

    /// A file inside a trusted *folder* is trusted — that is the containment
    /// rule the whole directory trust rests on, and it has to hold in both
    /// tables and stop at a real boundary. (The `dir` flag is what makes it
    /// work: trusting a directory trusts its subtree, trusting a *file* trusts
    /// only itself.)
    #[test]
    fn a_file_inside_a_trusted_folder_is_trusted() {
        let lua = vm();
        let problem: Option<String> = lua
            .load(
                r#"
            local ask = agent.ask
            ask.forget_all()

            -- A trusted directory covers what is inside it, in both tables.
            ask.trust("/usr/share")
            local read_in = ask.is_trusted("/usr/share/doc/lua/readme.md")
            ask.trust_write("/etc")
            local write_in = ask.is_write_trusted("/etc/ssl/certs/ca.pem")
            local write_in_also_read = ask.is_trusted("/etc/ssl/certs/ca.pem")
            -- A *file* trusted inside a directory does not extend to the
            -- directory: only the path itself.
            ask.trust("/usr/share/doc")
            local file_covered = ask.is_trusted("/usr/share/doc/lua")
            -- Tidied and trailing-slash spellings resolve to the same answer.
            local messy = ask.is_trusted("/usr/share/./doc/../share/man/man1/x.1.gz")
            local trailing = ask.is_trusted("/usr/share/doc/")
            -- The boundary: a sibling whose name merely starts with the trusted
            -- one is *not* inside it.
            local sibling = ask.is_trusted("/usr/sharefoo")
            local root_sibling = ask.is_write_trusted("/etcfoo")
            -- Nothing in a folder the user never named.
            local elsewhere = ask.is_write_trusted("/opt/other/file")

            ask.forget_all()
            if not read_in then return "a file inside a trusted dir (read)" end
            if not write_in then return "a file inside a write-trusted dir" end
            if not write_in_also_read then return "and trust_write implies trust" end
            if not file_covered then return "a trusted file that is a dir path" end
            if not messy then return "a tidied path inside it" end
            if not trailing then return "a trailing slash" end
            if sibling then return "a sibling sharing the prefix" end
            if root_sibling then return "a sibling of a write-trusted dir" end
            if elsewhere then return "a folder nobody named" end
            return nil
        "#,
            )
            .eval()
            .expect("containment walk");
        assert!(
            problem.is_none(),
            "containment: {}",
            problem.unwrap_or_default()
        );
    }

    /// A trusted *directory* covers its subtree, and the boundary is respected:
    /// `/tmp` trusted does not trust `/tmpfoo`. Also the resolution forms — `~`,
    /// a relative path, `.`/`..` tidied — and that the table is left clean.
    #[test]
    fn a_trusted_directory_covers_its_subtree_only() {
        let lua = vm();
        let problem: Option<String> = lua
            .load(
                r#"
            local ask = agent.ask
            ask.forget_all()
            ask.trust("/tmp")
            local inside = ask.is_trusted("/tmp/agent-trust-probe/deep/file.txt")
            local sibling = ask.is_trusted("/tmpfoo")
            local itself = ask.is_trusted("/tmp")
            -- The same directory reached the way a user would write it.
            local messy = ask.is_trusted("/tmp/./a/../b/c.txt")
            -- A trusted file is *not* a trusted directory.
            ask.trust("/etc/hostname")
            local file_only = ask.is_trusted("/etc/hostname/sub")
            -- The write table is its own question: "trusted at all" is not
            -- "writable", and `trust_write` implies both.
            ask.trust_write("/opt/scratch")
            local write_only = ask.is_write_trusted("/opt/scratch")
            local write_also_general = ask.is_trusted("/opt/scratch")
            ask.trust("/opt/read-only")
            local general_only = not ask.is_write_trusted("/opt/read-only")
            local narrow = ask.forget_write("/opt/scratch")
            local narrow_took_write = not ask.is_write_trusted("/opt/scratch")
            local narrow_kept_general = ask.is_trusted("/opt/scratch")
            -- A path that is not there is trusted as a single file, which is
            -- the point: the write a policy asks about is usually the creation
            -- of the file. The narrow reading, so it covers no subtree.
            ask.trust("definitely/not/here")
            local missing_exact = ask.is_trusted("definitely/not/here")
            local missing_child = ask.is_trusted("definitely/not/here/under")
            -- `~` and a relative path resolve to the same entries.
            local home_ok, tilde_ok = true, true
            if os.getenv("HOME") then
              ask.trust("~")
              tilde_ok = ask.is_trusted(os.getenv("HOME"))
            end
            local cwd_ok = true
            if os.getenv("PWD") then
              local here = ask.trust("lua")
              cwd_ok = here:sub(1, 1) == "/" and not here:find("%.%.")
            end
            ask.forget_all()
            local left = #ask.trusted_paths()
            if not inside then return "a file inside the trusted dir" end
            if sibling then return "a sibling sharing the prefix" end
            if not itself then return "the directory itself" end
            if not messy then return "a tidied path inside it" end
            if file_only then return "a trusted file trusted a child path" end
            if not missing_exact then return "the missing path itself" end
            if missing_child then return "a missing path trusted a subtree" end
            if not write_only then return "the write table did not record" end
            if not write_also_general then return "trust_write did not write both" end
            if not general_only then return "general trust implied write trust" end
            if not narrow then return "forget_write reported nothing" end
            if not narrow_took_write then return "forget_write left the write" end
            if not narrow_kept_general then return "forget_write took the general trust" end
            if not tilde_ok then return "a tilde" end
            if not cwd_ok then return "a relative path" end
            if left ~= 0 then return "forget_all left " .. left end
            return nil
        "#,
            )
            .eval()
            .expect("trust walk");
        assert!(problem.is_none(), "trust: {}", problem.unwrap_or_default());
    }

    /// The flag-checking lib, exercised the way a policy uses it: the syscall
    /// table carries flags, and the answer comes from the name.
    #[test]
    fn seccomp_lib_decodes_flags_by_name() {
        let lua = vm();
        let problem: Option<String> = lua
            .load(
                r#"
            local sc = agent.seccomp
            -- openat(dirfd, path, flags): a write open with create + append.
            local sys = { name = "openat", pid = 42, args = { -100, "/tmp/x", 1089 } }
            if not sc.check_sys(sys, "openat", "WRITE") then return "write open" end
            if not sc.check_sys(sys, "openat", { "CREATE", "APPEND" }) then return "creat+append" end
            if sc.check_sys(sys, "openat", "TRUNCATE") then return "truncate" end
            if sc.describes("openat", sc.arg(sys, "openat")) ~= "O_WRONLY|O_CREAT|O_APPEND" then
              return "describes: " .. sc.describes("openat", 1089)
            end
            -- The tty probe is exempt, and named rather than a literal.
            if not sc.is_tty_probe({ name = "openat", args = { -100, "/dev/tty", 2050 } }) then
              return "tty probe"
            end
            if sc.TTY_PROBE_FLAGS ~= 2050 then return "TTY_PROBE_FLAGS" end
            -- Other families go through the same call.
            if not sc.check("access", 6, { "R", "W" }) then return "access rw" end
            if not sc.check("mmap.prot", 5, { "R", "X" }) then return "prot rx" end
            return nil
        "#,
            )
            .eval()
            .expect("seccomp eval");
        assert!(
            problem.is_none(),
            "agent.seccomp: {}",
            problem.unwrap_or_default()
        );
    }

    /// `lua/init.lua` is the one top-level script the loader runs, and it runs
    /// on every VM: the config surface is there without anyone calling a config
    /// helper first. Two halves of it — the settings table `agent.llm` (the entry
    /// script's) and the read-only `agent.llm.usage` counters (the bridge's) — plus
    /// the two names that must *not* come back: `agent.config`, which the
    /// settings table replaced, and `agent.policy`, which never existed as a
    /// namespace.
    #[test]
    fn entry_script_defines_the_config_surface_on_every_vm() {
        let lua = vm();
        let missing: Option<String> = lua
            .load(
                r#"
            local absent = {}
            for name, t in pairs({
              llm = "table", shq = "function",
              on_event = "function", trigger = "function", memory = "table",
            }) do
              if type(agent[name]) ~= t then absent[#absent + 1] = name end
            end
            -- The tool constructor is `agent.utils.tool` now, from
            -- `lua/lib/utils.lua`; the old bare name is not kept alive.
            if type(agent.utils.tool) ~= "function" then absent[#absent+1] = "utils.tool" end
            if agent.tool ~= nil then absent[#absent+1] = "agent.tool exists" end
            if type(agent.memory.flush) ~= "function" then absent[#absent+1] = "memory.flush" end
            -- A sandbox policy is a per-call table, not a namespace: there is
            -- deliberately no `agent.policy` to consult, and nothing may put
            -- one back. Same for the old `agent.config`: the settings table is
            -- `agent.llm` and nothing may keep the old name alive.
            if agent.policy ~= nil then absent[#absent+1] = "agent.policy exists" end
            if agent.config ~= nil then absent[#absent+1] = "agent.config exists" end
            -- The defaults the entry script owns.
            if agent.llm.base_url ~= "https://api.openai.com/v1" then
              return "llm.base_url", nil
            end
            if agent.llm.model ~= "gpt-4o-mini" then return "llm.model", nil end
            if agent.llm.api_key ~= "" then return "llm.api_key", nil end
            -- The script's own default is `""`, but it also activates the
            -- `coding` mode, so what is in force is that mode's prompt. What
            -- matters here is that it is a string the next request can send.
            if type(agent.llm.system_prompt) ~= "string" then
              absent[#absent+1] = "llm.system_prompt"
            end
            if type(agent.llm.memory) ~= "table" then absent[#absent+1] = "llm.memory" end
            -- The read-only counters, and read-only in fact.
            if type(agent.llm.usage.total) ~= "number" then absent[#absent+1] = "llm.usage.total" end
            if type(agent.llm.usage.reported) ~= "boolean" then
              absent[#absent+1] = "llm.usage.reported"
            end
            if pcall(function() agent.llm.usage.total = 1 end) then
              absent[#absent+1] = "agent.llm.usage is writable"
            end
            if #absent > 0 then return table.concat(absent, ","), nil end
            return nil
        "#,
            )
            .eval()
            .expect("entry script eval");
        assert!(
            missing.is_none(),
            "lua/init.lua did not define: {}",
            missing.unwrap_or_default()
        );
    }

    /// The loader's promise about the standard library, asserted so a mlua bump
    /// that narrows the safe subset cannot quietly take it away: the modules the
    /// shipped tree and the docs rely on are there, and the two withheld ones
    /// are the two we expect to be withheld (see [`STDLIB`]).
    #[test]
    fn stdlib_is_available_to_config_policies_and_tools() {
        let lua = vm();
        let report: String = lua
            .load(
                r#"
            local out = {}
            for _, name in ipairs({ "os", "io", "package", "coroutine", "string",
                                    "table", "math" }) do
              out[#out + 1] = name .. "=" .. type(_G[name])
            end
            -- What agent.ask.trust actually uses to resolve and identify a path.
            out[#out + 1] = "os.getenv=" .. type(os.getenv)
            out[#out + 1] = "os.rename=" .. type(os.rename)
            out[#out + 1] = "io.open=" .. type(io.open)
            -- Withheld by the safe subset, on purpose: loading either needs an
            -- unsafe state, which would also re-enable C modules.
            out[#out + 1] = "debug=" .. type(debug)
            out[#out + 1] = "ffi=" .. type(ffi)
            return table.concat(out, " ")
        "#,
            )
            .eval()
            .expect("stdlib probe");
        for module in [
            "os=table",
            "io=table",
            "package=table",
            "coroutine=table",
            "string=table",
            "table=table",
            "math=table",
            "os.getenv=function",
            "os.rename=function",
            "io.open=function",
            "debug=nil",
            "ffi=nil",
        ] {
            assert!(
                report.split(' ').any(|pair| pair == module),
                "stdlib: {module} missing from {report}"
            );
        }
    }

    /// The whole agent namespace now comes from `lua/lib/`, and every module
    /// also resolves by name through the search path — `require("bash")`,
    /// `require("on_timeout")` and friends are the same values `agent.*`
    /// publishes. There is no `driver` module and no `package.preload` entry
    /// left: the tree is the only source.
    #[test]
    fn the_agent_namespace_comes_from_the_lib_tree() {
        let lua = vm();
        let problem: Option<String> = lua
            .load(
                r#"
            -- Nothing of *ours* is preloaded any more: the loader only sets
            -- package.path. (LuaJIT's own stdlib preloads — string.buffer,
            -- jit.util — are still there; we do not touch those.)
            if package.preload["driver"] ~= nil then return "driver is preloaded" end
            if package.loaded["driver"] ~= nil then return "the driver is still loaded" end
            -- Each module is both on `agent` and reachable by name.
            if require("bash").bash ~= agent.bash then return "bash" end
            if require("panel").panel ~= agent.panel then return "panel" end
            if require("http").http ~= agent.http then return "http" end
            if require("mcp") ~= agent.mcp then return "mcp" end
            if require("on_timeout") ~= agent.on_timeout then return "on_timeout" end
            if require("utils") ~= agent.utils then return "utils" end
            if require("seccomp") ~= agent.seccomp then return "seccomp" end
            if require("ask") ~= agent.ask then return "ask" end
            -- The verdicts, the panel helpers, the cooperative wait.
            for _, name in ipairs({ "bash", "deny", "allow", "panel", "split_panel",
                                    "http", "mcp", "on_timeout" }) do
              if type(agent[name]) ~= "function" then return "agent." .. name end
            end
            return nil
        "#,
            )
            .eval()
            .expect("namespace eval");
        assert!(
            problem.is_none(),
            "agent namespace: {}",
            problem.unwrap_or_default()
        );
    }

    /// A name that is in no searcher fails with a name-bearing error (the
    /// standard "module not found" shape), not a silent nil.
    #[test]
    fn require_of_a_missing_module_fails_by_name() {
        let lua = vm();
        let err = lua
            .load(r#"require("no_such_module_xyz")"#)
            .eval::<mlua::Value>()
            .expect_err("require of a missing module must fail");
        let text = err.to_string();
        assert!(
            text.contains("no_such_module_xyz"),
            "error should name the module, got: {text}"
        );
    }

    /// The tree is on the module search path, `lib/` first: `require` finds a
    /// lib module, a top-level module, and a nested one, and the path itself
    /// says so.
    #[test]
    fn the_tree_is_on_the_module_search_path() {
        let lua = vm();
        let (path, ok): (String, bool) = lua
            .load(
                r#"
            local head = {}
            for entry in package.path:gmatch("[^;]+") do head[#head + 1] = entry end
            -- The first four entries are ours: lib/?/?.lua, lib/?/init.lua,
            -- ?/?.lua, ?/init.lua — the original path follows.
            return table.concat(head, ";"), require("utils") == agent.utils
        "#,
            )
            .eval()
            .expect("search path eval");
        let entries: Vec<&str> = path.split(';').collect();
        assert!(
            entries[0].ends_with("lua/lib/?.lua"),
            "lib first in the search path: {path}"
        );
        assert!(
            entries[1].ends_with("lua/lib/?/init.lua"),
            "the ?/init.lua form for a directory module: {path}"
        );
        assert!(
            entries[2].ends_with("lua/?.lua"),
            "the tree root is in the path too: {path}"
        );
        assert!(ok, "require resolves a lib module to the same table");
    }

    /// The lib loader requires modules in **alphabetical** order, so a module
    /// that captures a sibling's `agent.<name>` at load time gets `nil` when the
    /// sibling sorts later. `require("<name>")` is the order-independent way:
    /// it loads the sibling on demand, and the auto-scan's later require is a
    /// cache hit. Pinned here because the difference is silent.
    #[test]
    fn lib_modules_capture_siblings_with_require_not_agent() {
        let dir = fixture("order");
        std::fs::create_dir_all(dir.join("lib")).expect("fixture lib");
        // The sibling under test: publishes itself, and sorts *after* the two
        // modules that capture it.
        std::fs::write(
            dir.join("lib").join("seccomp.lua"),
            "local M = { O = { RDONLY = 0 } }\nagent.seccomp = M\nreturn M",
        )
        .expect("sibling module");
        // "aaa" loads first: agent.seccomp is not there yet.
        std::fs::write(
            dir.join("lib").join("aaa.lua"),
            "local via_agent = agent.seccomp\nlocal via_require = require(\"seccomp\")\n\
             return { via_agent = via_agent, via_require = via_require }",
        )
        .expect("early module");
        // "zzz" loads last, when agent.seccomp *is* there — so both work here,
        // which is exactly why the early one is the trap.
        std::fs::write(
            dir.join("lib").join("zzz.lua"),
            "return { via_agent = agent.seccomp ~= nil }",
        )
        .expect("late module");
        std::fs::copy(tree().join("api.lua"), dir.join("api.lua")).expect("api.lua");
        std::fs::write(dir.join("init.lua"), "agent.api_docs = require(\"api\")\n")
            .expect("init");

        let lua = Lua::new();
        setup_tree(&lua, None, None, &dir, &ConfigSource::Tree).expect("fixture tree setup");
        let problem: Option<String> = lua
            .load(
                r#"
            local early = package.loaded["aaa"]
            if early.via_agent ~= nil then
              return "agent.seccomp was already there for aaa (order changed?)"
            end
            if type(early.via_require) ~= "table" then
              return "require('seccomp') did not load the sibling"
            end
            -- It is the same table the sibling published.
            if early.via_require ~= agent.seccomp then return "different table" end
            if not package.loaded["zzz"].via_agent then return "zzz" end
            return nil
        "#,
            )
            .eval()
            .expect("load-order eval");
        assert!(
            problem.is_none(),
            "lib load order: {}",
            problem.unwrap_or_default()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The "always" flag is Lua's, and it reaches the answer: a question that
    /// carries a path offers the third answer, and the tool is what passes it
    /// across. (That a question *without* a path does not offer it is the
    /// ask-table's own business, pinned in ask's self-test.)
    #[test]
    fn the_always_flag_is_lua_s_and_reaches_the_handler() {
        // The tool runs on the shipped config VM, so the built-in configuration
        // is the source of both the tool and its policy — this VM is here to
        // fail loudly if that configuration ever stops loading.
        let _config = shipped_vm();
        // What the handler was told, per call.
        let seen: Rc<RefCell<Vec<(String, bool)>>> = Rc::new(RefCell::new(Vec::new()));
        let watch = seen.clone();
        let sink = PanelSink::default();
        let run = |args: &str, watch: Rc<RefCell<Vec<(String, bool)>>>| {
            invoke_mcp_tool_with_asks(
                "bash.bash",
                args,
                Some(&sink),
                // Records what it was told and says yes: the default policy asks
                // about every open, so denying the first one would kill the run
                // before it reached the write this is about.
                Some(Rc::new(move |text: &str, always: bool| {
                    watch.borrow_mut().push((text.to_string(), always));
                    AskAnswer::Allow
                })),
                &ConfigSource::Tree,
            )
            .expect("invoke")
        };

        // The shipped policy asks about every open with a path in the question,
        // so the third answer is on offer for each of them.
        let p = std::env::temp_dir().join(format!("ask-flag-{}.txt", std::process::id()));
        // Seeded, so the write is an *overwrite* and therefore still a question.
        // Creating a name nothing holds is deliberately silent (see
        // `creating_a_new_name_is_not_a_question`), and `echo >` on a fresh path
        // would leave this test with no write to inspect.
        std::fs::write(&p, "before\n").expect("seed the target");
        let args = serde_json::json!({
            "cmdline": format!("echo x > {}", p.display()),
        })
        .to_string();
        let _ = run(&args, watch.clone());
        let asked = seen.borrow().clone();
        assert!(!asked.is_empty(), "the opens were asked about: {asked:?}");
        assert!(
            asked.iter().all(|(_, always)| *always),
            "every ask here carries a path, so all of them offer always: {asked:?}"
        );
        // The write is asked about too — it is the last one, because the default
        // policy asks about the program's own libraries before the command runs.
        let asked_about_target = asked
            .iter()
            .any(|(text, _)| text.contains(&p.display().to_string()));
        assert!(
            asked_about_target,
            "and the question for the write names its path: {asked:?}"
        );
        let _ = std::fs::remove_file(&p);

    }

    /// `agent.llm.usage` is the read-only token ledger of the **most recent**
    /// request: the numbers the server reported, refreshed after every turn, and
    /// seeded into every VM from a process-wide snapshot so a tool call and a
    /// `turn_completed` handler see the same counts.
    #[test]
    fn agent_usage_is_the_read_only_count_of_the_last_request() {
        let _usage = usage_guard();
        let lua = vm();

        // Before anything has run: a number, but honestly zero and *reported =
        // false* — "unknown", never a stale figure.
        let start: String = lua
            .load(
                r#"
            return string.format("%s/%s/%s/%s", agent.llm.usage.prompt, agent.llm.usage.completion,
                                 agent.llm.usage.total, tostring(agent.llm.usage.reported))
        "#,
            )
            .eval()
            .expect("usage");
        assert_eq!(start, "0/0/0/false", "nothing has been requested yet");

        // A request that reported both halves: total is their sum, and the
        // counts reach a *new* VM (the process-wide snapshot, not a field on the
        // config VM).
        record_usage(
            &lua,
            Usage {
                prompt: Some(1_200),
                completion: Some(345),
            },
        );
        let seen: String = lua
            .load(
                r#"
            return string.format("%d/%d/%d/%s", agent.llm.usage.prompt, agent.llm.usage.completion,
                                 agent.llm.usage.total, tostring(agent.llm.usage.reported))
        "#,
            )
            .eval()
            .expect("usage after record");
        assert_eq!(seen, "1200/345/1545/true");
        let fresh = new_vm().expect("a fresh VM");
        let seen_elsewhere: i64 = fresh
            .load("return agent.llm.usage.total")
            .eval()
            .expect("usage on another VM");
        assert_eq!(
            seen_elsewhere, 1_545,
            "a tool/event VM is seeded with the same count"
        );

        // One half only: the total is the sum of what *was* reported, and it is
        // still reported.
        record_usage(
            &lua,
            Usage {
                prompt: Some(10),
                completion: None,
            },
        );
        let half: String = lua
            .load("return agent.llm.usage.total .. '/' .. tostring(agent.llm.usage.completion)")
            .eval()
            .expect("partial usage");
        assert_eq!(half, "10/0", "the missing half counts as zero, not unknown");

        // Neither half: back to unknown rather than a stale number.
        record_usage(&lua, Usage::default());
        let none: String = lua
            .load("return agent.llm.usage.total .. '/' .. tostring(agent.llm.usage.reported)")
            .eval()
            .expect("no usage");
        assert_eq!(none, "0/false", "a server that says nothing leaves no stale total");

        // Read-only in fact: every field refuses a write, and says so.
        let refused: Option<String> = lua
            .load(
                r#"
            for _, k in ipairs({ "total", "prompt", "completion", "reported" }) do
              if pcall(function() agent.llm.usage[k] = 1 end) then return "writable: " .. k end
            end
            local ok, err = pcall(function() agent.llm.usage.total = 1 end)
            if not tostring(err):find("read%-only") then return "unclear: " .. tostring(err) end
            return nil
        "#,
            )
            .eval()
            .expect("read-only probe");
        assert!(
            refused.is_none(),
            "agent.llm.usage accepted a write: {}",
            refused.unwrap_or_default()
        );

        // The `usage` key is an ordinary key on `agent.llm`, so a stray
        // assignment can replace the proxy — but the property does not outlive
        // it. The next recording puts a locked table back, numbers included, and
        // so does a `/reload` (a config that replaced the whole `agent.llm`
        // would otherwise leave the surface incomplete until a request ran).
        lua.load("agent.llm.usage = { total = 999 }")
            .exec()
            .expect("replace the key");
        assert_eq!(
            lua.load("return agent.llm.usage.total")
                .eval::<i64>()
                .expect("after replace"),
            999,
            "the stray table is what Lua holds until the next request"
        );
        record_usage(&lua, Usage { prompt: Some(7), completion: None });
        let restored: String = lua
            .load("return agent.llm.usage.total .. '/' .. tostring(agent.llm.usage.reported)")
            .eval()
            .expect("restored");
        assert_eq!(restored, "7/true", "the next recording restores the lock");

        // And a config that replaces `agent.llm` wholesale: `/reload` re-seats
        // the counters, the endpoint keeps the user's values.
        apply_config_source(
            &lua,
            r#"
            agent.llm = { base_url = "http://kept/v1", model = "m", api_key = "" }
            "#,
        )
        .expect("a config that replaces the table");
        let after_reload: String = lua
            .load("return agent.llm.usage.total .. '/' .. agent.llm.base_url")
            .eval()
            .expect("after reload");
        assert_eq!(after_reload, "7/http://kept/v1", "reload re-seats the counters");
    }

    /// The rename is a rename: `agent.llm` is the settings table — the endpoint
    /// fields flat, beside the system prompt, the log settings, and the
    /// read-only token counters — and the old `agent.config` is gone rather than
    /// left behind as a second source of truth (a stale
    /// `agent.config.system_prompt` that silently did nothing would be worse
    /// than a loud failure).
    #[test]
    fn the_settings_table_is_agent_llm_and_the_old_name_is_gone() {
        let lua = shipped_vm();
        let problem: Option<String> = lua
            .load(
                r#"
            if agent.config ~= nil then return "agent.config still exists" end
            -- One table, flat: the endpoint fields are not nested under `llm`.
            if type(agent.llm.base_url) ~= "string" then return "base_url" end
            if type(agent.llm.model) ~= "string" then return "model" end
            if type(agent.llm.api_key) ~= "string" then return "api_key" end
            if type(agent.llm.system_prompt) ~= "string" then return "system_prompt" end
            if type(agent.llm.memory) ~= "table" then return "memory" end
            -- `false` is the "not configured" default, and is deliberately not
            -- a number: compaction is off until the user says what the window
            -- is, because a guessed one compacts at the wrong moment.
            if agent.llm.context_size ~= false then return "context_size" end
            if agent.llm.llm ~= nil then return "llm.llm" end
            -- And Rust reads it from there.
            local names = {}
            for name, _ in pairs(agent.llm) do names[#names + 1] = name end
            table.sort(names)
            return table.concat(names, ",")
        "#,
            )
            .eval()
            .expect("settings shape");
        assert_eq!(
            problem.as_deref(),
            Some("api_key,base_url,context_size,memory,model,system_prompt,usage"),
            "the settings table is flat and complete: every key the starter \
             config defines, plus the read-only counters"
        );
        assert_eq!(
            llm_config(&lua).expect("llm config").model,
            "gpt-4o-mini",
            "and Rust reads the endpoint from agent.llm — the entry script's default, \
             with no user config in the tree to override it"
        );
        assert!(
            system_prompt(&lua).expect("prompt").contains("coding agent"),
            "as well as the system prompt — the `coding` mode's, which the entry \
             script activates by default"
        );
    }

    /// The automatic compaction turn, driven on the real config VM — the VM the
    /// loop reads the prompt and the registry from, which is what makes a
    /// handler's mode switch reach the next turn (see [`EventRun::start`]).
    ///
    /// The trigger is a process-wide channel to the TUI's loop, so the "loop"
    /// here is a Lua stub: `agent.trigger` is a plain function on `agent`, and
    /// the handler calls it by name at call time, so replacing it records what
    /// the handler queued. That tests the handler's actual contract — what it
    /// does to the live config, and what it asks the loop for — without owning
    /// the one process-wide channel (see
    /// `trigger_queues_run_turn_commands_on_the_bound_channel`).
    #[test]
    fn context_pressure_arms_a_compaction_turn_and_lands_its_summary() {
        let _usage = usage_guard();
        // `new_vm` is the whole configuration now: one script, not two.
        let lua = new_vm().expect("VM");
        // A context window to measure against, and a mode with something to
        // switch away from.
        lua.load(
            r#"
            agent.llm.context_size = 20000
            agent.mode.new("work", {
              system_prompt = "WORK PROMPT",
              mcps = { fs = { name = "fs", tools = { read = true } } },
            })
            agent.mode.set("work")
            -- Stand in for the TUI's loop: record what the handler asks for.
            QUEUED = {}
            agent.trigger = function(a)
              QUEUED[#QUEUED + 1] = a
              return true     -- a bound loop accepts it
            end
        "#,
        )
        .exec()
        .expect("configure");
        let compact_prompt = mode_prompt(&lua, "compact");

        // A turn with room to spare: the handler does nothing.
        record_usage(&lua, Usage { prompt: Some(1_000), completion: Some(50) });
        // Eight messages, so cutting a 6-message tail actually drops something.
        let mut history: Vec<serde_json::Value> = (1..=4)
            .flat_map(|i| {
                [
                    json!({ "role": "user", "content": format!("ask {i}") }),
                    json!({ "role": "assistant", "content": format!("reply {i}") }),
                ]
            })
            .collect();
        let before = history.clone();
        assert!(fire_event_on_vm(&lua, "turn_completed", &json!({ "history": history })).expect("fire"));
        assert_eq!(queued(&lua).len(), 0, "plenty of room: nothing queued");
        assert_eq!(mode_current(&lua).as_deref(), Some("work"), "mode kept");
        assert_eq!(history, before, "and the conversation is untouched");
        lua.load("QUEUED = {}").exec().expect("reset the queue");

        // Context pressure (20000 - 9000 = 11000 < 15000 headroom): the handler
        // arms, switches to compact, and asks for a summary — on the VM the next
        // turn reads.
        record_usage(&lua, Usage { prompt: Some(9_000), completion: Some(50) });
        assert!(fire_event_on_vm(&lua, "turn_completed", &json!({ "history": history })).expect("fire"));
        let asked = queued(&lua);
        assert_eq!(asked.len(), 1, "one queued command: {asked:?}");
        assert!(
            asked[0].as_str().is_some_and(|u| u.contains("Compact")),
            "it asks for the summary as a user turn: {asked:?}"
        );
        assert_eq!(
            mode_current(&lua).as_deref(),
            Some("compact"),
            "the agent is in compact mode for the very next turn"
        );
        assert_eq!(
            system_prompt(&lua).expect("prompt"),
            compact_prompt,
            "which carries the compaction brief"
        );
        assert!(
            mcps_tool_defs(&lua).expect("defs").is_empty(),
            "and a compaction turn is offered no tools"
        );

        // The compaction turn runs and answers: the ask, then the summary. That
        // completion is the second event, and it is what must not re-arm (this
        // request carried the whole history too).
        lua.load("QUEUED = {}").exec().expect("reset the queue");
        let summary = "## Task\nship the feature\n\n## Next\nwrite the code";
        let mark = history.len();
        history.push(json!({ "role": "user", "content": "Compact the conversation now…" }));
        history.push(json!({ "role": "assistant", "content": summary }));
        assert!(
            fire_event_on_vm(&lua, "turn_completed", &json!({ "history": history })).expect("fire"),
            "the summary's own completion"
        );
        let replaced = queued(&lua);
        assert_eq!(replaced.len(), 1, "the replacement history is queued: {replaced:?}");
        let m = replaced[0].as_array().expect("a replacement history, not a message");
        assert_eq!(m[0]["role"], "system", "the summary leads the new history");
        assert_eq!(m[0]["content"], summary);
        assert_eq!(
            m.len(),
            1 + 6,
            "the summary plus a 6-message tail: {m:?}"
        );
        assert_eq!(
            &m[1..],
            &before[mark - 6..mark],
            "the tail is the last COMPACT_KEEP messages from *before* the \
             compaction turn, verbatim"
        );
        assert!(
            !m[1..].iter().any(|msg| msg["content"] == summary),
            "and the summary does not appear in the tail as well: {m:?}"
        );
        assert_eq!(
            mode_current(&lua).as_deref(),
            Some("work"),
            "the mode that was in force is back"
        );
        assert_eq!(
            system_prompt(&lua).expect("prompt"),
            "WORK PROMPT",
            "so the turn this starts runs in the restored mode"
        );

        // And it settles: the compacted history is small, so one more event
        // queues nothing — no compaction loop.
        lua.load("QUEUED = {}").exec().expect("reset the queue");
        record_usage(&lua, Usage { prompt: Some(300), completion: Some(20) });
        assert!(fire_event_on_vm(&lua, "turn_completed", &json!({ "history": m })).expect("fire"));
        assert_eq!(queued(&lua).len(), 0, "a compacted conversation does not re-trigger");
    }

    /// Without a context window there is no headroom to measure, so the
    /// automatic turn stays off — a wrong guess at a window would compact at the
    /// wrong moment, so "not configured" must mean "off", not "always".
    #[test]
    fn compaction_is_off_without_a_context_size() {
        let _usage = usage_guard();
        let lua = shipped_vm();
        lua.load("QUEUED = {}; agent.trigger = function(a) QUEUED[#QUEUED+1] = a; return true end")
            .exec()
            .expect("stub the loop");
        // A usage far past any plausible window, and no `context_size` set.
        record_usage(
            &lua,
            Usage {
                prompt: Some(1_000_000),
                completion: Some(1),
            },
        );
        assert!(
            fire_event_on_vm(&lua, "turn_completed", &json!({ "history": [] })).expect("fire"),
            "the handler is registered"
        );
        assert_eq!(queued(&lua).len(), 0, "no window, no automatic compaction");
        // The shipped config starts in the `coding` mode, so a mode *is* in
        // force — what matters here is that compaction did not switch one itself.
        assert_eq!(
            mode_current(&lua).as_deref(),
            Some("coding"),
            "and the only mode in force is the one the config started in"
        );
    }

    /// A handler can still suspend across the wait it asks for, on the shared
    /// VM: `agent.on_timeout` yields, the reactor resumes the *same* coroutine,
    /// and everything it had — locals and the config it changed — is still there.
    #[test]
    fn a_handler_may_yield_on_the_shared_vm_and_keep_its_state() {
        // `new_vm` is the whole configuration now: one script, not two.
        let lua = new_vm().expect("VM");
        lua.load(
            r#"
            agent.llm.system_prompt = "BEFORE THE WAIT"
            local seen = {}
            agent.on_event("turn_completed", function(info)
              seen[#seen + 1] = "start"
              agent.on_timeout(5)
              -- Resumed: the locals and the config both survived.
              seen[#seen + 1] = agent.llm.system_prompt
              agent.llm.system_prompt = "AFTER THE WAIT"
              seen[#seen + 1] = "end"
            end)
        "#,
        )
        .exec()
        .expect("register the waiting handler");

        let payload = json!({ "history": [] });
        let (mut run, step) = EventRun::start(&lua, "turn_completed", &payload)
            .expect("start")
            .expect("a handler is registered");
        assert!(
            matches!(step, EventStep::Waiting { .. }),
            "the handler suspended on its timer, as the reactor expects"
        );
        // The loop keeps running while it waits: the config it wrote before the
        // wait is readable, and the handler is mid-flight.
        assert_eq!(system_prompt(&lua).expect("prompt"), "BEFORE THE WAIT");
        let step = run.step().expect("resume on the timer");
        assert!(matches!(step, EventStep::Returned), "and then it finished");
        assert_eq!(
            system_prompt(&lua).expect("prompt"),
            "AFTER THE WAIT",
            "a write made after the wait lands on the live config"
        );
    }

    /// Read `agent.mode.current()`.
    fn mode_current(lua: &mlua::Lua) -> Option<String> {
        lua.load("return agent.mode.current()")
            .eval()
            .expect("current mode")
    }

    /// A registered mode's system prompt.
    fn mode_prompt(lua: &mlua::Lua, name: &str) -> String {
        lua.load(format!("return agent.mode.get({name:?}).system_prompt"))
            .eval()
            .expect("mode prompt")
    }

    /// What the stubbed `agent.trigger` recorded. An empty Lua table encodes as
    /// `{}` as readily as `[]`, so a non-array reads as "nothing queued".
    fn queued(lua: &mlua::Lua) -> Vec<serde_json::Value> {
        let json: String = lua
            .load("return agent.api.json_encode(QUEUED)")
            .eval()
            .expect("queued commands");
        match serde_json::from_str(&json).expect("queued json") {
            serde_json::Value::Array(items) => items,
            other => {
                assert_eq!(other, serde_json::json!({}), "queued shape");
                Vec::new()
            }
        }
    }

    /// The shipped `compact` mode: a spec that swaps the prompt for a compaction
    /// brief and the registry for *nothing*. "Disable all tools" has to mean all
    /// of them — including the shell, which only counts as a tool because the
    /// configuration registered it — and it has to be true at the tool-dispatch
    /// level, not merely in the advertised list.
    #[test]
    fn the_compact_mode_takes_every_tool_away() {
        let lua = shipped_vm();
        // The shipped config starts in the `coding` mode, so clear to the baseline
        // first: "the baseline" here means what `agent.mode.set()` restores, and
        // that is not the state the config left the VM in.
        lua.load("agent.mode.set()").exec().expect("clear to the baseline");
        let baseline = system_prompt(&lua).expect("baseline prompt");

        // Registered but inert: the baseline is untouched.
        let names: String = lua
            .load(r#"return table.concat(agent.mode.names(), ",")"#)
            .eval()
            .expect("mode names");
        assert!(
            names.split(',').any(|n| n == "compact"),
            "the shipped config registers the compact mode, got {names:?}"
        );
        assert_eq!(
            system_prompt(&lua).expect("baseline prompt"),
            baseline,
            "registering a mode does not switch to it"
        );
        let defs = mcps_tool_defs(&lua).expect("baseline defs");
        assert!(
            defs.iter().any(|d| d.name == "bash.bash"),
            "the shell is there before the switch"
        );

        lua.load(r#"agent.mode.set("compact")"#)
            .exec()
            .expect("switch");

        // The prompt half: Rust reads it per request, so the *next* request
        // carries it.
        let prompt = system_prompt(&lua).expect("compact prompt");
        assert_ne!(prompt, baseline, "the mode's prompt is in force");
        for section in ["## Task", "## Done", "## State", "## Next"] {
            assert!(
                prompt.contains(section),
                "the brief asks for {section}: {prompt}"
            );
        }
        assert!(
            prompt.contains("no tools"),
            "and says so: {}",
            prompt.lines().next().unwrap_or_default()
        );

        // The tool half: the catalog is empty, and a call is not merely
        // un-advertised — the dispatcher has nothing to run it with.
        assert!(
            mcps_tool_defs(&lua).expect("compact defs").is_empty(),
            "a compaction turn is offered no tools"
        );
        // Note the *other* half of "not offered": a tool is called by name
        // against the live registry, so a dropped tool is not callable only
        // because the loop refuses any name the request did not offer —
        // `main::may_run`, asserted there. What this layer guarantees is the
        // catalog: nothing to choose from, and nothing to call.

        // And back: both halves of the baseline return, shell included.
        lua.load("agent.mode.set()").exec().expect("clear");
        assert_eq!(
            system_prompt(&lua).expect("restored prompt"),
            baseline
        );
        let defs = mcps_tool_defs(&lua).expect("restored defs");
        let mut names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            ["bash.bash", "fs.apply_patch", "fs.hand_to_user", "fs.read", "fs.write_file"],
            "clearing the mode gives the tools back"
        );
    }

    /// The compact spec is a *table*, not a side effect: requiring it registers
    /// nothing, so `agent.mode.new("compact", require("compact"))` is the whole
    /// setup and a spec can be inspected, copied, or composed before it is
    /// named. A `require` that quietly switched modes would make the setup line
    /// mean two things.
    #[test]
    fn the_compact_spec_is_inert_until_it_is_named() {
        let lua = shipped_vm();
        // The shipped config starts in the `coding` mode, so clear to the baseline
        // first: "the baseline" here means what `agent.mode.set()` restores, and
        // that is not the state the config left the VM in.
        lua.load("agent.mode.set()").exec().expect("clear to the baseline");
        let baseline = system_prompt(&lua).expect("prompt");
        let spec: String = lua
            .load(
                r#"
            local spec = require("compact")
            if agent.mode.current() ~= nil then return "a require switched modes" end
            if type(spec.system_prompt) ~= "string" or spec.system_prompt == "" then
              return "no prompt"
            end
            if type(spec.mcps) ~= "table" or next(spec.mcps) ~= nil then
              return "the registry is not empty"
            end
            if type(spec.description) ~= "string" then return "no description" end
            -- The same table every time: one spec, many possible names.
            if require("compact") ~= spec then return "require re-ran it" end
            return spec.description
        "#,
            )
            .eval()
            .expect("compact spec");
        assert!(spec.contains("compact"), "{spec}");
        assert_eq!(
            system_prompt(&lua).expect("prompt"),
            baseline,
            "and the baseline prompt never moved"
        );
    }

    // -----------------------------------------------------------------------
    // The `bash` tool, as a connection: `lua/bash_tool.lua` + `lua/policy.lua`
    // are what the built-in ToolDef used to be, and every assertion here is
    // about the *shipped* path — the registry advertises it, the MCP reply is
    // well-formed, and the panel/ask seam behaves. (The engine contract under
    // `agent.bash` itself is pinned by the `run_bash` tests above.)
    // -----------------------------------------------------------------------

    /// An ask handler that says yes to everything. The default policy asks about
    /// every open and every endpoint, so a test that is about the *tool* — its
    /// result shape, its panels, an exit status — needs a user who answers, or it
    /// measures the policy instead. A test about the policy itself passes `None`
    /// and gets the headless auto-deny.
    fn allow_all() -> Option<AskHandler> {
        Some(Rc::new(|_: &str, _: bool| AskAnswer::Allow))
    }

    /// Call the shipped `bash` tool the way the TUI does: on the shipped
    /// config VM, with the round's panel sink and the call's ask handler.
    /// Returns the tool's JSON body.
    fn call_bash(args: &str, sink: &PanelSink, on_ask: Option<AskHandler>) -> serde_json::Value {
        let (body, _) = invoke_mcp_tool_with_asks("bash.bash", args, Some(sink), on_ask, &ConfigSource::Tree)
            .expect("invoke bash")
            .expect("the shipped config registers agent.mcps.bash");
        serde_json::from_str(&body).expect("tool json")
    }

    /// The shell is a registered connection, advertised like every other tool —
    /// and it is the *only* built-in-looking thing in the catalog, because there
    /// are no built-ins.
    #[test]
    fn the_bash_tool_is_an_ordinary_registered_tool() {
        let lua = shipped_vm();
        let defs = mcps_tool_defs(&lua).expect("reindex");
        let mut names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            ["bash.bash", "fs.apply_patch", "fs.hand_to_user", "fs.read", "fs.write_file"],
            "the shell is advertised because the config registered it, nothing else is"
        );
        let def = defs
            .into_iter()
            .find(|d| d.name == "bash.bash")
            .expect("bash.bash def");
        assert!(
            def.description.contains("seccomp sandbox"),
            "the tool describes itself: {}",
            def.description
        );
        let required: Vec<String> = serde_json::from_value(def.parameters["required"].clone())
            .expect("required is a list");
        assert_eq!(required, ["cmdline"], "cmdline is required");
    }

    #[test]
    fn the_bash_tool_runs_a_command_and_reports_the_outcome() {
        let sink = PanelSink::default();
        let v = call_bash(r#"{"cmdline":"echo from the lua tool"}"#, &sink, allow_all());
        assert_eq!(v["ok"], true, "a run that completes is ok: {v}");
        assert_eq!(v["result"]["stdout"], "from the lua tool\n");
        assert_eq!(v["result"]["stderr"], "");
        assert_eq!(v["result"]["exit_code"], 0);
        assert!(v["result"]["exit_signal"].is_null(), "no signal on a clean exit");
        // No `syscalls` field: a raw total of every trapped call said nothing
        // about the command, and `denied` is the number a reader can act on.
        assert!(
            v["result"].get("syscalls").is_none(),
            "the syscall total is gone: {v}"
        );
        assert_eq!(v["result"]["denied"], 0);
        assert!(v["result"]["denied_reason"].is_null());

        // A non-zero exit is still a completed run: `ok` means "the tool ran",
        // and the status is in the result for the model to read.
        let v = call_bash(r#"{"cmdline":"exit 3"}"#, &sink, allow_all());
        assert_eq!(v["ok"], true, "a failing command is not a tool failure: {v}");
        assert_eq!(v["result"]["exit_code"], 3);
    }

    #[test]
    fn the_bash_tool_rejects_a_missing_cmdline() {
        let sink = PanelSink::default();
        // Never a sandboxed run: a bad argument is the tool's own error.
        let v = call_bash("{}", &sink, None);
        assert_eq!(v["ok"], false, "{v}");
        assert!(
            v["error"].as_str().unwrap_or_default().contains("cmdline"),
            "the error names the argument: {v}"
        );
        assert!(sink.ops().is_empty(), "no run, so no panel: {:?}", sink.ops());
    }

    /// Headless, the shipped policy's ask auto-denies, so the shell stays
    /// read-only: the write-open fails, the file is never created, and the reply
    /// says the tool did not complete.
    #[test]
    fn the_bash_tool_blocks_write_opens_headless() {
        let sink = PanelSink::default();
        for p in ["/tmp/agent-lua-bash-w", "/tmp/agent-lua-bash-rw"] {
            let _ = std::fs::remove_file(p);
        }
        for (cmdline, path) in [
            ("echo w > /tmp/agent-lua-bash-w; echo past", "/tmp/agent-lua-bash-w"),
            (
                "exec 3<>/tmp/agent-lua-bash-rw; echo past",
                "/tmp/agent-lua-bash-rw",
            ),
        ] {
            let v = call_bash(
                &serde_json::json!({ "cmdline": cmdline }).to_string(),
                &sink,
                None,
            );
            assert_eq!(v["ok"], false, "the write was refused: {v}");
            assert!(
                v["result"]["denied"].as_u64().unwrap() >= 1,
                "the denied counter moved: {cmdline}: {v}"
            );
            assert!(
                v["error"].as_str().unwrap_or_default().starts_with("denied:"),
                "the error says why: {v}"
            );
            // A reasonless denial invents no reason.
            assert!(
                v["result"]["denied_reason"].is_null(),
                "an ask-denial carries no reason: {cmdline}: {v}"
            );
            assert!(
                !std::path::Path::new(path).exists(),
                "a denied open must not create {path}"
            );
            assert!(
                !v["result"]["stdout"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("past"),
                "the tracee dies before the echo after a denied open"
            );
        }
    }

    #[test]
    fn the_bash_tool_streams_stdout_into_a_result_panel() {
        // The round's sink flows through the tool's VM into the Lua driver: the
        // panel is created before the sandbox spawns, each stdout chunk is
        // appended as it arrives, and a status line finishes it.
        let sink = PanelSink::default();
        let v = call_bash(r#"{"cmdline":"echo from sandbox"}"#, &sink, allow_all());
        assert_eq!(v["ok"], true, "{v}");
        let ops = sink.ops();
        let PanelOp::Create {
            id,
            title,
            boxed,
            conceal_box,
        } = &ops[0]
        else {
            panic!("expected Create first, got {:?}", ops[0]);
        };
        assert_eq!(*id, 1);
        assert_eq!(title, "echo from sandbox", "the command is the title");
        assert!(*boxed && !*conceal_box, "a raw tool-style box, {ops:?}");
        let mut streamed = String::new();
        for op in &ops[1..] {
            match op {
                PanelOp::Append { id, text } => {
                    assert_eq!(*id, 1, "all appends target the stream panel");
                    streamed.push_str(text);
                }
                // The overlay an ask sets and clears, interleaved with the
                // stream. The default policy asks about every open, so a run that
                // needs a library has one; the overlay seam itself is pinned by
                // `the_bash_tool_panels_a_denial`.
                PanelOp::Overlay { id, .. } => assert_eq!(*id, 1, "the overlay is the same panel"),
                other => panic!("expected Append or Overlay, got {other:?}"),
            }
        }
        assert_eq!(
            streamed, "from sandbox\nexited with exit code 0",
            "the stream plus its status line"
        );
    }

    /// The title is one row, so a command with newlines or runs of whitespace
    /// in it is flattened — otherwise a multi-line command would break the top
    /// border of its own box. The renderer cuts a title that is still too wide.
    #[test]
    fn the_bash_tool_titles_its_panel_with_one_line_of_the_command() {
        let cases = [
            (r#"{"cmdline":"echo a && echo b"}"#, "echo a && echo b"),
            (r#"{"cmdline":"echo a\n\necho b"}"#, "echo a echo b"),
            (r#"{"cmdline":"  echo\ta  "}"#, "echo a"),
            (r#"{"cmdline":"for i in 1 2 3; do echo $i; done"}"#, "for i in 1 2 3; do echo $i; done"),
        ];
        for (args, want) in cases {
            let sink = PanelSink::default();
            let v = call_bash(args, &sink, allow_all());
            assert_eq!(v["ok"], true, "{args}: {v}");
            let ops = sink.ops();
            let Some(PanelOp::Create { title, .. }) = ops.first() else {
                panic!("{args}: expected a Create first");
            };
            assert_eq!(title, want, "{args}");
            assert!(
                !title.contains('\n') && !title.contains('\r'),
                "a title is one row: {title:?}"
            );
        }
    }

    /// A denied run streams whatever arrived before the kill (often nothing) and
    /// appends "Denied" instead of an exit line. The ask it raises is drawn by
    /// the event loop, not by the tool.
    #[test]
    fn the_bash_tool_panels_a_denial() {
        let _ = std::fs::remove_file("/tmp/agent-lua-bash-panel-deny");
        let sink = PanelSink::default();
        let v = call_bash(
            r#"{"cmdline":"exec 3<>/tmp/agent-lua-bash-panel-deny; echo past"}"#,
            &sink,
            None,
        );
        assert!(v["result"]["denied"].as_u64().unwrap() >= 1, "open denied");
        assert!(
            !v["result"]["stdout"].as_str().unwrap_or_default().contains("past"),
            "the tracee dies before the echo"
        );
        let _ = std::fs::remove_file("/tmp/agent-lua-bash-panel-deny");

        let ops = sink.ops();
        let mut streamed = String::new();
        for op in &ops {
            if let PanelOp::Append { text, .. } = op {
                streamed.push_str(text);
            }
        }
        assert_eq!(streamed, "Denied", "a denied run appends its status line");

        // The dialog is the tool's own, on the panel the command is running in:
        // `p:ask` sets it, waits, and clears it, so the question appears inside
        // the run's box and leaves when the verdict lands. The driver draws
        // nothing and adds no message of its own.
        let dialogs: Vec<&PanelOp> = ops
            .iter()
            .filter(|op| matches!(op, PanelOp::Overlay { .. }))
            .collect();
        assert_eq!(dialogs.len(), 2, "asked, then cleared: {ops:?}");
        let PanelOp::Overlay { id, text, always } = dialogs[0] else {
            unreachable!("filtered above");
        };
        assert_eq!(*id, 1, "on the command's own panel, not another message");
        let desc = text.as_deref().unwrap_or_default();
        assert!(
            desc.contains("The process want to") && desc.contains('/'),
            "the dialog shows the question and the path it is about: {desc:?}"
        );
        assert!(*always, "a path can be remembered, so `always` is offered");
        let PanelOp::Overlay { text, .. } = dialogs[1] else {
            unreachable!("filtered above");
        };
        assert!(text.is_none(), "and it clears once the verdict lands");
    }

    /// The interactive path: the call's ask handler decides each frozen syscall.
    /// Allowing the write lets the command finish and create its file; denying
    /// it reproduces the headless outcome — and a denial that names a reason
    /// carries it all the way into the tool JSON and the panel status line.
    #[test]
    fn the_bash_tool_routes_ask_verdicts() {
        let _ = std::fs::remove_file("/tmp/agent-lua-bash-allow");
        let allow_sink = PanelSink::default();
        let v = call_bash(
            r#"{"cmdline":"echo written > /tmp/agent-lua-bash-allow"}"#,
            &allow_sink,
            Some(Rc::new(|_, _always: bool| AskAnswer::Allow)),
        );
        assert_eq!(v["ok"], true, "an allowed write completes: {v}");
        assert_eq!(v["result"]["denied"], 0);
        assert!(
            std::path::Path::new("/tmp/agent-lua-bash-allow").exists(),
            "the allowed open created the file"
        );
        assert!(
            v["result"]["stdout"].as_str().unwrap().is_empty(),
            "the echo went to the file, not stdout: {v}"
        );

        let _ = std::fs::remove_file("/tmp/agent-lua-bash-deny");
        let deny_sink = PanelSink::default();
        let v = call_bash(
            r#"{"cmdline":"exec 3<>/tmp/agent-lua-bash-deny; echo past"}"#,
            &deny_sink,
            Some(Rc::new(|_, _always: bool| AskAnswer::Deny(Some("user refused".to_string())))),
        );
        assert_eq!(v["ok"], false, "a refused write is not ok: {v}");
        assert_eq!(v["result"]["denied_reason"], "user refused");
        assert!(
            v["error"].as_str().unwrap_or_default().contains("user refused"),
            "the reply carries the reason: {v}"
        );
        assert!(
            !std::path::Path::new("/tmp/agent-lua-bash-deny").exists(),
            "a denied open must not create the file"
        );
        // The status line names the reason too.
        let streamed: String = deny_sink
            .ops()
            .iter()
            .filter_map(|op| match op {
                PanelOp::Append { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(streamed, "Denied: user refused");
        let _ = std::fs::remove_file("/tmp/agent-lua-bash-allow");
        let _ = std::fs::remove_file("/tmp/agent-lua-bash-deny");
    }

    /// The file tools ask, and the question names the path the agent is really
    /// about — including where that came from when the model wrote something
    /// else. A relative path is resolved before the user is asked, so the
    /// question is answerable: "allow writing this" means nothing if the user
    /// cannot see which file.
    #[test]
    fn the_file_tools_ask_about_the_resolved_path() {
        let dir = std::env::temp_dir().join(format!("agent-fs-ask-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let target = dir.join("notes.txt");
        std::fs::write(&target, "x\n").expect("seed");
        let path = target.to_string_lossy().to_string();

        // A model that writes an absolute path: asked about exactly that.
        let (v, asked) = tool_allowed("fs.read", &serde_json::json!({ "path": &path }).to_string());
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(asked, vec![format!("Allow read {path}")], "the whole question");

        // A path the model wrote that is not the path it means: the question
        // carries the resolved one and says where it came from. The spelling here
        // is untidy rather than relative — it resolves to the *same* file through
        // a `..` — because the working directory is trusted by `lua/init.lua`, and
        // a relative path would resolve inside it and never be asked about at all.
        // (Which is the grant working, not a gap in it.)
        let untidy = format!(
            "{}/./agent-fs-ask-{}/../agent-fs-ask-{}/notes.txt",
            std::env::temp_dir().display(),
            std::process::id(),
            std::process::id()
        );
        let (v, asked) =
            tool_allowed("fs.read", &serde_json::json!({ "path": &untidy }).to_string());
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(
            asked,
            vec![format!("Allow read {path}, which is the symlink of {untidy}")],
            "resolved, and the model's own spelling named"
        );

        // A write asks the write question about the same resolved path.
        let (v, asked) = tool_allowed(
            "fs.write_file",
            &serde_json::json!({ "path": &path, "content": "y\n" }).to_string(),
        );
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(asked, vec![format!("Allow write {path}")], "a write asks about writing");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "y\n", "and it wrote");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `read` names the file it read, and shows nothing else.
    ///
    /// The withheld half is the point. A tool call puts nothing in the
    /// transcript, so this panel is the *only* trace of the read — and it is
    /// still not the file. The content is the model's to have; printing it here
    /// too would put every read back on screen a second time, which is the
    /// duplication the per-call result boxes were removed for.
    #[test]
    fn read_names_the_path_and_withholds_the_content() {
        let dir = std::env::temp_dir().join(format!("agent-fs-read-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let target = dir.join("secret.txt");
        // Distinctive enough that finding it in a panel op would be unambiguous.
        std::fs::write(&target, "CANARY-LINE-ONE\nCANARY-LINE-TWO\n").expect("seed");
        let path = target.to_string_lossy().to_string();

        let sink = PanelSink::default();
        let (body, _) = invoke_mcp_tool_with_asks(
            "fs.read",
            &serde_json::json!({ "path": &path }).to_string(),
            Some(&sink),
            Some(Rc::new(|_: &str, _: bool| AskAnswer::Allow)),
            &ConfigSource::Tree,
        )
        .expect("invoke")
        .expect("the shipped config registers fs.read");

        // The model still gets the file, in full — this is a panel, not a
        // truncation of the tool's result.
        assert!(
            body.contains("CANARY-LINE-ONE") && body.contains("CANARY-LINE-TWO"),
            "the model reads the whole file: {body}"
        );

        let drawn: Vec<String> = sink
            .ops()
            .iter()
            .map(|op| match op {
                PanelOp::Create { title, .. } => format!("┌─ {title}"),
                PanelOp::Append { text, .. } => text.clone(),
                _ => String::new(),
            })
            .collect();
        let panel = drawn.join("\n");
        assert!(
            panel.contains("┌─ fs.read"),
            "titled like every other tool panel: {panel:?}"
        );
        assert!(
            panel.contains(&path),
            "and it names the path: {panel:?}"
        );
        assert!(
            !panel.contains("CANARY"),
            "and shows none of the content: {panel:?}"
        );
        // One line, because the path the model wrote *is* the path. The second
        // line is for when it is not — see the untidy case below.
        // Only the title and the text ops: the overlay ops that put the
        // question up and take it down are not part of what the panel says.
        let body_lines: Vec<&String> = drawn
            .iter()
            .filter(|l| !l.starts_with('┌') && !l.is_empty())
            .collect();
        assert_eq!(
            body_lines,
            vec![&format!("{path}\n")],
            "exactly the resolved path, and nothing else: {panel:?}"
        );

        // A path that is not the one it means: both are shown, because a panel
        // naming only the resolved one would leave the model looking at a file
        // it never wrote, and the *question* already names the other.
        let untidy = format!(
            "{}/./agent-fs-read-{}/../agent-fs-read-{}/secret.txt",
            std::env::temp_dir().display(),
            std::process::id(),
            std::process::id()
        );
        let usink = PanelSink::default();
        invoke_mcp_tool_with_asks(
            "fs.read",
            &serde_json::json!({ "path": &untidy }).to_string(),
            Some(&usink),
            Some(Rc::new(|_: &str, _: bool| AskAnswer::Allow)),
            &ConfigSource::Tree,
        )
        .expect("invoke")
        .expect("registered");
        let ubody: String = usink
            .ops()
            .iter()
            .filter_map(|op| match op {
                PanelOp::Append { text, .. } => Some(text.clone()),
                _ => None,
            })
            .collect();
        assert!(
            ubody.contains(&path) && ubody.contains(&untidy),
            "both paths when they differ: {ubody:?}"
        );
        assert!(
            ubody.contains("which is the symlink of"),
            "and it says which is which: {ubody:?}"
        );

        // The path is the whole of it: one panel, no line numbers, no envelope.
        assert_eq!(
            drawn
                .iter()
                .filter(|l| l.starts_with('┌'))
                .count(),
            1,
            "exactly one panel for one read: {panel:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A read the user refuses still says so, in the panel it already opened.
    /// A tool call is silent everywhere else, so a panel that appeared and then
    /// `write_file` shows the bytes it wrote, with the file's own grammar
    /// declared — the reverse of `read`, and deliberately so: a read's
    /// content is the model's to consume, but a write changes the user's files,
    /// so what landed on disk is the thing being checked.
    #[test]
    fn write_file_shows_the_content_with_its_language_declared() {
        let dir = std::env::temp_dir().join(format!("agent-fs-write-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let target = dir.join("shown.rs");
        let path = target.to_string_lossy().to_string();
        // Something the grammar will actually recognise, so "highlighted" is a
        // claim about a real parse rather than about a fence.
        let content = "fn main() {\n    let x: u32 = 7;\n    println!(\"{}\", x);\n}\n";

        let sink = PanelSink::default();
        let (body, _) = invoke_mcp_tool_with_asks(
            "fs.write_file",
            &serde_json::json!({ "path": &path, "content": content }).to_string(),
            Some(&sink),
            Some(Rc::new(|_: &str, _: bool| AskAnswer::Allow)),
            &ConfigSource::Tree,
        )
        .expect("invoke")
        .expect("the shipped config registers fs.write_file");

        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            content,
            "and it wrote the bytes verbatim"
        );
        assert!(body.contains("written") || body.contains("bytes"), "the model is told: {body}");

        // The panel, and the grammar on it.
        let ops = sink.ops();
        let split = ops
            .iter()
            .find_map(|op| match op {
                PanelOp::Split { title, panes, .. } => Some((title.clone(), panes.clone())),
                _ => None,
            })
            .unwrap_or_else(|| panic!("write_file drew no split panel: {ops:?}"));
        assert!(
            split.0.starts_with("write_file: ") && split.0.contains(&path),
            "titled with the tool and the file it changed: {:?}", split.0
        );
        assert_eq!(split.1.len(), 1, "one pane: there is only an \'after\'");
        assert_eq!(
            split.1[0].lang.as_deref(),
            Some("rust"),
            "and the file's own grammar, which is the whole of \'highlighted\': {:?}",
            split.1[0]
        );
        assert_eq!(
            split.1[0].caption,
            format!("{} lines, {} bytes", content.lines().count(), content.len()),
            "the caption sizes it, and agrees: {:?}",
            split.1[0].caption
        );

        // The content is in the pane, and the pane is the only copy on screen.
        let pane_text = ops
            .iter()
            .find_map(|op| match op {
                PanelOp::SetPane { text, .. } => Some(text.clone()),
                _ => None,
            })
            .unwrap_or_default();
        assert!(pane_text.contains("fn main()"), "the content is shown: {pane_text:?}");
        assert_eq!(pane_text, content, "and shown as written, not reformatted");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A one-line file gets "1 line", not "1 lines". Caught by looking at a
    /// live panel rather than by any test: the first run of this said "1 lines"
    /// and it was the sort of thing a reader stops trusting the rest of the box
    /// The permission question is drawn, as a dialog, inside the panel of the
    /// tool that raised it.
    ///
    /// This is the fix for a question asked into the void. `raise_ask` was a
    /// bare `coroutine.yield`: it reached the loop, which remembered that
    /// something was outstanding so a key press could be read as a verdict, and
    /// the loop drew *nothing* — its own comment claimed the question was
    /// already on screen, which is true only of an ask that came through
    /// `panel:ask`. So `read` and `write_file` sat waiting on a question
    /// nobody could see, with the input hint still reading "Enter sends".
    #[test]
    fn a_file_tools_question_is_a_dialog_on_its_own_panel() {
        let dir = std::env::temp_dir().join(format!("agent-fs-askpanel-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");

        // The panel ids each tool opened, and the overlays asked on them.
        let overlays = |sink: &PanelSink| -> Vec<(u64, Option<String>, bool)> {
            sink.ops()
                .iter()
                .filter_map(|op| match op {
                    PanelOp::Overlay { id, text, always } => Some((*id, text.clone(), *always)),
                    _ => None,
                })
                .collect()
        };
        let panel_ids = |sink: &PanelSink| -> Vec<u64> {
            sink.ops()
                .iter()
                .filter_map(|op| match op {
                    PanelOp::Create { id, .. } | PanelOp::Split { id, .. } => Some(*id),
                    _ => None,
                })
                .collect()
        };

        // A read, on a path nothing trusts.
        let target = dir.join("asked.txt");
        std::fs::write(&target, "x\n").expect("seed");
        let path = target.to_string_lossy().to_string();
        let sink = PanelSink::default();
        invoke_mcp_tool_with_asks(
            "fs.read",
            &serde_json::json!({ "path": &path }).to_string(),
            Some(&sink),
            Some(Rc::new(|_: &str, _: bool| AskAnswer::Allow)),
            &ConfigSource::Tree,
        )
        .expect("invoke")
        .expect("registered");

        let ids = panel_ids(&sink);
        assert_eq!(ids.len(), 1, "read opened one panel: {ids:?}");
        let asked = overlays(&sink);
        assert_eq!(
            asked.len(),
            2,
            "the question went up and came back down: {asked:?}"
        );
        assert_eq!(
            asked[0].0, ids[0],
            "and it is a dialog on the read panel, not somewhere else: {asked:?}"
        );
        assert_eq!(
            asked[0].1.as_deref(),
            Some(format!("Allow read {path}").as_str()),
            "naming the path being read: {asked:?}"
        );
        assert!(
            asked[0].2,
            "and offering [a]lways, which is what makes the answer rememberable"
        );
        assert_eq!(
            asked[1],
            (ids[0], None, false),
            "the dialog is cleared once answered, so it cannot outlive its question"
        );

        // A write asks on its own panel too — a different one.
        let wtarget = dir.join("asked2.txt");
        let wpath = wtarget.to_string_lossy().to_string();
        let wsink = PanelSink::default();
        invoke_mcp_tool_with_asks(
            "fs.write_file",
            &serde_json::json!({ "path": &wpath, "content": "y\n" }).to_string(),
            Some(&wsink),
            Some(Rc::new(|_: &str, _: bool| AskAnswer::Allow)),
            &ConfigSource::Tree,
        )
        .expect("invoke")
        .expect("registered");
        let wids = panel_ids(&wsink);
        let wasked = overlays(&wsink);
        assert_eq!(wids.len(), 1, "write_file opened one panel: {wids:?}");
        assert_eq!(wasked[0].0, wids[0], "its question is on its own panel");
        assert_eq!(
            wasked[0].1.as_deref(),
            Some(format!("Allow write {wpath}").as_str()),
            "and it is the write question: {wasked:?}"
        );

        // A trusted path asks nothing at all, so it has no dialog: the grant is
        // the point, and a panel that appeared to ask would be a lie.
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A split panel can host a dialog. `apply_patch` needs it: the ask gates the
    /// write, the panel it lands in is the before/after view, and the captions
    /// are fixed at creation — which is why they say "before"/"after" and not
    /// the line counts, which need the very read the ask is gating.
    #[test]
    fn a_split_panel_can_host_the_question_too() {
        let dir = std::env::temp_dir().join(format!("agent-fs-patchask-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let target = dir.join("patched.txt");
        std::fs::write(&target, "one\ntwo\n").expect("seed");
        let path = target.to_string_lossy().to_string();

        let sink = PanelSink::default();
        let (body, _) = invoke_mcp_tool_with_asks(
            "fs.apply_patch",
            &serde_json::json!({
                "path": &path,
                "patch": "@@ -1,2 +1,2 @@
 one
-two
+two-changed
",
            })
            .to_string(),
            Some(&sink),
            Some(Rc::new(|_: &str, _: bool| AskAnswer::Allow)),
            &ConfigSource::Tree,
        )
        .expect("invoke")
        .expect("registered");
        assert!(body.contains("changed"), "the patch applied: {body}");

        let split_id = sink
            .ops()
            .iter()
            .find_map(|op| match op {
                PanelOp::Split { id, panes, .. } => Some((*id, panes.clone())),
                _ => None,
            })
            .expect("apply_patch drew a split panel");
        let ops = sink.ops();
        let asked: Vec<PanelOp> = ops
            .iter()
            .filter(|op| matches!(op, PanelOp::Overlay { text: Some(_), .. }))
            .cloned()
            .collect();
        assert_eq!(asked.len(), 1, "the write was asked about: {asked:?}");
        match &asked[0] {
            PanelOp::Overlay { id, text, always } => {
                assert_eq!(*id, split_id.0, "asked on the patch panel itself");
                assert_eq!(
                    text.as_deref(),
                    Some(format!("Allow write {path}").as_str()),
                    "naming the file being patched"
                );
                assert!(*always, "with [a]lways offered");
            }
            _ => unreachable!(),
        }
        assert_eq!(
            split_id.1[0].caption, "before",
            "captions are fixed at creation, so they cannot carry the line counts"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
    /// over.
    #[test]
    fn a_one_line_file_is_captioned_in_the_singular() {
        let dir = std::env::temp_dir().join(format!("agent-fs-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let target = dir.join("one.txt");
        let path = target.to_string_lossy().to_string();

        let caption = |content: &str| -> String {
            let sink = PanelSink::default();
            invoke_mcp_tool_with_asks(
                "fs.write_file",
                &serde_json::json!({ "path": &path, "content": content }).to_string(),
                Some(&sink),
                Some(Rc::new(|_: &str, _: bool| AskAnswer::Allow)),
                &ConfigSource::Tree,
            )
            .expect("invoke")
            .expect("registered");
            sink.ops()
                .iter()
                .find_map(|op| match op {
                    PanelOp::Split { panes, .. } => Some(panes[0].caption.clone()),
                    _ => None,
                })
                .expect("a panel")
        };

        assert_eq!(caption("one line, no newline"), "1 line, 20 bytes");
        assert_eq!(caption("one line\n"), "1 line, 9 bytes");
        assert_eq!(caption("two\nlines\n"), "2 lines, 10 bytes");
        assert_eq!(caption(""), "0 lines, 0 bytes");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A refused write says so, in the panel that is already on screen showing
    /// what the agent was trying to put there.
    #[test]
    fn a_refused_write_says_so_beside_the_content_it_would_have_written() {
        let dir = std::env::temp_dir().join(format!("agent-fs-wdeny-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let target = dir.join("refused.rs");
        let path = target.to_string_lossy().to_string();
        let content = "fn denied() -> bool { true }\n";

        let sink = PanelSink::default();
        invoke_mcp_tool_with_asks(
            "fs.write_file",
            &serde_json::json!({ "path": &path, "content": content }).to_string(),
            Some(&sink),
            Some(Rc::new(|_: &str, _: bool| AskAnswer::Deny(None))),
            &ConfigSource::Tree,
        )
        .expect("invoke")
        .expect("registered");

        assert!(
            !target.exists(),
            "and it wrote nothing"
        );
        let pane_text: String = sink
            .ops()
            .iter()
            .filter_map(|op| match op {
                PanelOp::SetPane { text, .. } => Some(text.clone()),
                _ => None,
            })
            .collect();
        assert!(
            pane_text.contains("fn denied()"),
            "the content is still shown — this is what the agent wanted to do: {pane_text:?}"
        );
        assert!(
            pane_text.contains("not allowed"),
            "and the refusal is right there: {pane_text:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
    /// said nothing would be the one shape worse than silence.
    #[test]
    fn a_refused_read_says_so_in_its_own_panel() {
        let dir = std::env::temp_dir().join(format!("agent-fs-deny-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let target = dir.join("denied.txt");
        std::fs::write(&target, "x\n").expect("seed");
        let path = target.to_string_lossy().to_string();

        let sink = PanelSink::default();
        let (_, _) = invoke_mcp_tool_with_asks(
            "fs.read",
            &serde_json::json!({ "path": &path }).to_string(),
            Some(&sink),
            Some(Rc::new(|_: &str, _: bool| AskAnswer::Deny(None))),
            &ConfigSource::Tree,
        )
        .expect("invoke")
        .expect("registered");

        let panel: String = sink
            .ops()
            .iter()
            .map(|op| match op {
                PanelOp::Append { text, .. } => text.clone(),
                _ => String::new(),
            })
            .collect();
        assert!(
            panel.contains(&path),
            "the file is still named — the panel was opened before the ask: {panel:?}"
        );
        assert!(
            panel.contains("not allowed"),
            "and the refusal is in the panel, not only in the model's result: {panel:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A file operation *offers* "always" — a path is exactly what the trust
    /// tables remember — and every operation is asked, because the tables are
    /// per VM and each tool call gets a fresh one. That limitation is the honest
    /// state of it: within a call there is a single ask anyway, so what the
    /// answer buys today is nothing for these tools. Remembering across calls
    /// wants the same treatment `agent.llm.usage` has: a process-wide snapshot
    /// the VM is seeded from.
    #[test]
    fn a_file_operation_offers_always_and_asks_every_time() {
        let dir = std::env::temp_dir().join(format!("agent-fs-always-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let args = |name: &str| {
            serde_json::json!({
                "path": dir.join(name).to_string_lossy(),
                "content": "payload\n",
            })
            .to_string()
        };
        let offered: Rc<RefCell<Vec<bool>>> = Rc::new(RefCell::new(Vec::new()));
        let asked: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        // One write, with the handler recording what it was told.
        let call = |name: &str| {
            let seen_asks = asked.clone();
            let seen_offered = offered.clone();
            let sink = PanelSink::default();
            let (body, _) = invoke_mcp_tool_with_asks(
                "fs.write_file",
                &args(name),
                Some(&sink),
                Some(Rc::new(move |text: &str, always: bool| {
                    seen_offered.borrow_mut().push(always);
                    seen_asks.borrow_mut().push(text.to_string());
                    AskAnswer::Allow
                })),
                &ConfigSource::Tree,
            )
            .expect("invoke")
            .expect("registered write_file");
            serde_json::from_str::<serde_json::Value>(&body).expect("tool json")
        };

        // The first write: allowed, and "always" was on offer for it.
        let v = call("a.txt");
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(offered.borrow().as_slice(), [true], "always is offered");

        // A second, different file asks again — the trust tables are per VM.
        let v = call("b.txt");
        assert_eq!(v["ok"], true, "{v}");
        // And the same file again is no different: nothing crosses a call.
        let v = call("a.txt");
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(
            asked.borrow().len(),
            3,
            "every operation is asked, even a repeat of the same path: {:?}",
            asked.borrow()
        );
        // Within a call, though, "always" is real: a command that writes the
        // same file twice asks once (see ask_trust_write_remembers_only_on_always).
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The LuaLS annotation file (`lua/agent_api.meta.lua`) claims a type for
    /// every primitive in the bridge, and a claim like that is only worth
    /// anything if it stays true — an unannotated primitive is exactly what the
    /// file exists to prevent, and a stale one sends a reader after a signature
    /// that no longer exists.
    ///
    /// So the two sets are compared, both ways. (`lua/api.lua` is checked
    /// separately, and more strictly, by the loader's drift check at startup: it
    /// is prose the bridge validates. This one is the editor's view of the same
    /// 33, and it is cheap to keep honest.)
    #[test]
    fn the_lua_ls_annotations_cover_exactly_the_bridge() {
        let lua = new_vm().expect("vm");
        // `agent.api` itself cannot be enumerated from Lua: it is a *locked*
        // table, a proxy whose `pairs` yields nothing on purpose, so that a typo
        // in a primitive name raises instead of reading as nil. Its names are
        // enumerated through `agent.api_docs` instead — which is sound because
        // the loader refuses to build a VM whose `api_docs` and the real bridge
        // disagree, so this VM existing is already the proof they match.
        let joined: String = lua
            .load(
                r#"
        local names = {}
        for name in pairs(agent.api_docs) do names[#names + 1] = name end
        table.sort(names)
        return table.concat(names, "\n")
    "#,
            )
            .eval()
            .expect("enumerate the bridge");
        let bridge: Vec<&str> = joined.lines().collect();
        assert_eq!(bridge.len(), 36, "the bridge's size is part of the contract");

        let source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("lua/agent_api.meta.lua"),
        )
        .expect("read the annotation file");
        let declared: Vec<&str> = source
            .lines()
            .filter_map(|l| l.trim().strip_prefix("function agent.api."))
            .filter_map(|rest| rest.split('(').next())
            .collect();

        let untyped: Vec<&str> = bridge
            .iter()
            .filter(|b| !declared.iter().any(|d| d == *b))
            .copied()
            .collect();
        let invented: Vec<&str> = declared
            .iter()
            .filter(|d| !bridge.contains(d))
            .copied()
            .collect();
        assert!(
            untyped.is_empty(),
            "lua/agent_api.meta.lua leaves these primitives untyped: {untyped:?}"
        );
        assert!(
            invented.is_empty(),
            "lua/agent_api.meta.lua annotates these, which are not primitives: {invented:?}"
        );
        assert_eq!(declared.len(), 36, "and it declares each one exactly once");
    }

    /// `lua/mcps.lua` is the shipped connection set as one registry — the same
    /// tools `lua/init.lua` registers, obtainable in a single require, and usable
    /// as a mode's tool set.
    ///
    /// Its *name* is pinned here too, because getting it wrong is silent: `mcp`
    /// is `lua/lib/mcp.lua` (the client), `lib/` is ahead of the root on
    /// `package.path`, and a root `mcp.lua` would be shadowed rather than
    /// preferred. So this asserts that `require("mcps")` is the registry and
    /// that `require("mcp")` is still the client.
    #[test]
    fn mcps_module_is_the_shipped_connection_registry() {
        let lua = shipped_vm();

        // It is a registry of connections, not a tool: keyed by name, each value
        // carrying the connection's own tools.
        let problem: Option<String> = lua
            .load(
                r#"
        local mcps = require("mcps")
        if type(mcps) ~= "table" then return "not a table" end
        for _, name in ipairs({ "fs", "bash" }) do
          local conn = mcps[name]
          if type(conn) ~= "table" then return name .. " missing" end
          if type(conn.tools) ~= "table" then return name .. " is not a connection" end
          if next(conn.tools) == nil then return name .. " has no tools" end
          if agent.mcps[name] ~= conn then
            return name .. " is not the same connection the config registered"
          end
        end
        return nil
    "#,
            )
            .eval()
            .expect("mcps eval");
        assert!(problem.is_none(), "lua/mcps.lua: {}", problem.unwrap_or_default());

        // The two names are two different modules, which is the whole reason for
        // the plural.
        let which: String = lua
            .load(
                r#"
        local client = require("mcp")
        if client ~= agent.mcp then return "require('mcp') is not agent.mcp" end
        if client == require("mcps") then return "mcp and mcps are the same table" end
        return "ok"
    "#,
            )
            .eval()
            .expect("which mcp");
        assert_eq!(which, "ok", "the singular name is still the client");

        // And it is usable as a mode's tool set, which is the other reason to
        // have it: an explicitly named set, rather than the "all" sentinel. The
        // check is Rust's own reindex, so it is the catalog the model would be
        // offered, not Lua's opinion of it.
        let baseline: Vec<String> = mcps_tool_defs(&lua)
            .expect("baseline defs")
            .iter()
            .map(|d| d.name.clone())
            .collect();
        lua.load(
            r#"
        agent.mode.new("named", { mcps = require("mcps"), system_prompt = "N" })
        agent.mode.set("named")
    "#,
        )
        .exec()
        .expect("switch to the named mode");
        let offered: Vec<String> = mcps_tool_defs(&lua)
            .expect("named defs")
            .iter()
            .map(|d| d.name.clone())
            .collect();
        assert_eq!(
            offered, baseline,
            "the mode offers exactly the shipped registry"
        );
        let current: Option<String> = lua.load("return agent.mode.current()").eval().expect("current");
        assert_eq!(current.as_deref(), Some("named"), "and it is the mode in force");
    }

    /// The `coding` mode is the *permissive* half of the mode machinery: it
    /// changes the prompt and leaves the tool set exactly as it is, so the mode a
    /// session actually works in cannot go stale against the connections its
    /// config registered.
    ///
    /// The contrast is the point: `compact` narrows to nothing, `coding` narrows
    /// to nothing *less*, and the sentinel is what makes "everything" expressible
    /// without listing connections that may not be registered yet.
    #[test]
    fn the_coding_mode_keeps_every_tool_and_changes_only_the_prompt() {
        let lua = shipped_vm();
        // The shipped config already starts in `coding`, so clear to the baseline
        // first: this test is about what a switch *does*, and starting from the
        // mode itself would make the switch a no-op and prove nothing.
        lua.load("agent.mode.set()").exec().expect("clear to the baseline");
        let tools_before = mcps_tool_defs(&lua).expect("baseline defs");
        let mut before: Vec<&str> = tools_before.iter().map(|d| d.name.as_str()).collect();
        before.sort_unstable();
        assert!(
            before.contains(&"fs.read") && before.contains(&"fs.write_file"),
            "the baseline has the file tools: {before:?}"
        );
        let baseline_prompt = system_prompt(&lua).expect("baseline prompt");

        // Switching to it registers and applies in one step.
        lua.load(r#"agent.mode.set("coding")"#).exec().expect("switch");
        let tools_after = mcps_tool_defs(&lua).expect("coding defs");
        let mut after: Vec<&str> = tools_after.iter().map(|d| d.name.as_str()).collect();
        after.sort_unstable();
        assert_eq!(after, before, "every tool is still offered, tool for tool");

        // The prompt is the other half. The shipped config's *default* prompt is
        // the same wording, so "the mode's prompt differs from the baseline" is
        // not a property this VM can show — what it can show is that the prompt
        // in force while `coding` is the coding prompt, and that the mode's own
        // spec carries it.
        let prompt = system_prompt(&lua).expect("coding prompt");
        // Both halves, not one phrase. The prompt used to describe only the
        // editing path, which left a task that changes nothing with no guidance
        // at all; asserting on one remembered sentence would not have caught
        // that, and would not catch a half-removed path either.
        assert!(
            prompt.contains("coding agent")
                && prompt.contains("To understand code")
                && prompt.contains("To change code"),
            "the coding prompt is what is sent, with both paths in it: {prompt:.80}"
        );
        let spec_prompt: String = lua
            .load("return agent.mode.get('coding').system_prompt")
            .eval()
            .expect("spec prompt");
        assert_eq!(
            spec_prompt, prompt,
            "and it is the one the mode carries, not a copy that drifted"
        );
        let _ = baseline_prompt; // the default wording; see above

        // And the mode knows which one is in force.
        let current: Option<String> = lua.load("return agent.mode.current()").eval().expect("current");
        assert_eq!(current.as_deref(), Some("coding"));

        // The mode names its tool set, so it is exactly the shipped registry and
        // nothing more: a connection registered afterwards is *not* in it. (The
        // `"all"` sentinel is the other way round, and `agent.mode._selftest`
        // pins that directly.)
        lua.load(
            r#"
        agent.mcps.later = { name = "later", tools = { ping = agent.utils.tool(
          "a tool registered after the mode", { type = "object", properties = {} }, function() return "pong" end) } }
        agent.mode.set("coding")
    "#,
        )
        .exec()
        .expect("re-apply after registering");
        let names: Vec<String> = mcps_tool_defs(&lua)
            .expect("defs")
            .iter()
            .map(|d| d.name.clone())
            .collect();
        assert!(
            !names.contains(&"ping".to_string()),
            "a named registry is what the mode said it is, not the session's: {names:?}"
        );

        // Clearing restores the baseline prompt and the baseline registry — and
        // that registry is a *snapshot* taken at the first switch, which is what
        // keeps a connection registered mid-session out of it.
        lua.load("agent.mode.set()").exec().expect("clear");
        assert_eq!(
            system_prompt(&lua).expect("restored prompt"),
            baseline_prompt,
            "the baseline prompt is back"
        );
        let restored_defs = mcps_tool_defs(&lua).expect("restored defs");
        let restored: Vec<&str> = restored_defs
            .iter()
            .map(|d| d.name.as_str())
            .collect();
        assert_eq!(
            restored, before,
            "and so is the baseline tool set — the mode added nothing"
        );
    }

    /// A mode narrows what the agent can reach: its connection set replaces
    /// `agent.mcps`, so a tool the mode leaves out is neither advertised to the
    /// next request nor callable — and clearing the mode brings it back.
    ///
    /// The read-only view is a *new connection* holding the *same tool tables*
    /// as the full one (the reference semantics `mcps` relies on), which is how
    /// a mode trims a connection's tool set without rebuilding it.
    #[test]
    fn a_mode_narrows_the_tool_set() {
        let lua = shipped_vm();
        let dir = std::env::temp_dir().join(format!("agent-mode-fs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // `None` = the mode does not offer the tool at all. A tool the mode
        // *does* offer still has to be answered: the file tools ask before they
        // touch anything, so a write is only as available as the last yes.
        let write = |name: &str| -> Option<bool> {
            let args = serde_json::json!({
                "path": dir.join(name).to_string_lossy(),
                "content": "payload\n",
            })
            .to_string();
            invoke_tool(&lua, "fs.write_file", &args)
                .expect("invoke")
                .and_then(|(body, _)| serde_json::from_str::<serde_json::Value>(&body).ok())
                .and_then(|v| v["ok"].as_bool())
        };
        let asked_write = |name: &str| -> Option<bool> {
            let args = serde_json::json!({
                "path": dir.join(name).to_string_lossy(),
                "content": "payload\n",
            })
            .to_string();
            let (v, _asked) = tool_allowed("fs.write_file", &args);
            v["ok"].as_bool()
        };

        // Baseline: the full connection, so the write is offered and works.
        let defs = mcps_tool_defs(&lua).expect("baseline defs");
        let baseline: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert!(
            baseline.contains(&"fs.write_file"),
            "baseline: {baseline:?}"
        );
        assert_eq!(
            asked_write("baseline.txt"),
            Some(true),
            "the baseline write goes through, once allowed"
        );

        // A mode whose connection exposes only the two read tools.
        lua.load(
            r#"
            local fs = require("fs")
            local read_only = {
              name = "fs_read_only",
              description = "reads only",
              tools = { read = fs.tools.read },
            }
            agent.mode.new("read_only", {
              description = "no edits",
              system_prompt = "You may read, not write.",
              mcps = { fs_read_only = read_only },
            })
            agent.mode.set("read_only")
        "#,
        )
        .exec()
        .expect("set read-only mode");

        let defs = mcps_tool_defs(&lua).expect("mode defs");
        let mut names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            ["fs_read_only.read"],
            "the mode advertises exactly the tools *its* connection exposes — \
             qualified by that connection's name, not the built-in one's"
        );
        assert_eq!(
            write("blocked.txt"),
            None,
            "a tool the mode omits is not callable at all"
        );
        assert!(!dir.join("blocked.txt").exists(), "nothing was written");
        assert_eq!(
            system_prompt(&lua).expect("prompt"),
            "You may read, not write.",
            "the mode's prompt half is what the next request sends"
        );

        // Clearing the mode restores both halves.
        lua.load("agent.mode.set()").exec().expect("clear mode");
        let defs = mcps_tool_defs(&lua).expect("restored defs");
        let mut restored: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        restored.sort_unstable();
        assert_eq!(
            restored,
            ["bash.bash", "fs.apply_patch", "fs.hand_to_user", "fs.read", "fs.write_file"],
            "clearing the mode restores the configured tool set"
        );
        assert_eq!(
            asked_write("allowed.txt"),
            Some(true),
            "clearing the mode restores the write tool, once allowed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A unique temp dir for a fixture tree: `<name>-<pid>-<n>`.
    fn fixture(name: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        std::env::temp_dir().join(format!(
            "agent-lua-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    /// A fixture tree loads exactly as the shipped one does: nested modules
    /// resolve through the dotted name, a top-level module through the tree
    /// root, both are auto-required at setup *before* the entry script runs
    /// (which the script itself records), a lib module's own
    /// `agent.<name> = M` registration survives, and each stays cached.
    #[test]
    fn a_fixture_tree_loads_nested_root_and_entry_in_order() {
        let dir = fixture("tree");
        std::fs::create_dir_all(dir.join("lib").join("net")).expect("fixture dirs");
        std::fs::write(
            dir.join("lib").join("net").join("http.lua"),
            "return { url = 'http' }",
        )
        .expect("nested module");
        // A lib module following the convention: it publishes itself on agent.
        std::fs::write(
            dir.join("lib").join("widgets.lua"),
            "local M = { n = 2 }\nagent.widgets = M\nreturn M",
        )
        .expect("self-registering module");
        std::fs::write(dir.join("lib").join("shadowed.lua"), "return { from = 'lib' }")
            .expect("lib module");
        // Same name at the tree root: `lib/` must win.
        std::fs::write(dir.join("shadowed.lua"), "return { from = 'root' }").expect("root module");
        std::fs::write(dir.join("only_root.lua"), "return { from = 'root' }")
            .expect("root-only module");
        // The entry script records which of the fixture modules were already
        // loaded by the time it ran, and publishes the bridge annotations
        // exactly as the shipped `lua/init.lua` does.
        std::fs::write(
            dir.join("init.lua"),
            r#"
            agent.api_docs = require("api")
            __init_saw = {}
            for _, name in ipairs({ "net.http", "only_root", "shadowed", "widgets" }) do
              __init_saw[name] = package.loaded[name] ~= nil
            end
            __init_saw.agent_widgets = agent.widgets and agent.widgets.n or nil
            "#,
        )
        .expect("entry script");
        // The real annotation file: a fixture tree has to satisfy the same
        // bridge/annotation check the shipped one does.
        std::fs::copy(tree().join("api.lua"), dir.join("api.lua")).expect("copy api.lua");

        let lua = Lua::new();
        setup_tree(&lua, None, None, &dir, &ConfigSource::Tree).expect("fixture tree setup");
        let problem: Option<String> = lua
            .load(
                r#"
            -- lib modules (nested ones included) were required before init ran.
            if not __init_saw["net.http"] then return "net.http not preloaded" end
            if not __init_saw["shadowed"] then return "shadowed not preloaded" end
            -- The tree root is require()-able but not auto-loaded: only lib/ is.
            if __init_saw["only_root"] then return "only_root was auto-loaded" end
            if require("net.http").url ~= "http" then return "nested module" end
            if require("only_root").from ~= "root" then return "root module" end
            -- lib/ outranks the tree root on a name collision.
            if require("shadowed").from ~= "lib" then return "lib precedence" end
            -- Cached: a re-require is the same table.
            if package.loaded["net.http"] ~= require("net.http") then return "cache" end
            -- A lib module's self-registration is live, and it is the module.
            if __init_saw.agent_widgets ~= 2 then return "agent.widgets" end
            if agent.widgets ~= package.loaded["widgets"] then return "widgets table" end
            return nil
        "#,
            )
            .eval()
            .expect("fixture eval");
        assert!(
            problem.is_none(),
            "fixture tree: {}",
            problem.unwrap_or_default()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A tree without an entry script is a load-time error naming the file it
    /// wanted (the tree ships with the binary, so a missing one is a broken
    /// install, not something to paper over with an empty default).
    /// The two tool shapes the live TUI run could not reach, because the local
    /// model narrates a tool call as prose instead of emitting one: a tool that
    /// draws nothing, and a tool that fails.
    ///
    /// Both are run through the real registry on a real VM, because the claim
    /// being pinned is not "the loop suppresses a box" — it is the whole
    /// arrangement: a tool has nothing to draw if it does not draw, and the
    /// model learns the outcome either way. The transcript's half of that is in
    /// `main.rs`, where the folding happens.
    #[test]
    fn a_silent_tool_and_a_failing_tool_both_reach_the_model_and_draw_nothing() {
        let dir = fixture("quiet");
        std::fs::create_dir_all(dir.join("lib")).expect("fixture dir");
        std::fs::copy(tree().join("api.lua"), dir.join("api.lua")).expect("api.lua");
        // The tool table written out rather than built with `agent.utils.tool`:
        // a fixture tree has no `lib/` modules, so `agent.utils` is nil. This is
        // the shape `utils.tool` produces (`lua/lib/utils.lua`), spelled here so
        // the test does not need the whole tree to mean one thing.
        std::fs::write(
            dir.join("init.lua"),
            r#"
            agent.api_docs = require("api")
            local function tool(description, callback)
              return { description = description,
                       signature = { type = "object", properties = {} },
                       callback = callback }
            end
            agent.mcps = {}
            agent.mcps.quiet = {
              name = "quiet",
              tools = {
                silent = tool("Succeed without drawing anything.", function()
                  return { ok = true, result = "done" }
                end),
                broken = tool("Raise without drawing anything.", function()
                  error("the tool fell over")
                end),
              },
            }
            "#,
        )
        .expect("entry script");

        let sink = crate::panels::PanelSink::default();
        let lua = Lua::new();
        setup_tree(&lua, Some(&sink), None, &dir, &ConfigSource::Tree).expect("fixture setup");

        // A tool that draws nothing has nothing to draw.
        let ran = invoke_tool_asking(&lua, "quiet.silent", "{}", None)
            .expect("the silent tool runs");
        let (_body, content) = ran.expect("the registry holds quiet.silent");
        assert!(
            sink.ops().is_empty(),
            "a tool that drew nothing queued no panel op: {:?}",
            sink.ops()
        );
        assert!(
            content.contains("done"),
            "and the model is told it worked: {content}"
        );

        // A tool that fails draws nothing either, and says nothing — the
        // transcript honours that. The model still gets the error.
        let err = invoke_tool_asking(&lua, "quiet.broken", "{}", None)
            .expect_err("a raising tool is an error");
        assert!(
            sink.ops().is_empty(),
            "a failure drew nothing either: {:?}",
            sink.ops()
        );
        assert!(
            err.contains("fell over"),
            "but the model is told why: {err}"
        );
    }

    #[test]
    fn a_tree_without_an_entry_script_fails_by_name() {
        let dir = fixture("no-init");
        std::fs::create_dir_all(dir.join("lib")).expect("fixture dir");
        let lua = Lua::new();
        let err = setup_tree(&lua, None, None, &dir, &ConfigSource::Tree).expect_err("a tree without init.lua must fail");
        let text = err.to_string();
        assert!(
            text.contains("init.lua") && text.contains(&dir.display().to_string()),
            "error should name the missing entry script, got: {text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The tree resolution order, without touching the process environment
    /// (which other tests' VMs would race on): an explicit dir wins; else
    /// `lua/` beside the executable when it has an `init.lua`; else `lua/` in
    /// the working directory.
    #[test]
    fn lua_dir_resolution_order() {
        let explicit = PathBuf::from("/srv/shared/lua");
        assert_eq!(
            lua_dir_in(Some(explicit.clone()), Some(PathBuf::from("/opt/bin/agent"))),
            explicit
        );
        // Beside the executable: an exe under <repo>/bin/ finds <repo>/lua.
        let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        assert_eq!(
            lua_dir_in(None, Some(repo.join("bin"))),
            repo.join("lua")
        );
        // No lua/init.lua beside the executable -> the working directory.
        assert_eq!(
            lua_dir_in(None, Some(repo.join("bin").join("deep"))),
            PathBuf::from("lua")
        );
        assert_eq!(lua_dir_in(None, None), PathBuf::from("lua"));
    }

    /// The tree the tests load is the one the repo ships: an entry script plus
    /// at least one lib module (a missing tree would make every VM test fail
    /// above, so this only pins the shape).
    #[test]
    fn shipped_tree_has_an_entry_script_and_lib_modules() {
        let dir = tree();
        assert!(
            dir.join("init.lua").is_file(),
            "{} is missing the entry script",
            dir.display()
        );
        let modules = std::fs::read_dir(dir.join("lib"))
            .expect("lua/lib")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("lua"))
            .count();
        assert!(modules > 0, "no lua/lib/*.lua modules shipped");
    }

    /// Allow every syscall: a policy with no own keys, so the interception mask
    /// is empty and nothing is intercepted at all. (Its `__index` is never
    /// consulted for masked syscalls — the mask is the policy's own string
    /// keys — so it is vestigial here; tests that want a syscall decided
    /// explicitly assign a key, e.g. `allowall.execve = ...`.)
    const ALLOW_ALL: &str =
        r#"setmetatable({}, { __index = function() return function() return true end end })"#;

    /// Collect pushed output chunks into tables (1-based, so the entry count
    /// is the chunk count) and stamp them onto `opts`; returns `opts, out,
    /// err`. The pump reads the callback fields off the object at drive time,
    /// so collectors work whether installed before or after `run`.
    const COLLECT: &str = r#"
    local function collect(opts)
      opts = opts or {}
      local out, err = {}, {}
      opts.on_stdout = function(c) out[#out + 1] = c end
      opts.on_stderr = function(c) err[#err + 1] = c end
      return opts, out, err
    end
    "#;

    /// Build an in-process fake MCP transport for the `agent.mcp` tests: a
    /// function(request_json, on_streaming_response_json) that decodes each
    /// request, looks up `handlers[req.method]`, and streams every message the
    /// handler returns (JSON-encoded) through the callback in order. Request
    /// handlers receive the decoded request and must return response messages
    /// carrying `id = req.id`; unknown notifications are accepted silently;
    /// unknown requests raise ("no handler"). Lua-only — it proves the client
    /// talks to *any* transport func, not just spawned processes. Inserted as
    /// a `format!` value, so the Lua braces inside are literal.
    const FAKE_MCP_FUNC: &str = r#"
    local function fake_mcp_func(handlers)
      local encode, decode = agent.api.json_encode, agent.api.json_decode
      return function(request_json, on_streaming_response_json)
        local req = decode(request_json)
        local h = handlers[req.method]
        if h == nil then
          if req.id == nil then return end
          error("fake func: no handler for '" .. tostring(req.method) .. "'", 0)
        end
        local msgs = h(req)
        if msgs ~= nil then
          for _, m in ipairs(msgs) do
            on_streaming_response_json(encode(m))
          end
        end
      end
    end
    "#;

    /// Standard fake-server handlers for `fake_mcp_func`: initialize,
    /// tools/list (tools `probe` and `sum`), and tools/call (probe text back
    /// or sum two numbers). Close to the reference `mcp_fake` server's shape,
    /// but in-process. See `FAKE_MCP_FUNC` for the transport contract.
    const FAKE_MCP_HANDLERS: &str = r#"
    local handlers = {
      initialize = function(req)
        return {
          { jsonrpc = "2.0", id = req.id,
            result = { protocolVersion = "2025-03-26", capabilities = { tools = {} },
                       serverInfo = { name = "lua-fake", version = "1.0.0" } } },
        }
      end,
      ["tools/list"] = function(req)
        return {
          { jsonrpc = "2.0", id = req.id,
            result = { tools = {
              { name = "probe", description = "probe text back",
                inputSchema = { type = "object",
                                properties = { text = { type = "string" } },
                                required = { "text" } } },
              { name = "sum", description = "add two numbers",
                inputSchema = { type = "object",
                                properties = { a = { type = "number" }, b = { type = "number" } },
                                required = { "a", "b" } } },
            } } },
        }
      end,
      ["tools/call"] = function(req)
        local args = req.params.arguments
        local text
        if args.text ~= nil then
          text = args.text
        else
          text = tostring(args.a + args.b)
        end
        return {
          { jsonrpc = "2.0", id = req.id,
            result = { content = { { type = "text", text = text } }, isError = false } },
        }
      end,
    }
    "#;

    #[test]
    fn runtime_is_luajit_and_evaluates() {
        let lua = Lua::new();
        let sum: i64 = lua.load("return 21 * 2").eval().expect("lua eval of 21*2");
        assert_eq!(sum, 42);
        // LuaJIT implements the Lua 5.1 ABI, so `_VERSION` reads "Lua 5.1";
        // the LuaJIT-specific identity lives in the `jit` library's version.
        let version: String = lua
            .globals()
            .get::<mlua::Table>("jit")
            .expect("jit library present")
            .get("version")
            .expect("jit.version exists");
        assert!(
            version.contains("LuaJIT"),
            "expected the vendored LuaJIT runtime, got {version:?}"
        );
    }

    #[test]
    fn rust_values_cross_into_lua_and_back() {
        let lua = Lua::new();
        lua.globals()
            .set("saved", "payload".to_string())
            .expect("set global");
        let round: String = lua
            .load("return saved .. '!'")
            .eval()
            .expect("concat round-trip");
        assert_eq!(round, "payload!");
    }

    #[test]
    fn coroutine_yield_then_resume_with_verdict() {
        // The Ask↔verdict primitive, exercised bare: a coroutine that yields
        // once (the "ask"), is resumed with an answer, and the yield site
        // receives it before the coroutine completes. This is precisely the
        // shape `Verdict::Ask`/`resolve_ask` takes across the Rust↔Lua
        // boundary. (The body must be a thread-wrapped *function*: yielding
        // at the top level of a chunk crosses a C-call boundary and is
        // rejected — as the future policy layer will too.)
        let lua = Lua::new();
        let body: mlua::Function = lua
            .load(
                r#"
            return function()
                local asked = coroutine.yield("frozen syscall")
                return "decided: " .. asked
            end
            "#,
            )
            .eval()
            .expect("load coroutine body");
        let thread = lua
            .create_thread(body)
            .expect("wrap coroutine body in a thread");

        // First resume runs the function to its yield: Rust receives the ask.
        let ask: String = thread.resume(()).expect("resume to yield");
        assert_eq!(ask, "frozen syscall");

        // Second resume carries the verdict: the Lua yield site sees it.
        let result: String = thread.resume("allow").expect("resume with verdict");
        assert_eq!(result, "decided: allow");

        // The coroutine finished: a further resume must refuse.
        let e = thread
            .resume::<mlua::Value>(())
            .expect_err("dead coroutine");
        assert!(
            matches!(e, mlua::Error::CoroutineUnresumable),
            "expected CoroutineUnresumable, got {e:?}"
        );
    }

    #[test]
    fn agent_bash_echo_streams_and_completes() {
        // Push callbacks receive the streamed chunks; s:run() returns the
        // completed result table. stdout/"hello\n" arrives (as one or more
        // chunks), stderr is empty. ALLOW_ALL names no syscalls, so the mask
        // is empty: a pure-builtin `echo` performs no masked syscall at all
        // — zero intercepts, and the run completes because nothing needed
        // deciding (un-named syscalls run free).
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            {COLLECT}
            local allowall = {ALLOW_ALL}
            local opts, out, err = collect()
            local s = agent.bash("echo hello", allowall, opts)
            local r = s:run()
            return r.stdout == "hello\n" and r.exit.code == 0
                   and table.concat(out) == "hello\n" and table.concat(err) == ""
                   and r.denied == 0 and r.syscalls == 0
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "expected a clean allow-all echo run");
    }

    #[test]
    fn empty_policy_traces_nothing_and_the_command_runs() {
        // A policy's syscall-name keys are the interception mask: `{}` names
        // nothing, so nothing is traced — the command runs free under the
        // kernel default and completes cleanly with zero intercepted
        // syscalls (the engine's fork-family mask adds nothing for a
        // builtin). The old fail-closed contract (unlisted ⇒ denied) is
        // gone: unlisted syscalls are simply not decided.
        let lua = vm();
        let r: mlua::Table = lua
            .load(r#"return agent.bash("echo nope", {}):run()"#)
            .eval()
            .expect("eval");
        let exit: mlua::Table = r.get("exit").expect("exit");
        let code: i64 = exit.get("code").expect("code");
        let denied: u64 = r.get("denied").expect("denied");
        let syscalls: u64 = r.get("syscalls").expect("syscalls");
        let stdout: String = r.get("stdout").expect("stdout");
        assert_eq!(code, 0, "nothing was denied");
        assert_eq!(denied, 0, "an empty policy denies nothing");
        assert_eq!(syscalls, 0, "an empty policy traces nothing");
        assert_eq!(stdout, "nope\n", "the command ran to completion");
    }

    #[test]
    fn bare_policy_traps_only_its_named_syscalls() {
        // `{ write = allow }` is a *bare* partial table: under the old
        // fail-closed contract its first un-named syscall would have killed
        // the run; under the named-mask contract only writes are intercepted
        // (and allowed) while execve/read/stat/… run straight through the
        // kernel. Proves the mask is exactly the table's keys.
        let lua = vm();
        let r: mlua::Table = lua
            .load(r#"return agent.bash("echo hi", { write = function() return true end }):run()"#)
            .eval()
            .expect("eval");
        let exit: mlua::Table = r.get("exit").expect("exit");
        assert_eq!(exit.get::<i64>("code").expect("code"), 0);
        let denied: u64 = r.get("denied").expect("denied");
        let syscalls: u64 = r.get("syscalls").expect("syscalls");
        let stdout: String = r.get("stdout").expect("stdout");
        assert_eq!(stdout, "hi\n");
        assert_eq!(denied, 0);
        assert!(syscalls >= 1, "writes are named, so they are intercepted");
    }

    #[test]
    fn yield_in_policy_callback_is_an_ask() {
        // The core Ask round-trip, driven through the pump: the execve
        // callback calls a user-asking function which yields — the raw value
        // is re-yielded to whoever resumed s.pump; resuming with `true`
        // delivers the verdict to the yield site and the run completes.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            {COLLECT}
            local allowall = {ALLOW_ALL}
            allowall.execve = function(s)
              -- the syscall table reaches the callback intact
              assert(s.name == "execve" and s.nr == 59, "execve identity")
              assert(type(s.pid) == "number" and s.pid > 0, "pid present")
              assert(type(s.args) == "table" and s.args[1] ~= nil, "args present")
              -- user-asking function: yields the ask; the resume-verdict lands here
              local function uask(v) return coroutine.yield(v) end
              return uask(s.name)
            end
            local opts, out = collect()
            local s = agent.bash("echo asked", allowall, opts)
            local ok1, ask = coroutine.resume(s.pump)
            assert(ok1, tostring(ask))
            assert(ask == "execve", "ask is the raw yielded value, got " .. tostring(ask))
            local ok2, r = coroutine.resume(s.pump, true)
            assert(ok2, tostring(r))
            assert(coroutine.status(s.pump) == "dead", "pump finished after the verdict")
            return r.stdout == "asked\n" and r.exit.code == 0
                   and table.concat(out) == "asked\n"
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "ask/yield round-trip failed");
    }

    #[test]
    fn callback_error_kills_tree_and_propagates() {
        // A raising callback never bubbles into the driver: the sandbox is
        // killed on the spot and the error reaches whoever resumed the pump.
        let lua = vm();
        let (errored, errmsg): (bool, String) = lua
            .load(format!(
                r#"
            local allowall = {ALLOW_ALL}
            allowall.execve = function() error("boom") end
            local s = agent.bash("echo x", allowall)
            local ok, e = coroutine.resume(s.pump)
            return ok == false, tostring(e)
            "#
            ))
            .eval()
            .expect("eval");
        assert!(
            errored,
            "expected the pump resume to error, got a completed resume"
        );
        assert!(errmsg.contains("boom"), "expected boom, got {errmsg:?}");
    }

    #[test]
    fn denying_a_specific_syscall_kills_mid_run() {
        // Everything allowed except `write`: bash's first stdout write denies,
        // which is final — the tree dies with SIGKILL.
        let lua = vm();
        let r: mlua::Table = lua
            .load(format!(
                r#"
            local policy = {ALLOW_ALL}
            policy.write = function() return false end
            return agent.bash("echo hi", policy):run()
            "#
            ))
            .eval()
            .expect("eval");
        let exit: mlua::Table = r.get("exit").expect("exit");
        let signal: i64 = exit.get("signal").expect("signal");
        let denied: u64 = r.get("denied").expect("denied");
        assert_eq!(signal, libc::SIGKILL as i64, "denied write kills the tree");
        assert!(denied >= 1, "write was denied");
    }

    #[test]
    fn multi_chunk_output_streams_whole() {
        // 20k lines ≈ 140KB, far beyond one 64KB pipe chunk: the pushed
        // output arrives in multiple callback invocations and the
        // concatenation is exact.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            {COLLECT}
            local allowall = {ALLOW_ALL}
            local opts, out = collect()
            local s = agent.bash("seq 1 20000", allowall, opts)
            local r = s:run()
            local count, first, last = 0, nil, nil
            for line in table.concat(out):gmatch("[^\n]+") do
              count = count + 1
              if count == 1 then first = line end
              last = line
            end
            return count == 20000 and first == "1" and last == "20000"
                   and #out >= 2 and r.stdout == table.concat(out)
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "expected all 20000 seq lines, streamed whole");
    }

    #[test]
    fn bash_argument_validation() {
        let lua = vm();
        let ok: bool = lua
            .load(
                r#"
            local ok1 = pcall(agent.bash, "echo x", nil)
            local ok2 = pcall(agent.bash, 42, {})
            local ok3 = pcall(agent.bash, "echo x", {}, 5)
            local ok4 = pcall(agent.bash, "echo x", {}, { on_stdout = 5 })
            local ok5 = pcall(agent.bash, "echo x", {}, { on_stderr = "s" })
            local ok6 = pcall(agent.bash, "echo x", {}, { on_exit = false })
            return ok1 == false and ok2 == false and ok3 == false and ok4 == false
                   and ok5 == false and ok6 == false
            "#,
            )
            .eval()
            .expect("eval");
        assert!(ok, "arg validation errors");
    }

    #[test]
    fn yield_across_pcall_crosses_and_resumes() {
        // Pins the actual LuaJIT behavior for a yield inside a `pcall`ed
        // function (relevant to user-written callbacks): unlike a yield at a
        // chunk's top level (rejected — the substrate test above), a yield
        // inside `pcall` crosses the boundary: the coroutine suspends, the
        // resumer receives the yielded value, and a second resume continues
        // the pcalled function. The driver never relies on this (it cannot
        // catch callback errors across pcall the same way), but callbacks may.
        let lua = Lua::new();
        let ok: bool = lua
            .load(
                r#"
            local co = coroutine.create(function()
              return pcall(function() return coroutine.yield("nope") end)
            end)
            local ok1, v = coroutine.resume(co)
            if not (ok1 and v == "nope") then
              return false, tostring(v)
            end
            -- resume with a value: the yield site inside the pcalled
            -- function receives it, the function returns it, pcall returns
            -- (true, value), and the coroutine finishes with all of it.
            local ok2, pcall_ok, ret = coroutine.resume(co, "back")
            return ok2 == true and pcall_ok == true and ret == "back"
            "#,
            )
            .eval()
            .expect("eval");
        assert!(ok, "yield across pcall must suspend/resume cleanly");
    }

    #[test]
    fn ask_round_trip_is_stable_under_repetition() {
        // Regression for the asker-excluded freeze: repeated ask→allow round
        // trips must complete. A full-tree SIGSTOP-freeze used to interrupt
        // the asker's notification wait — the kernel discarded the pending
        // notification, so the restarted syscall re-asked forever. The bridge
        // now freezes only the *other* processes (never the asker), and each
        // of these round trips rides the freeze → allow → completion-wait →
        // thaw cycle.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            {COLLECT}
            local allowall = {ALLOW_ALL}
            allowall.execve = function(s)
              local function uask(v) return coroutine.yield(v) end
              return uask(s.name)
            end
            for i = 1, 15 do
              local opts, out = collect()
              local s = agent.bash("echo round", allowall, opts)
              local ok1, ask = coroutine.resume(s.pump)
              assert(ok1, tostring(ask))
              assert(ask == "execve", "ask " .. i .. " is execve, got " .. tostring(ask))
              local ok2, r = coroutine.resume(s.pump, true)
              assert(ok2, tostring(r))
              assert(coroutine.status(s.pump) == "dead", "pump finished in round " .. i)
              assert(r.stdout == "round\n" and r.exit.code == 0
                     and table.concat(out) == "round\n", "round " .. i .. " failed")
            end
            return true
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "ask round-trip must be stable across runs");
    }

    #[test]
    fn multi_ask_per_syscall_round_trips_a_deny() {
        // A callback may ask more than once for one syscall: each yield is a
        // separate ask re-yielded to the caller, each resumed verdict is
        // delivered to the yield site, and only the callback's final return
        // value is the decision. Here two asks resolve (true, false) → the
        // callback returns false → deny. The deny kills the tree *before*
        // the errno is replayed (the thread is still parked in its
        // notification wait), so the run deterministically ends in SIGKILL
        // even under this narrow mask — no post-deny exit path can race it.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            local allowall = {ALLOW_ALL}
            allowall.execve = function(s)
              local function uask(v) return coroutine.yield(v) end
              local v1 = uask(s.name .. "/first")
              local v2 = uask(s.name .. "/second")
              return v1 and v2
            end
            local s = agent.bash("echo multi", allowall)
            local ok1, ask1 = coroutine.resume(s.pump)
            assert(ok1, tostring(ask1))
            assert(ask1 == "execve/first", "first ask, got " .. tostring(ask1))
            local ok2, ask2 = coroutine.resume(s.pump, true)
            assert(ok2, tostring(ask2))
            assert(ask2 == "execve/second", "second ask, got " .. tostring(ask2))
            local ok3, res = coroutine.resume(s.pump, false)
            assert(ok3, tostring(res))
            return type(res) == "table" and res.exit.signal == 9 and res.denied >= 1
            "#
            ))
            .eval()
            .expect("eval");
        assert!(
            ok,
            "multi-ask per syscall must round-trip to the final verdict"
        );
    }

    #[test]
    fn multi_ask_per_syscall_round_trips_an_allow() {
        // Same multi-ask flow, both verdicts true → the syscall runs and the
        // run completes normally.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            {COLLECT}
            local allowall = {ALLOW_ALL}
            allowall.execve = function(s)
              local function uask(v) return coroutine.yield(v) end
              local v1 = uask(s.name .. "/first")
              local v2 = uask(s.name .. "/second")
              return v1 and v2
            end
            local opts, out = collect()
            local s = agent.bash("echo multi", allowall, opts)
            local ok1, ask1 = coroutine.resume(s.pump)
            assert(ok1, tostring(ask1))
            assert(ask1 == "execve/first")
            local ok2, ask2 = coroutine.resume(s.pump, true)
            assert(ok2, tostring(ask2))
            assert(ask2 == "execve/second")
            local ok3, r = coroutine.resume(s.pump, true)
            assert(ok3, tostring(r))
            assert(coroutine.status(s.pump) == "dead", "pump finished after the verdicts")
            return r.stdout == "multi\n" and r.exit.code == 0 and table.concat(out) == "multi\n"
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "multi-ask allow must complete");
    }

    #[test]
    fn bash_streams_stdout_and_stderr_in_order() {
        // Pushed chunks arrive per-stream in write order; stdout and stderr
        // go to their own callbacks.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            {COLLECT}
            local allowall = {ALLOW_ALL}
            local opts, out, err = collect()
            local s = agent.bash("echo out; echo err >&2; echo out2", allowall, opts)
            local r = s:run()
            return table.concat(out) == "out\nout2\n" and table.concat(err) == "err\n"
                   and r.exit.code == 0
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "expected streamed stdout out,out2 and stderr err");
    }

    #[test]
    fn write_feeds_stdin_and_output_streams() {
        // Full-duplex through the stream object: s:write_stdin feeds the
        // tracee's stdin, s:close_stdin signals EOF, and cat echoes the bytes
        // back through on_stdout and into the captured result.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            {COLLECT}
            local allowall = {ALLOW_ALL}
            local opts, out = collect()
            local s = agent.bash("cat", allowall, opts)
            s:write_stdin("hello\n")
            s:close_stdin()
            local r = s:run()
            return table.concat(out) == "hello\n"
                   and r.stdout == "hello\n" and r.exit.code == 0
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "expected cat to echo the written stdin");
    }

    #[test]
    fn sibling_output_completes_after_an_ask() {
        // While a policy ask holds the background child's write of "ping",
        // the parent's write of "pong" is *also* parked — both processes'
        // writes are in the masked set (this policy names `execve` and
        // `write`), so nothing enters the pipes until the
        // supervisor allows it. The tree is not frozen though: the parent
        // keeps executing until its own write (intercepted before the
        // verdict, thanks to the sleep) queues after the child's ask. After
        // the verdict the child's write completes first (resolve_ask), then
        // the queued parent write — pushed through the callbacks in that
        // order, with no bytes lost. `root` is the *first* execve's pid;
        // later execs (e.g. /usr/bin/sleep) must not clobber it.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            {COLLECT}
            local allowall = {ALLOW_ALL}
            local root = nil
            allowall.execve = function(s)
              if root == nil then root = s.pid end
              return true
            end
            allowall.write = function(s)
              if s.pid ~= root then
                local function uask(v) return coroutine.yield(v) end
                return uask("sibling write")
              end
              return true
            end
            local opts, out = collect()
            local s = agent.bash("echo ping & sleep 0.05; echo pong; wait", allowall, opts)
            local ok1, ask = coroutine.resume(s.pump)
            assert(ok1, tostring(ask))
            assert(ask == "sibling write",
                   "first ask is the child's write, got " .. tostring(ask))
            -- The parent's "pong" write happens on its own timeline; keep the
            -- ask open long enough that it is provably intercepted and queued
            -- before the verdict.
            os.execute("sleep 0.15")
            local ok2, r = coroutine.resume(s.pump, true)
            assert(ok2, tostring(r))
            assert(coroutine.status(s.pump) == "dead", "pump finished after the ask")
            return r.exit.code == 0 and table.concat(out) == "ping\npong\n"
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "queued sibling output must complete after the ask");
    }

    #[test]
    fn pull_reader_wrapper_drives_the_pump() {
        // The user's pull-reader pattern: wrap the pump in *their own*
        // coroutine, collect pushed chunks, and re-yield asks to their
        // resumer. Asks and output interleave with no corruption because the
        // drive chain (user coroutine → pump → callback sub-coroutine) is
        // pure Lua frames end to end — no ask yield crosses a C call.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            local allowall = {ALLOW_ALL}
            allowall.execve = function(s)
              local function uask(v) return coroutine.yield(v) end
              return uask(s.name)
            end
            local chunks = {{}}
            local s = agent.bash("echo pull", allowall,
                                 {{ on_stdout = function(c) chunks[#chunks + 1] = c end }})
            local user_co = coroutine.create(function()
              local pump = s.pump
              local pending
              while true do
                local ok, ev = coroutine.resume(pump, pending)
                pending = nil
                assert(ok, tostring(ev))
                if coroutine.status(pump) == "dead" then return ev end
                pending = coroutine.yield("user sees: " .. tostring(ev))
              end
            end)
            local ok1, ask = coroutine.resume(user_co)
            assert(ok1, tostring(ask))
            assert(ask == "user sees: execve",
                   "ask surfaced through the wrapper, got " .. tostring(ask))
            local ok2, r = coroutine.resume(user_co, true)
            assert(ok2, tostring(r))
            assert(coroutine.status(user_co) == "dead", "wrapper finished")
            return r.stdout == "pull\n" and r.exit.code == 0
                   and table.concat(chunks) == "pull\n"
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "pull-reader wrapper must drive the pump without bugs");
    }

    #[test]
    fn run_with_on_ask_answers_asks() {
        // The non-interactive driver: s:run(on_ask) answers asks raised by
        // user-asking functions and returns the result; the ask value is
        // passed through verbatim.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            {COLLECT}
            local allowall = {ALLOW_ALL}
            allowall.execve = function(s)
              local function uask(v) return coroutine.yield(v) end
              return uask(s.name)
            end
            local opts, out = collect()
            local s = agent.bash("echo askus", allowall, opts)
            local asked_n = 0
            local r = s:run(function(ask)
              assert(ask == "execve", "on_ask got the raw ask, got " .. tostring(ask))
              asked_n = asked_n + 1
              return true
            end)
            return r.stdout == "askus\n" and r.exit.code == 0 and asked_n == 1
                   and table.concat(out) == "askus\n"
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "s:run(on_ask) must answer asks and complete");
    }

    #[test]
    fn run_without_on_ask_handler_raises_on_ask() {
        // Ask with no handler: s:run() raises a clear error instead of
        // silently auto-answering. (The pump stays suspended at the ask; VM
        // teardown cleans the parked tree up.)
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            local allowall = {ALLOW_ALL}
            allowall.execve = function(s)
              local function uask(v) return coroutine.yield(v) end
              return uask(s.name)
            end
            local s = agent.bash("echo nope", allowall)
            local ok, e = pcall(function() return s:run() end)
            return ok == false and tostring(e):find("on_ask") ~= nil
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "run() without on_ask must raise on an ask");
    }

    #[test]
    fn detached_without_callbacks_completes() {
        // "Ignore it entirely": no output callbacks at all — output is
        // discarded by the config, yet the run still completes and the final
        // result is produced.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            local allowall = {ALLOW_ALL}
            local s = agent.bash("echo ignored", allowall)
            local r = s:run()
            return r.exit.code == 0 and r.stdout == "ignored\n" and r.denied == 0
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "detached run without callbacks must complete");
    }

    #[test]
    fn callbacks_are_assignable_and_on_exit_fires() {
        // The pump reads the callback fields at drive time: they may be
        // installed after construction (how pull readers redirect push into a
        // queue), and on_exit fires with the very result table run returns.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            local allowall = {ALLOW_ALL}
            local late, exited = {{}}, nil
            local s = agent.bash("echo late", allowall)
            s.on_stdout = function(c) late[#late + 1] = c end
            s.on_exit = function(r) exited = r end
            local r = s:run()
            return exited ~= nil and exited == r and r.exit.code == 0
                   and r.stdout == "late\n" and table.concat(late) == "late\n"
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "assignable callbacks and on_exit must work");
    }

    #[test]
    fn non_boolean_callback_kills_and_raises() {
        // A callback whose completion value is not a boolean: the sandbox is
        // killed on the spot and the driver raises instead of guessing.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            local allowall = {ALLOW_ALL}
            allowall.execve = function() return "maybe" end
            local s = agent.bash("echo x", allowall)
            local ok, e = coroutine.resume(s.pump)
            return ok == false and tostring(e):find("boolean") ~= nil
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "non-boolean completion must kill and raise");
    }

    #[test]
    fn non_function_policy_entry_kills_and_raises() {
        // A policy entry that is not a callback function: same kill + raise.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            local policy = {ALLOW_ALL}
            policy.execve = 42
            local s = agent.bash("echo x", policy)
            local ok, e = coroutine.resume(s.pump)
            return ok == false and tostring(e):find("not a callback") ~= nil
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "non-function policy entry must kill and raise");
    }

    #[test]
    fn lua_bash_runs_a_command_under_an_allow_policy() {
        // `lua::bash` — Rust's one-shot wrapper over agent.bash — runs a
        // sandboxed command and reports the captured output and exit status.
        // ALLOW_ALL is a bare expression, so it is wrapped in `return`.
        // ALLOW_ALL names no syscalls → empty mask → nothing intercepted:
        // a pure-builtin echo reports zero intercepts yet still runs (its
        // un-named syscalls went straight through the kernel).
        let out = run_bash("echo sandboxed", &format!("return {ALLOW_ALL}"), None, None)
            .expect("bash ran");
        assert_eq!(out.stdout, "sandboxed\n");
        assert_eq!(out.exit_code, Some(0));
        assert_eq!(out.exit_signal, None);
        assert!(!out.failed());
        assert_eq!(out.syscalls, 0, "ALLOW_ALL names no syscalls to trap");
        assert_eq!(out.denied, 0);
    }

    #[test]
    fn lua_policy_blocks_openat_read_write() {
        // `exec 3<>file` opens the file read-write (O_RDWR | O_CREAT) — the
        // first such openat is denied: the open fails EPERM and the engine
        // kills the tree, so the process cannot exit cleanly. (bash's own
        // /dev/tty probe — O_RDWR|O_NONBLOCK — is exempted so the policy is
        // testing the real open, not startup.)
        let policy = r#"
        local p = setmetatable({}, { __index = function() return function() return true end end })
        p.openat = function(sys)
          local flags = sys.args[3]
          if flags == 2050 then return true end -- /dev/tty probe
          return (flags % 4) ~= 2
        end
        return p
        "#;
        let out = run_bash(
            "exec 3<>/tmp/lua-bash-denied-rw; echo unreachable",
            policy,
            None,
            None,
        )
        .expect("bash ran");
        assert!(out.denied >= 1, "at least one read-write openat denied");
        assert!(out.failed(), "a denied rw open must not exit cleanly");
        assert!(
            !out.stdout.contains("unreachable"),
            "the tracee dies before the echo after a denied open"
        );
    }

    /// A policy that *asks* (yields) on write `openat`s — the shape the bash
    /// tool's own policy uses, minus the flag decoding.
    const ASK_ON_WRITE_POLICY: &str = r#"
    local p = setmetatable({}, { __index = function() return function() return true end end })
    local function uask(v) return coroutine.yield(v) end
    p.openat = function(sys)
      local flags = sys.args[3]
      if flags == 2050 then return true end -- /dev/tty probe
      if flags % 4 ~= 0 then return uask({ description = "openat requests write" }) end
      return true
    end
    return p
    "#;

    #[test]
    fn lua_bash_auto_denies_an_ask_without_a_handler() {
        // A policy that raises an ask never hangs a run: with no ask handler
        // (`agent.api.ask_user` on a headless VM) the ask resolves to deny,
        // exactly like the flat deny the policy used to return — same outcome,
        // terminated. The tool's overlay around it is covered by
        // `the_bash_tool_panels_a_denial`.
        let _ = std::fs::remove_file("/tmp/lua-bash-ask-auto-deny");
        let out = run_bash(
            "exec 3<>/tmp/lua-bash-ask-auto-deny; echo unreachable",
            ASK_ON_WRITE_POLICY,
            None,
            None,
        )
        .expect("bash ran");
        assert!(out.denied >= 1, "the ask auto-denies without a handler");
        assert!(out.failed(), "a denied ask must not exit cleanly");
        assert!(
            !out.stdout.contains("unreachable"),
            "the tracee dies before the echo"
        );
    }

    #[test]
    fn an_ask_handler_routes_its_verdicts() {
        // The interactive path: the VM's ask handler decides each frozen
        // syscall. Allowing the write open lets the command complete and create
        // its file; denying it reproduces the headless outcome. (The overlay
        // and the status line around an ask are the *tool's* — see
        // `the_bash_tool_...` below.)
        for p in ["/tmp/lua-bash-ask-allow", "/tmp/lua-bash-ask-deny"] {
            let _ = std::fs::remove_file(p);
        }
        let out = run_bash(
            "echo ask-write > /tmp/lua-bash-ask-allow",
            ASK_ON_WRITE_POLICY,
            None,
            Some(Rc::new(|_, _always: bool| AskAnswer::Allow)),
        )
        .expect("bash ran");
        assert_eq!(out.denied, 0, "the handler allowed the write open");
        assert!(!out.failed(), "an allowed write lets the run finish");
        assert!(
            std::path::Path::new("/tmp/lua-bash-ask-allow").exists(),
            "the allowed open created the file"
        );

        let out = run_bash(
            "exec 3<>/tmp/lua-bash-ask-deny; echo unreachable",
            ASK_ON_WRITE_POLICY,
            None,
            Some(Rc::new(|_, _always: bool| AskAnswer::Deny(None))),
        )
        .expect("bash ran");
        assert!(out.denied >= 1, "a denied ask blocks the syscall");
        assert!(out.failed(), "a denied ask must not exit cleanly");
        assert!(
            !std::path::Path::new("/tmp/lua-bash-ask-deny").exists(),
            "a denied open must not create the file"
        );

        let _ = std::fs::remove_file("/tmp/lua-bash-ask-allow");
        let _ = std::fs::remove_file("/tmp/lua-bash-ask-deny");
    }

    #[test]
    fn an_ask_verdicts_reason_surfaces_on_the_result() {
        // An ask is a yielded user-asking call resumed with its verdict; a
        // verdict object from the ask handler (`AskAnswer::Deny(Some(..))`)
        // therefore carries the reason exactly like a policy's
        // `agent.deny(reason)` — on the outcome here, and on the panel status
        // line where the tool renders it (`the_bash_tool_panels_a_denial`).
        let out = run_bash(
            "exec 3<>/tmp/lua-bash-ask-reason; echo unreachable",
            ASK_ON_WRITE_POLICY,
            None,
            Some(Rc::new(|_, _always: bool| AskAnswer::Deny(Some("user said no".to_string())))),
        )
        .expect("bash ran");
        assert!(out.denied >= 1, "the ask denial blocks the write");
        assert!(out.failed(), "a denied ask must not exit cleanly");
        assert_eq!(
            out.denied_reason.as_deref(),
            Some("user said no"),
            "the ask handler's reason travels on the result"
        );
        assert!(
            !std::path::Path::new("/tmp/lua-bash-ask-reason").exists(),
            "the denied open must not create the file"
        );

        let _ = std::fs::remove_file("/tmp/lua-bash-ask-reason");
    }

    #[test]
    fn an_ask_verdict_allow_succeeds_like_true() {
        // `AskAnswer::Allow` resumed into the asking callback behaves exactly
        // like the boolean `true` verdict.
        let out = run_bash(
            "exec 3<>/tmp/lua-bash-ask-allow-v; echo via-ask-allow",
            ASK_ON_WRITE_POLICY,
            None,
            Some(Rc::new(|_, _always: bool| AskAnswer::Allow)),
        )
        .expect("bash ran");
        assert_eq!(out.denied, 0, "an allowed ask lets the run finish");
        assert!(!out.failed());
        assert_eq!(out.stdout, "via-ask-allow\n");
        assert_eq!(out.denied_reason, None);
        assert!(
            std::path::Path::new("/tmp/lua-bash-ask-allow-v").exists(),
            "the allowed open created the file"
        );
        let _ = std::fs::remove_file("/tmp/lua-bash-ask-allow-v");
    }

    #[test]
    fn syscall_table_carries_the_caller_cmdline_from_proc() {
        // Every policy callback can see *who* is asking: the syscall table
        // carries the caller's pid and its `/proc/<pid>/cmdline`. The tracee
        // is spawned as `bash -c "<cmdline>"`; the pre-exec `execve` still
        // shows the *inherited* argv (the forked child is a copy of the
        // sandbox's own process), but from the moment bash runs every
        // intercepted syscall's caller argv holds the full -c line — asserted
        // on every syscall of the run here.
        let policy = r#"
        local function inspect(sys)
          assert(type(sys.pid) == "number" and sys.pid > 0, "pid present")
          assert(type(sys.cmdline) == "string" and sys.cmdline ~= "",
                 "caller cmdline is a readable string")
          if sys.name ~= "execve" then
            assert(sys.cmdline:find("cmdl-ask", 1, true) ~= nil,
                   "cmdline is the caller's bash -c line: " .. tostring(sys.cmdline))
          end
          return true
        end
        -- `execve` and `write` are the named mask: exactly those are
        -- intercepted, and each one passes through `inspect`.
        local policy = {}
        policy.execve = inspect
        policy.write = inspect
        return policy
        "#;
        let out = run_bash("echo cmdl-ask", policy, None, None)
            .expect("bash ran");
        assert_eq!(out.stdout, "cmdl-ask\n");
        assert!(!out.failed());
    }

    #[test]
    fn read_cstr_parses_a_nul_terminated_string_from_a_targets_memory() {
        // The dereference primitive: reads a NUL-terminated C string from the
        // target's address space (here, the test process's own), and yields
        // None for an unreadable pointer rather than erroring.
        let s = std::ffi::CString::new("hello from the sandbox supervisor").unwrap();
        let got = read_cstr(std::process::id() as i32, s.as_ptr() as u64, CSTRING_CAP)
            .expect("self memory is readable");
        assert_eq!(got, "hello from the sandbox supervisor");
        assert_eq!(
            read_cstr(std::process::id() as i32, 0, CSTRING_CAP),
            None,
            "null ptr"
        );
        assert_eq!(
            read_cstr(
                std::process::id() as i32,
                0xdead_beef_dead_beef,
                CSTRING_CAP
            ),
            None,
            "bogus pointer is None, not an error"
        );
    }

    #[test]
    fn cstring_arg_positions_name_the_string_slots_per_syscall() {
        // The `sys.str` dereference map: which 0-based `args` slots are C
        // strings for each syscall, with fd slots and out-buffers excluded.
        assert_eq!(
            cstring_positions("execve"),
            Some(&[0][..]),
            "execve: program"
        );
        assert_eq!(
            cstring_positions("openat"),
            Some(&[1][..]),
            "openat: dirfd, path"
        );
        assert_eq!(
            cstring_positions("rename"),
            Some(&[0, 1][..]),
            "rename: old, new"
        );
        assert_eq!(
            cstring_positions("symlinkat"),
            Some(&[0, 2][..]),
            "symlinkat: target, link"
        );
        assert_eq!(
            cstring_positions("mount"),
            Some(&[0, 1, 2, 3][..]),
            "mount: four strings"
        );
        assert_eq!(
            cstring_positions("getcwd"),
            None,
            "getcwd's arg is an out-buffer, not a string"
        );
        assert_eq!(
            cstring_positions("read"),
            None,
            "fd-based syscalls have no string args"
        );
        assert_eq!(
            cstring_positions("nosuchsyscall"),
            None,
            "unknown names: no positions"
        );
    }

    #[test]
    fn cwd_resolution_is_gated_on_at_fdcwd_for_dirfd_syscalls() {
        // The dirfd family (openat & friends) resolves relative names against
        // a caller-held fd, invisible to us — only AT_FDCWD means "the cwd".
        let at_fdcwd = libc::AT_FDCWD as u64;
        let mut args = [0u64; 6];
        args[0] = at_fdcwd;
        assert!(
            cwd_resolution_ok("openat", 1, args),
            "AT_FDCWD: resolve vs cwd"
        );
        args[0] = 3;
        assert!(
            !cwd_resolution_ok("openat", 1, args),
            "real dirfd: pass the name through"
        );

        // symlinkat: the target (0) is cwd-relative, the linkpath (2) follows
        // the fd in slot 1.
        args[0] = 0;
        args[1] = at_fdcwd;
        assert!(cwd_resolution_ok("symlinkat", 0, args));
        assert!(
            cwd_resolution_ok("symlinkat", 2, args),
            "AT_FDCWD linkpath resolves"
        );
        args[1] = 5;
        assert!(
            !cwd_resolution_ok("symlinkat", 2, args),
            "dirfd'd linkpath passes through"
        );
        assert!(
            cwd_resolution_ok("symlinkat", 0, args),
            "target is still cwd-relative"
        );

        // Plain pathname syscalls have no dirfd at all.
        assert!(cwd_resolution_ok("execve", 0, args));
        assert!(cwd_resolution_ok("unlink", 0, args));
        assert!(cwd_resolution_ok("mount", 0, args));
    }

    #[test]
    fn resolve_path_chases_symlinks_and_collapses_dotdot() {
        // A temp sandwich: base/a/x.txt real file, base/b/link.txt a symlink
        // to it. Resolution must land on the *actual* file either way.
        use std::os::unix::fs::symlink;
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let base = std::env::temp_dir().join(format!(
            "agent-resolve-{:x}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let a = base.join("a");
        let b = base.join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(a.join("x.txt"), "x").unwrap();
        symlink(a.join("x.txt"), b.join("link.txt")).unwrap();
        let real = |p: &std::path::Path| p.canonicalize().unwrap().to_string_lossy().into_owned();

        // An existing file resolves to its canonical path.
        assert_eq!(
            resolve_path(None, a.join("x.txt").to_str().unwrap()),
            real(&a.join("x.txt"))
        );

        // A symlink resolves to the actual file it points at.
        assert_eq!(
            resolve_path(None, b.join("link.txt").to_str().unwrap()),
            real(&a.join("x.txt"))
        );

        // ".." is collapsed: a/../a/x.txt is a/x.txt.
        let dod = a.join("..").join("a").join("x.txt");
        assert_eq!(
            resolve_path(None, dod.to_str().unwrap()),
            real(&a.join("x.txt"))
        );

        // A missing tail keeps its literal form: an uncreated file passes the
        // name through (it cannot resolve to a file that does not exist), and
        // an unrefinable absolute path stays as it was given.
        let newborn = a.join("soon.txt");
        assert_eq!(
            resolve_path(None, newborn.to_str().unwrap()),
            newborn.to_string_lossy()
        );

        // A missing prefix passes the name through unchanged.
        let gone = base.join("nope").join("deep");
        assert_eq!(
            resolve_path(None, gone.to_str().unwrap()),
            gone.to_string_lossy()
        );
        let nowhere = "/this/does/not/exist-zz";
        assert_eq!(resolve_path(None, nowhere), nowhere);
        assert_eq!(resolve_path(None, ""), "");

        // Relative names resolve against the given cwd when the file exists
        // (canonical target); a missing file passes the name through.
        assert_eq!(resolve_path(Some(&a), "x.txt"), real(&a.join("x.txt")));
        assert_eq!(resolve_path(Some(&a), "soon.txt"), "soon.txt");

        // Dangling symlinks: the target doesn't exist yet, but the *intended*
        // location still lands — where the file will live.
        symlink("missing-zz.txt", b.join("dangling.txt")).unwrap();
        assert_eq!(
            resolve_path(None, b.join("dangling.txt").to_str().unwrap()),
            b.join("missing-zz.txt").to_string_lossy().into_owned()
        );
        symlink("/this/does/not/exist-zz", b.join("absdangling.txt")).unwrap();
        assert_eq!(
            resolve_path(None, b.join("absdangling.txt").to_str().unwrap()),
            "/this/does/not/exist-zz"
        );

        // A chain of dangling links unwinds to the final intended target.
        symlink("dangling.txt", b.join("chain.txt")).unwrap();
        assert_eq!(
            resolve_path(None, b.join("chain.txt").to_str().unwrap()),
            b.join("missing-zz.txt").to_string_lossy().into_owned()
        );

        // A cycle of dangling links gives up (hop cap) and stays literal — no
        // hang, name passes through.
        symlink("cycle-b", b.join("cycle-a")).unwrap();
        symlink("cycle-a", b.join("cycle-b")).unwrap();
        assert_eq!(
            resolve_path(None, b.join("cycle-a").to_str().unwrap()),
            b.join("cycle-a").to_string_lossy().into_owned()
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn proc_cmdline_reads_argv_from_the_proc_tree() {
        // `/proc/<pid>/cmdline` of the test process itself: readable and it
        // names the test binary (cargo runs it as target/debug/deps/agent-*).
        let line = proc_cmdline(std::process::id() as i32);
        assert!(!line.is_empty(), "self cmdline is readable");
        assert!(
            line.contains("agent"),
            "it is the test binary's argv: {line}"
        );
        // A pid that cannot exist yields the empty string, never an error.
        assert_eq!(proc_cmdline(1 << 30), "");
    }

    #[test]
    fn lua_policy_denied_reason_surfaces_on_the_result() {
        // `agent.deny(reason)` — the `Denied(reason)` arm of the policy sum
        // type — denies like `false`, but carries the reason out on the run's
        // result. (The tool renders it as `Denied: <reason>` on the panel; see
        // `the_bash_tool_panels_a_denial`.)
        let policy = r#"
        local p = setmetatable({}, { __index = function() return function() return true end end })
        p.openat = function()
          return agent.deny("openat is forbidden here")
        end
        return p
        "#;
        let out = run_bash("echo unreachable", policy, None, None)
            .expect("bash ran");
        assert!(out.denied >= 1, "a denied reason still denies");
        assert!(out.failed(), "a denied run must not exit cleanly");
        assert_eq!(
            out.denied_reason.as_deref(),
            Some("openat is forbidden here"),
            "the reason travels on the result"
        );
    }

    #[test]
    fn lua_policy_allow_constructor_runs_the_command() {
        // The `Allow` arm: `agent.allow()` behaves exactly like `true`.
        let policy = r#"
        local p = setmetatable({}, { __index = function() return function() return agent.allow() end end })
        return p
        "#;
        let out = run_bash("echo allowed-via-ctor", policy, None, None)
            .expect("bash ran");
        assert!(!out.failed());
        assert_eq!(out.stdout, "allowed-via-ctor\n");
        assert_eq!(out.denied, 0);
    }

    #[test]
    fn lua_policy_rejects_a_non_verdict_table_return() {
        // Only booleans and `agent.allow()`/`agent.deny(reason)` are legal
        // callback results; a hand-rolled table is an error, not a deny.
        // `execve` is named so the callback actually runs (a metatable-only
        // policy would trace nothing and never call anything).
        let e = run_bash(
            "echo hi",
            r#"
            local p = setmetatable({}, { __index = function() return function() return { verdict = "deny" } end end })
            p.execve = function() return { verdict = "deny" } end
            return p
            "#,
            None,
            None,
        )
        .expect_err("a malformed verdict is an error, not a run");
        assert!(
            e.contains("must return a boolean or agent.allow()/agent.deny(reason)"),
            "{e}"
        );
    }

    #[test]
    fn lua_bash_surfaces_policy_and_run_errors() {
        // A policy that is not a table and a callback that raises both
        // surface as Err with the Lua-side message (never a hung run).
        let e = run_bash("echo hi", "return 42", None, None).unwrap_err();
        assert!(e.contains("policy") || e.contains("agent.bash"), "{e}");
        let e = run_bash(
            "echo hi",
            r#"
            local p = setmetatable({}, { __index = function() return function() return true end end })
            p.execve = function(sys) error('policy exploded') end
            return p
            "#,
            None,
            None,
        )
        .unwrap_err();
        assert!(e.contains("policy exploded"), "{e}");
    }

    #[test]
    fn engine_loses_no_output_under_always_ask() {
        // Isolate the Lua layer entirely: drive the engine exactly as the
        // bridge does — always-Ask decider, digest every Blocked with
        // resolve_ask(Allow), drain output — and confirm no byte is lost at
        // completion. Any failure here is an engine-level bug reachable from
        // agent.bash.
        for _ in 0..50 {
            let mut sb =
                seccomp::Sandbox::spawn("bash", &["-c", "echo multi"], |_| Verdict::Ask, &[1])
                    .expect("spawn");
            let r = loop {
                let slots = sb.poll_slots();
                if slots.is_empty() {
                    match sb.step(0).expect("step") {
                        Step::Finished(r) => break r,
                        other => panic!("tree gone but step returned {other:?}"),
                    }
                }
                let mut pfds: Vec<libc::pollfd> = slots.iter().map(|(_, p)| *p).collect();
                let pr = unsafe {
                    libc::poll(
                        pfds.as_mut_ptr(),
                        pfds.len() as libc::nfds_t,
                        seccomp::DEFAULT_POLL_TIMEOUT_MS,
                    )
                };
                if pr == -1 {
                    panic!("poll: {}", std::io::Error::last_os_error());
                }
                if pr == 0 {
                    continue;
                }
                let mut listener_revents = 0i16;
                for (k, p) in pfds.iter().enumerate() {
                    if p.revents != 0 && slots[k].0 == FdSlot::Listener {
                        listener_revents = p.revents;
                    }
                }
                match sb.step(listener_revents).expect("step") {
                    Step::Blocked { .. } => sb.resolve_ask(Verdict::Allow).expect("resolve_ask"),
                    Step::Event(_) | Step::Idle => {}
                    Step::Finished(r) => break r,
                }
            };
            let stdout = String::from_utf8_lossy(&r.stdout).into_owned();
            assert_eq!(stdout, "multi\n", "output lost at completion: {stdout:?}");
            assert_eq!(r.exit.code, Some(0));
        }
    }

    #[test]
    fn raw_driver_primitives_are_exposed() {
        // The raw `agent.api` surface drives the same run the driver sugar
        // does: spawn, step, decide, and the finished result.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                r#"
            local allowall = {ALLOW_ALL}
            local h = agent.api.spawn("echo raw", {{"write"}})
            local decided, finished = 0, nil
            while finished == nil do
              local s = agent.api.step(h)
              if s.kind == "blocked" then
                local cb = allowall[s.syscall.name]
                agent.api.decide(h, cb(s.syscall))
                decided = decided + 1
              elseif s.kind == "finished" then
                finished = s.result
              end
            end
            return finished.stdout == "raw\n" and finished.exit.code == 0 and decided > 0
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "raw driver primitives failed");
    }

    #[test]
    fn mcp_fake_handshake_registers_tools_and_calls_them() {
        // The full agent.mcp flow against an in-process fake transport func:
        // handshake (initialize -> initialized notification -> tools/list),
        // tool objects registered on the connection with their fields, and
        // request/response tool calls correlated by id — all through
        // func(request_json, on_streaming_response_json). No process: the
        // transport is injected and the protocol lives in Lua.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
                body = r#"
            local func = fake_mcp_func(handlers)
            agent.mcps.fake = agent.mcp("fake", func)
            local conn = agent.mcps.fake
            -- handshake results surfaced on the connection
            assert(conn.serverInfo.name == "lua-fake", "serverInfo.name")
            assert(conn.protocolVersion == "2025-03-26", "protocolVersion")
            -- tool objects: callable tables with signature/description fields
            assert(type(conn.probe) == "table" and getmetatable(conn.probe).__call ~= nil,
                   "probe tool callable")
            assert(conn.probe.description == "probe text back", "probe description")
            assert(conn.probe.signature.type == "object", "probe signature")
            assert(conn.probe.signature.required[1] == "text", "probe signature required")
            assert(conn.tools.probe == conn.probe, "same tool in conn.tools")
            assert(type(conn.sum) == "table" and getmetatable(conn.sum).__call ~= nil,
                   "sum tool callable")
            -- tool calls return a table with ok/result/error/denied fields
            local r1 = conn.probe({ text = "hi there" })
            assert(r1.ok == true and r1.denied == false and r1.error == nil, "probe ok")
            assert(r1.result.content[1].type == "text", "probe content type")
            assert(r1.result.content[1].text == "hi there", "probe text")
            local r2 = conn.sum({ a = 2, b = 40 })
            assert(r2.ok == true and r2.denied == false, "sum ok")
            assert(r2.result.content[1].text == "42", "sum 2+40, got " ..
                   tostring(r2.result and r2.result.content and r2.result.content[1]
                            and r2.result.content[1].text))
            conn:close()
            assert(agent.mcps.fake == nil, "close unregisters the connection")
            return true
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "mcp handshake/tool-call flow failed");
    }

    #[test]
    fn mcp_tool_policy_denies_without_touching_the_wire() {
        // Tool-level approval is a plain Lua allow-list (no Ask machinery):
        // a `false` verdict denies the call locally — the transport func is
        // never invoked — and the connection is unaffected for other tools.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
                body = r#"
            local calls = 0
            local base = fake_mcp_func(handlers)
            local conn = agent.mcp("fake", function(request_json, on_streaming_response_json)
              calls = calls + 1
              base(request_json, on_streaming_response_json)
            end)
            conn.probe.policy = function(args) return args.text ~= "forbidden" end
            local a = conn.probe({ text = "ok" })
            assert(a.ok == true and a.denied == false, "allowed call passes")
            assert(a.result.content[1].text == "ok", "allowed call result")
            local before = calls
            local b = conn.probe({ text = "forbidden" })
            assert(b.ok == false and b.denied == true, "denied call fails locally")
            assert(calls == before, "denied call never touches the wire")
            local c = conn.sum({ a = 1, b = 2 })
            assert(c.ok == true and c.result.content[1].text == "3", "other tools unaffected")
            conn:close()
            return true
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "mcp tool policy flow failed");
    }

    #[test]
    fn mcp_tool_callback_overrides_the_rpc() {
        // tool.callback short-circuits the RPC: any return is the tool result
        // verbatim; a `false` return denies (used for stubs / dry-runs).
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
                body = r#"
            local conn = agent.mcp("fake", fake_mcp_func(handlers))
            conn.probe.callback = function(args) return "dry-run:" .. args.text end
            local r = conn.probe({ text = "x" })
            assert(r.ok == true and r.result == "dry-run:x", "callback result takes over")
            conn.probe.callback = function() return false end
            local d = conn.probe({ text = "x" })
            assert(d.ok == false and d.denied == true, "callback false denies")
            conn:close()
            return true
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "mcp tool callback flow failed");
    }

    #[test]
    fn mcp_close_marks_dead_and_invokes_on_close() {
        // close() marks the connection dead (later tool calls fail fast with
        // a result error, not a raise), unregisters from agent.mcps, and lets
        // the transport release its resources via opts.on_close.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
                body = r#"
            local closed = false
            local conn = agent.mcp("tmp", fake_mcp_func(handlers),
                                   { on_close = function() closed = true end })
            local r = conn.probe({ text = "before" })
            assert(r.ok == true, "works before close")
            conn:close()
            assert(closed == true, "on_close called")
            assert(conn.alive == false, "connection marked dead")
            local a = conn.probe({ text = "after" })
            assert(a.ok == false and a.error ~= nil, "connection dead after close")
            local okd, derr = conn:request("tools/list", {})
            assert(okd == nil and derr ~= nil, "request fails fast on a dead connection")
            return true
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "mcp close flow failed");
    }

    #[test]
    fn mcp_validation_and_handshake_failures() {
        // Argument validation happens before any transport contact; handshake
        // failures (transport raise, absent response, RPC error) raise out of
        // agent.mcp, so a connection is only ever handed back ready to go.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
                body = r#"
            assert(not pcall(agent.mcp, 7, function() end), "bad name rejected")
            assert(not pcall(agent.mcp, "n"), "missing func rejected")
            assert(not pcall(agent.mcp, "n", "not a function"), "non-function func rejected")
            assert(not pcall(agent.mcp, "n", function() end, 5), "bad opts rejected")
            assert(not pcall(agent.mcp, "n", function() end, { on_message = 5 }), "bad opt rejected")
            assert(not pcall(agent.mcp, "n", function() end, { protocolVersion = 7 }),
                   "bad protocolVersion rejected")
            -- handshake: a func that never streams a response raises
            assert(not pcall(agent.mcp, "gone", function() end),
                   "initialize without a response raises")
            -- handshake: a transport raise raises
            assert(not pcall(agent.mcp, "boom", function() error("network down") end),
                   "transport raise during handshake raises")
            -- handshake: an initialize RPC error raises
            local errfunc = fake_mcp_func({
              initialize = function(req)
                return { { jsonrpc = "2.0", id = req.id,
                           error = { code = -32000, message = "no such server" } } }
              end,
            })
            assert(not pcall(agent.mcp, "err", errfunc), "initialize rpc error raises")
            return true
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "mcp validation/handshake-failure flow failed");
    }

    #[test]
    fn mcp_streams_notifications_before_the_response() {
        // The callback is a *stream*: a single func round may deliver id-less
        // notifications first and the response last; the driver routes each —
        // notifications into opts.on_message, the matching response to the
        // pending request.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
                body = r#"
            local notes = {}
            local base_call = handlers["tools/call"]
            handlers["tools/call"] = function(req)
              local msgs = base_call(req)
              table.insert(msgs, 1, { jsonrpc = "2.0", method = "notes/changed", params = { n = 1 } })
              table.insert(msgs, 2, { jsonrpc = "2.0", method = "notes/changed", params = { n = 2 } })
              return msgs
            end
            local conn = agent.mcp("s", fake_mcp_func(handlers),
                                   { on_message = function(m) notes[#notes + 1] = m end })
            local r = conn.probe({ text = "x" })
            assert(r.ok == true and r.result.content[1].text == "x", "response still resolves")
            assert(#notes == 2, "both notifications streamed, got " .. tostring(#notes))
            assert(notes[1].method == "notes/changed" and notes[2].params.n == 2,
                   "notifications routed to on_message in order")
            conn:close()
            return true
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "mcp streaming-notification flow failed");
    }

    #[test]
    fn mcp_tool_call_transport_errors_surface_as_results() {
        // A func that raises mid-round, or that returns without streaming the
        // response, surfaces as { ok = false, error } — never a raise out of
        // the tool call. Non-JSON streamed text goes to on_badline.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
                body = r#"
            local conn = agent.mcp("s", fake_mcp_func(handlers))
            -- func raises: transport error
            conn.func = function() error("boom") end
            local r = conn.probe({ text = "x" })
            assert(r.ok == false and r.error ~= nil and r.error:find("boom", 1, true) ~= nil,
                   "func raise becomes a request error, got " .. tostring(r.error))
            -- func returns without streaming the response: protocol error
            conn.func = function(request_json, on_streaming_response_json) end
            local r2 = conn.sum({ a = 1, b = 2 })
            assert(r2.ok == false and r2.error ~= nil and
                   r2.error:find("no response", 1, true) ~= nil,
                   "missing response errors, got " .. tostring(r2.error))
            -- non-JSON text streamed by the func: on_badline, then the round
            -- still fails as unanswered
            local noted
            local conn2 = agent.mcp("b", fake_mcp_func(handlers),
                                    { on_badline = function(text, why) noted = { text, why } end })
            conn2.func = function(request_json, on_streaming_response_json)
              on_streaming_response_json('not json at all')
            end
            local r3 = conn2.probe({ text = "x" })
            assert(r3.ok == false and r3.error ~= nil and
                   r3.error:find("no response", 1, true) ~= nil,
                   "badline round still errors, got " .. tostring(r3.error))
            assert(noted ~= nil and noted[1] == 'not json at all', "on_badline saw the bad text")
            conn:close()
            conn2:close()
            return true
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "mcp transport-error flow failed");
    }

    #[test]
    fn mcp_notify_sends_without_expecting_a_response() {
        // conn:notify is fire-and-forget: func carries the notification over
        // the wire, but nothing streamed back is awaited (id-less messages
        // still dispatch into on_message).
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
                body = r#"
            local calls = 0
            local base = fake_mcp_func(handlers)
            local conn = agent.mcp("s", function(request_json, on_streaming_response_json)
              calls = calls + 1
              base(request_json, on_streaming_response_json)
            end, { on_message = function() end })
            local before = calls
            local okn, nerr = conn:notify("notifications/cancelled", { reason = "bye" })
            assert(okn == true and nerr == nil, "notify accepted")
            assert(calls == before + 1, "notify went through func")
            conn:close()
            return true
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "mcp notify flow failed");
    }

    #[test]
    fn mcp_per_call_streaming_routes_progress_and_messages_then_settles() {
        // Phase-A streaming: conn:invoke(name, args, { on_progress, on_message })
        // — a round carrying on_progress injects `_meta.progressToken` into the
        // request params (shallow-copied, never mutating the caller's table),
        // notifications streamed back during the round route to the per-call
        // callbacks in order, and the result still settles atomically.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
                body = r#"
            local base_call = handlers["tools/call"]
            local seen_request_meta
            local global_hits = 0
            handlers["tools/call"] = function(req)
              local msgs = base_call(req)
              if req.params.arguments.text ~= nil then
                seen_request_meta = req.params._meta
                local token = seen_request_meta and seen_request_meta.progressToken or nil
                table.insert(msgs, 1, { jsonrpc = "2.0", method = "notifications/progress",
                                        params = { progressToken = token, progress = 1, total = 2 } })
                table.insert(msgs, 2, { jsonrpc = "2.0", method = "notes/changed", params = { n = 1 } })
              end
              return msgs
            end
            local conn = agent.mcp("s", fake_mcp_func(handlers),
                                   { on_message = function() global_hits = global_hits + 1 end })
            local events = {}
            local r = conn:invoke("probe", { text = "x" }, {
              on_progress = function(m) events[#events + 1] = "progress:" .. tostring(m.params.progressToken) end,
              on_message  = function(m) events[#events + 1] = "message:" .. tostring(m.params.n) end,
            })
            assert(r.ok == true and r.result.content[1].text == "x", "response still settles")
            assert(seen_request_meta ~= nil and type(seen_request_meta.progressToken) == "string",
                   "on_progress opts the request in with a progressToken")
            assert(#events == 2, "both streamed messages surfaced, got " .. tostring(#events))
            assert(events[1] == "progress:" .. seen_request_meta.progressToken,
                   "progress routed with the matching token, got " .. events[1])
            assert(events[2] == "message:1", "per-call on_message routed in order, got " .. events[2])
            assert(global_hits == 0, "per-call on_message won over the global one")
            -- on_progress-only callopts: no _meta injected with on_message alone.
            local args = { text = "y" }
            local r2 = conn:invoke("probe", args, { on_message = function() end })
            assert(r2.ok == true, "on_message-only round settles")
            assert(args._meta == nil, "caller's params table is never mutated")
            conn:close()
            return true
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "mcp per-call streaming failed");
    }

    #[test]
    fn mcp_progress_without_on_progress_falls_back_to_global() {
        // Streaming is opt-in: without on_progress no `_meta.progressToken` is
        // injected and progress notifications fall through to the global
        // opts.on_message, exactly like any other inbound notification.
        //
        // This is now the `draw = false` case, and that scoping is the point:
        // a connection that draws sets `on_progress` on the caller's behalf, so
        // the opt-out is the only way to get the old wire behaviour — which is
        // why it forwards the callopts *untouched* rather than merely skipping
        // the panel. The default path is `mcp_a_wire_call_draws_its_own_panel`.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
                body = r#"
            local base_call = handlers["tools/call"]
            local seen_request_meta
            handlers["tools/call"] = function(req)
              local msgs = base_call(req)
              seen_request_meta = req.params._meta
              local token = seen_request_meta and seen_request_meta.progressToken or nil
              table.insert(msgs, 1, { jsonrpc = "2.0", method = "notifications/progress",
                                      params = { progressToken = token, progress = 1 } })
              return msgs
            end
            local notes = {}
            local conn = agent.mcp("s", fake_mcp_func(handlers),
                                   { draw = false,
                                     on_message = function(m) notes[#notes + 1] = m end })
            local r = conn.probe({ text = "x" })
            assert(r.ok == true and r.result.content[1].text == "x", "response still settles")
            assert(seen_request_meta == nil, "no progressToken without on_progress")
            assert(#notes == 1 and notes[1].method == "notifications/progress",
                   "progress fell back to the global on_message")
            conn:close()
            return true
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "mcp opt-in progress fallback failed");
    }

    /// What the drawing path puts in the transcript, read back off the sink as
    /// one string — `Create` contributes its title, everything else its text.
    fn drawn(sink: &crate::panels::PanelSink) -> String {
        sink.ops()
            .iter()
            .map(|op| match op {
                PanelOp::Create { title, .. } => format!("┌─ {title}\n"),
                PanelOp::Append { text, .. } => text.clone(),
                _ => String::new(),
            })
            .collect()
    }

    /// An MCP tool cannot report itself — its code is across the wire — so the
    /// connection draws the panel on its behalf. This is that, end to end
    /// through the real protocol against the in-process fake.
    ///
    /// The assertions are the ones that make it the *same* behaviour a local
    /// tool gets rather than a different one: a titled panel, opened before the
    /// request, holding the result's **text** rather than its JSON envelope.
    #[test]
    fn mcp_a_wire_call_draws_its_own_panel() {
        let sink = crate::panels::PanelSink::default();
        let lua = new_vm_with_sink(Some(&sink)).expect("agent VM");
        let ok: bool = lua
            .load(format!(
                "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
                body = r#"
            local conn = agent.mcp("wiki", fake_mcp_func(handlers))
            local r = conn.probe({ text = "hi there" })
            assert(r.ok == true, "the call still returns its result")
            conn:close()
            return true
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "mcp drawing path failed");

        // Opened *before* the result arrived, so a slow call is visibly in
        // flight rather than appearing all at once when it finishes. The order
        // of the ops is the evidence.
        let ops = sink.ops();
        assert!(
            matches!(ops.first(), Some(PanelOp::Create { .. })),
            "the panel is created first, then filled: {ops:?}"
        );

        let panel = drawn(&sink);
        // Titled the way tools are named everywhere else.
        assert!(
            panel.contains("┌─ wiki.probe"),
            "a panel titled {{connection}}.{{tool}}: {panel:?}"
        );
        // The result's text, not the envelope around it.
        assert!(
            panel.contains("hi there"),
            "the text block is shown: {panel:?}"
        );
        assert!(
            !panel.contains("\"content\"") && !panel.contains("\"type\":\"text\""),
            "and not the JSON envelope it arrived in: {panel:?}"
        );
    }

    /// `draw = false` is the escape hatch, and it has to be exact: no panel ops
    /// at all, and the request on the wire byte for byte what it always was.
    #[test]
    fn mcp_draw_false_keeps_the_call_silent_and_the_wire_unchanged() {
        let sink = crate::panels::PanelSink::default();
        let lua = new_vm_with_sink(Some(&sink)).expect("agent VM");
        let ok: bool = lua
            .load(format!(
                "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
                body = r#"
            local base_call = handlers["tools/call"]
            handlers["tools/call"] = function(req)
              __seen_meta = req.params._meta
              return base_call(req)
            end
            local conn = agent.mcp("wiki", fake_mcp_func(handlers), { draw = false })
            local r = conn.probe({ text = "hi there" })
            assert(r.ok == true, "and the call still works")
            assert(__seen_meta == nil, "no _meta at all: the callopts went through untouched")
            conn:close()
            return true
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "the draw=false path failed");
        assert!(
            sink.ops().is_empty(),
            "and an opted-out connection draws nothing: {:?}",
            sink.ops()
        );
    }

    /// The two shapes that are not a plain text result, and one failure. All
    /// three used to be a wall of JSON or nothing at all.
    #[test]
    fn mcp_panels_show_text_json_and_failure() {
        let sink = crate::panels::PanelSink::default();
        let lua = new_vm_with_sink(Some(&sink)).expect("agent VM");
        let ok: bool = lua
            .load(format!(
                "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
                body = r#"
            -- A result with no text block at all: shown as indented JSON, so a
            -- structured result is never reduced to nothing.
            handlers["tools/call"] = function(req)
              if req.params.name == "structured" then
                return { { jsonrpc = "2.0", id = req.id,
                           result = { content = { { type = "image", data = "…" } },
                                      meta = { rows = 2, ok = true } } } }
              end
              if req.params.name == "boom" then
                return { { jsonrpc = "2.0", id = req.id,
                           error = { code = -32000, message = "the server said no" } } }
              end
              -- The shape a real server actually uses for a failed tool: the
              -- call succeeds, `isError` is set, and the content is a generic
              -- sentence. Checked because a real `mcp` server does exactly
              -- this, so a failure can arrive looking like a result.
              if req.params.name == "iserr" then
                return { { jsonrpc = "2.0", id = req.id,
                           result = { isError = true,
                                      content = { { type = "text",
                                                    text = "Error executing tool iserr" } } } } }
              end
              error("fake func: unexpected tool " .. tostring(req.params.name))
            end
            -- Two more tools for these cases, advertised alongside the usual.
            local base_list = handlers["tools/list"]
            handlers["tools/list"] = function(req)
              local msgs = base_list(req)
              for _, t in ipairs({ "structured", "boom", "iserr" }) do
                table.insert(msgs[1].result.tools, {
                  name = t, description = t,
                  inputSchema = { type = "object", properties = {} } })
              end
              return msgs
            end
            local conn = agent.mcp("wiki", fake_mcp_func(handlers))
            conn.structured({})
            conn.boom({})
            conn.iserr({})
            conn:close()
            return true
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "mcp result shapes failed");

        let panel = drawn(&sink);
        // Indented, and it kept the structure rather than printing it flat.
        assert!(
            panel.contains("\"rows\": 2") && panel.contains("\"ok\": true"),
            "a textless result is shown as indented JSON: {panel:?}"
        );
        assert!(
            panel.contains("the server said no"),
            "and a JSON-RPC failure is reported in the call's own panel: {panel:?}"
        );
        // A tool that failed while the call succeeded: `isError` with a generic
        // sentence, which is what a real MCP server sends. Unmarked it would be
        // indistinguishable from a result.
        assert!(
            panel.contains("error: Error executing tool iserr"),
            "an isError result is marked as the failure it is: {panel:?}"
        );
    }

    /// A tool with a Lua `callback` is running on this VM, so it can ask for
    /// its own panel. Drawing for it too would be the double output the whole
    /// arrangement exists to prevent — so this path is left alone.
    #[test]
    fn mcp_a_callback_tool_is_left_to_draw_itself() {
        let sink = crate::panels::PanelSink::default();
        let lua = new_vm_with_sink(Some(&sink)).expect("agent VM");
        let ok: bool = lua
            .load(format!(
                "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
                body = r#"
            local conn = agent.mcp("wiki", fake_mcp_func(handlers))
            -- The override: same connection, but this tool answers in Lua.
            -- The same override shape `mcp_tool_callback_overrides_the_rpc`
            -- uses: a callback on a tool the server advertised.
            conn.probe.callback = function()
              return { content = { { type = "text", text = "answered here" } } }
            end
            local r = conn.probe({})
            assert(r.ok == true, "the callback answers")
            conn:close()
            return true
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "the callback-tool path failed");
        assert!(
            sink.ops().is_empty(),
            "a tool that can draw for itself is not drawn for: {:?}",
            sink.ops()
        );
    }

    #[test]
    fn mcp_invoke_rejects_bad_callopts_and_unknown_tool() {
        // conn:invoke validates callopts up front (a programming error raises,
        // it must never half-over-the-wire) and reports unknown tools as a
        // result error, matching the tool-object shape.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
                body = r#"
            local conn = agent.mcp("s", fake_mcp_func(handlers))
            assert(not pcall(function() conn:invoke("probe", {}, 5) end),
                   "non-table callopts raises")
            assert(not pcall(function() conn:invoke("probe", {}, { on_progress = "x" }) end),
                   "non-function on_progress raises")
            assert(not pcall(function() conn:invoke("probe", {}, { on_message = 7 }) end),
                   "non-function on_message raises")
            local u = conn:invoke("nope", {}, { on_progress = function() end })
            assert(u.ok == false and u.error ~= nil and u.error:find("unknown tool", 1, true) ~= nil,
                   "unknown tool reports a result error")
            local e = conn:invoke("probe", { text = "z" })
            assert(e.ok == true and e.result.content[1].text == "z", "plain conn:invoke works")
            conn:close()
            return true
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "mcp invoke validation failed");
    }

    #[test]
    fn mcp_tool_call_round_is_coroutine_wrappable() {
        // Wrapping an MCP round in a coroutine works: the request/dispatch
        // chain from the coroutine to the streaming callbacks is pure Lua, so
        // on_progress may yield progress events to the pump and the final
        // result arrives on the next resume. Phase-B async is up to users; this
        // is the guarantee they build on.
        let lua = vm();
        let ok: bool = lua
            .load(format!(
                "{FAKE_MCP_FUNC}\n{FAKE_MCP_HANDLERS}\n{body}",
                body = r#"
            local base_call = handlers["tools/call"]
            handlers["tools/call"] = function(req)
              local msgs = base_call(req)
              if req.params.arguments.text ~= nil then
                local token = req.params._meta and req.params._meta.progressToken
                table.insert(msgs, 1, { jsonrpc = "2.0", method = "notifications/progress",
                                        params = { progressToken = token, progress = 1 } })
              end
              return msgs
            end
            local conn = agent.mcp("s", fake_mcp_func(handlers))
            local co = coroutine.create(function()
              local r = conn:invoke("probe", { text = "hi" }, {
                on_progress = function(m) coroutine.yield({ kind = "progress", p = m }) end,
              })
              coroutine.yield({ kind = "done", r = r })
            end)
            local seen = {}
            local done
            while true do
              local okco, ev = coroutine.resume(co)
              assert(okco, "coroutine body ran clean")
              if ev == nil then break end
              seen[#seen + 1] = ev.kind
              if ev.kind == "done" then
                done = ev.r
                break
              end
            end
            assert(done ~= nil and done.ok == true and done.result.content[1].text == "hi",
                   "final result arrives through the coroutine wrapper")
            assert(#seen == 2 and seen[1] == "progress" and seen[2] == "done",
                   "progress yielded to the pump before done, got " .. table.concat(seen, ","))
            assert(coroutine.resume(co), "coroutine finishes cleanly after done")
            conn:close()
            return true
            "#
            ))
            .eval()
            .expect("eval");
        assert!(ok, "mcp coroutine wrapper failed");
    }

    #[test]
    fn mcp_json_bridge_is_wired_into_the_agent_vm() {
        // The JSON text boundary (src/mcp.rs) is installed on the real agent
        // namespace, not only on bare VMs.
        let lua = vm();
        let ok: bool = lua
            .load(
                r#"
            local enc = agent.api.json_encode({ jsonrpc = "2.0", id = 7, method = "tools/call",
                                            params = { name = "probe", arguments = { text = "hi" } } })
            local dec = agent.api.json_decode(enc)
            return dec.id == 7 and dec.method == "tools/call" and dec.params.name == "probe"
                   and dec.params.arguments.text == "hi"
            "#,
            )
            .eval()
            .expect("eval");
        assert!(ok, "json bridge must work inside the agent VM");
    }

    // ---------------------------------------------------------------------
    // HTTP(S) transport: `agent.http` (both routes) against the fake server.
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn agent_http_streams_body_into_on_chunk_and_on_done() {
        // The request goes out with body + headers; the response status,
        // headers and streamed body arrive through the callbacks.
        let fake = FakeHttpServer::start(|req: FakeRequest| {
            assert_eq!(req.method, "POST");
            assert_eq!(req.body, r#"{"hello":"world"}"#);
            assert!(
                req.headers
                    .iter()
                    .any(|(k, v)| k == "content-type" && v == "application/json"),
                "content-type header must reach the server"
            );
            FakeServerReply::Response(FakeResponse {
                status: 200,
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: req.body,
            })
        });
        let lua = vm();
        let ok: bool = eval_reactor(
            &lua,
            &format!(
                r#"
            local chunks, done = {{}}, nil
            local s = agent.http("POST", "{url}", {{
              body = '{{"hello":"world"}}',
              headers = {{ ["content-type"] = "application/json" }},
              on_chunk = function(c) chunks[#chunks + 1] = c end,
              on_done = function(o) done = o end,
            }})
            s:run()
            assert(done ~= nil and done.status == 200, "on_done carries the status")
            assert(done.headers["content-type"] == "application/json", "headers surface")
            assert(table.concat(chunks) == '{{"hello":"world"}}', "body streamed")
            assert(s.status == 200, "stream object exposes the status")
            s:close()
            return true
            "#,
                url = fake.url("/http")
            ),
        )
        .await
        .expect("eval");
        assert!(ok, "agent.http streaming flow failed");
    }

    #[tokio::test]
    async fn agent_http_reports_transport_error_to_on_error() {
        // A port with nothing listening: on_error fires (not a raise).
        let dead = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let dead_addr = dead.local_addr().expect("addr");
        drop(dead);
        let lua = vm();
        let ok: bool = eval_reactor(
            &lua,
            &format!(
                r#"
            local err = nil
            local s = agent.http("POST", "http://{addr}/nope", {{
              body = "x",
              on_error = function(e) err = e end,
            }})
            s:run()
            assert(err ~= nil, "on_error must fire on a transport failure")
            assert(s.error ~= nil and s.done == true, "stream object records the error")
            s:close()
            return true
            "#,
                addr = dead_addr
            ),
        )
        .await
        .expect("eval");
        assert!(ok, "agent.http transport-error flow failed");
    }

    #[tokio::test]
    async fn agent_sse_streams_events_into_on_event() {
        let fake = FakeHttpServer::start(|_req: FakeRequest| {
            FakeServerReply::StreamEvents(vec![
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n"
                    .to_string(),
                "event: note\ndata: hello\n\n".to_string(),
            ])
        });
        let lua = vm();
        let ok: bool = eval_reactor(
            &lua,
            &format!(
                r#"
            local got, closed = {{}}, false
            local s = agent.http("GET", "{url}", {{
              headers = {{ ["accept"] = "text/event-stream" }},
              on_event = function(event, data) got[#got + 1] = event .. "|" .. data end,
              on_done = function() closed = true end,
            }})
            s:run()
            assert(#got == 2, "both SSE events arrive")
            assert(got[1] == 'message|{{"jsonrpc":"2.0","id":1,"result":{{"ok":true}}}}', got[1])
            assert(got[2] == "note|hello", got[2])
            assert(closed, "on_done fires at the stream end")
            s:close()
            return true
            "#,
                url = fake.url("/events")
            ),
        )
        .await
        .expect("eval");
        assert!(ok, "the event-stream route of agent.http failed");
    }

    #[test]
    fn agent_http_sse_validation() {
        // Bad args are rejected before anything is fired.
        let lua = vm();
        let ok: bool = lua
            .load(
                r#"
            assert(not pcall(agent.http, 42, "http://x", {}), "bad method rejected")
            assert(not pcall(agent.http, "POST", "ftp://x", {}), "non-http url rejected")
            assert(not pcall(agent.http, "POST", "http://x", 5), "bad opts rejected")
            assert(not pcall(agent.http, "POST", "http://x", { on_chunk = "nope" }), "bad cb rejected")
            assert(not pcall(agent.http, "POST", "http://x", { headers = 5 }), "bad headers rejected")
            assert(not pcall(agent.http, "GET", nil, {}), "bad url rejected")
            assert(not pcall(agent.http, "GET", "http://x", { on_event = 5 }), "bad cb rejected")
            -- The stream route is what on_event + no body selects; the SSE
            -- transport is not reachable as a separate interface anymore.
            assert(agent.sse == nil, "agent.sse is merged into agent.http")
            return true
            "#,
            )
            .eval()
            .expect("eval");
        assert!(ok, "transport validation must reject bad args");
    }

    #[test]
    fn agent_panel_drives_the_sink() {
        let sink = PanelSink::default();
        let lua = new_vm_with_sink(Some(&sink)).expect("agent VM");
        lua.load(
            r#"
            local p = agent.panel("log", { boxed = false, conceal_box = false })
            p:append("line one\n")
            p:append("line two\n")
            p:highlight(0, 9, "bold.cyan")
            p:set("replaced")
            p:clear_regions()
            return true
            "#,
        )
        .eval::<bool>()
        .expect("eval");
        assert_eq!(
            sink.ops(),
            vec![
                PanelOp::Create {
                    id: 1,
                    title: "log".into(),
                    boxed: false,
                    conceal_box: false
                },
                PanelOp::Append {
                    id: 1,
                    text: "line one\n".into()
                },
                PanelOp::Append {
                    id: 1,
                    text: "line two\n".into()
                },
                PanelOp::Highlight {
                    id: 1,
                    start: 0,
                    end: 9,
                    style: "bold.cyan".into()
                },
                PanelOp::Set {
                    id: 1,
                    text: "replaced".into()
                },
                PanelOp::ClearRegions { id: 1 },
            ]
        );
    }

    #[test]
    fn agent_panel_defaults_and_is_noop_headless() {
        // No sink: the calls succeed but record nothing.
        let lua = vm();
        let ok: bool = lua
            .load(
                r#"
                local p = agent.panel("log")
                p:append("x")
                p:highlight(0, 1, "bold")
                return p.id >= 1
                "#,
            )
            .eval()
            .expect("eval headless panel calls");
        assert!(ok, "headless panel calls are graceful no-ops");
        // Default opts: boxed and conceal_box both on.
        let sink = PanelSink::default();
        let lua = new_vm_with_sink(Some(&sink)).expect("agent VM");
        lua.load(r#"agent.panel("log") return true"#)
            .eval::<bool>()
            .expect("eval");
        assert_eq!(
            sink.ops(),
            vec![PanelOp::Create {
                id: 1,
                title: "log".into(),
                boxed: true,
                conceal_box: true
            }]
        );
    }

    #[test]
    fn agent_panel_rejects_bad_options() {
        let lua = vm();
        let ok: bool = lua
            .load(
                r#"
            assert(not pcall(agent.panel, "log", { boxed = "yes" }), "non-bool boxed rejected")
            assert(not pcall(agent.panel, nil, {}), "nil title rejected")
            assert(not pcall(agent.api.panel_highlight, 1, 0, 2, nil), "nil style rejected")
            return true
            "#,
            )
            .eval()
            .expect("eval");
        assert!(ok, "panel arg validation rejects bad values");
    }

    #[test]
    fn agent_split_panel_drives_the_sink() {
        // `agent.split_panel` is the sibling driving API of `agent.panel`:
        // one titled box, several regions, each pane with its own text and
        // declared language (the building block for a Lua `apply_patch`).
        let sink = PanelSink::default();
        let lua = new_vm_with_sink(Some(&sink)).expect("agent VM");
        lua.load(
            r#"
            local p = agent.split_panel("apply_patch", {
                { caption = "before", lang = "bash" },
                "after",
            })
            p:set(1, "echo old")
            p:set(2, "echo new")
            p:highlight(2, 5, 8, "bold.green")
            p:lang(1, "bash")
            p:clear_regions(2)
            return true
            "#,
        )
        .eval::<bool>()
        .expect("eval");
        assert_eq!(
            sink.ops(),
            vec![
                PanelOp::Split {
                    id: 1,
                    title: "apply_patch".into(),
                    panes: vec![
                        PaneInit {
                            caption: "before".into(),
                            lang: Some("bash".into())
                        },
                        PaneInit {
                            caption: "after".into(),
                            lang: None
                        },
                    ],
                },
                PanelOp::SetPane {
                    id: 1,
                    pane: 1,
                    text: "echo old".into()
                },
                PanelOp::SetPane {
                    id: 1,
                    pane: 2,
                    text: "echo new".into()
                },
                PanelOp::HighlightPane {
                    id: 1,
                    pane: 2,
                    start: 5,
                    end: 8,
                    style: "bold.green".into(),
                },
                PanelOp::SetPaneLang {
                    id: 1,
                    pane: 1,
                    lang: Some("bash".into())
                },
                PanelOp::ClearPaneRegions { id: 1, pane: 2 },
            ]
        );
    }

    #[test]
    fn agent_split_panel_is_a_noop_headless_and_validates() {
        // No sink: the calls succeed and ids still allocate (per-VM counter).
        let lua = vm();
        let ok: bool = lua
            .load(
                r#"
                local p = agent.split_panel("t", { "a", "b" })
                p:set(2, "x")
                p:highlight(1, 0, 1, "bold")
                p:lang(2, nil)
                return p.id >= 1
                "#,
            )
            .eval()
            .expect("eval headless split panel calls");
        assert!(ok, "headless split panel calls are graceful no-ops");
        let ok: bool = lua
            .load(
                r#"
                assert(not pcall(agent.split_panel, "t", {}), "empty panes rejected")
                assert(not pcall(agent.split_panel, "t", { 42 }), "non-string/table pane rejected")
                assert(not pcall(agent.split_panel, "t", { { caption = 5 } }), "bad caption rejected")
                assert(not pcall(agent.split_panel, "t", { { lang = 5 } }), "bad lang rejected")
                assert(not pcall(agent.split_panel, "t", nil), "nil panes rejected")
                assert(not pcall(agent.split_panel), "missing args rejected")
                return true
                "#,
            )
            .eval()
            .expect("eval");
        assert!(ok, "split panel validation rejects bad input");
        // A pane table with neither caption nor lang is fine (blank pane).
        let sink = PanelSink::default();
        let lua = new_vm_with_sink(Some(&sink)).expect("agent VM");
        lua.load(r#"agent.split_panel("t", { {} }) return true"#)
            .eval::<bool>()
            .expect("eval");
        assert_eq!(
            sink.ops(),
            vec![PanelOp::Split {
                id: 1,
                title: "t".into(),
                panes: vec![PaneInit {
                    caption: "".into(),
                    lang: None
                }],
            }]
        );
    }

    #[test]
    fn the_policy_can_emit_panel_ops() {
        // Policy Lua (inside a real sandboxed run) drives `agent.panel`; the
        // ops land in the round's sink while the sandbox outcome stays intact.
        // The wrapper's "bash result" panel streams in after the policy's own
        // panel (ids from the same sink allocator, so they never collide).
        let sink = PanelSink::default();
        let policy = r#"
local policy = setmetatable({}, { __index = function() return function() return true end end })
local p = agent.panel("sandbox-note", { boxed = false })
p:append("run started\n")
return policy
"#;
        let out = run_bash("echo hi", policy, Some(&sink), None)
            .expect("bash run");
        assert_eq!(out.stdout, "hi\n");
        assert!(!out.failed());
        // Only the policy's own panel: the "bash result" stream panel around the
        // run is the *tool's* (`lua/bash_tool.lua`), asserted in
        // `the_bash_tool_streams_stdout_into_a_result_panel`.
        let _ = &sink;
        assert_eq!(
            sink.ops(),
            vec![
                PanelOp::Create {
                    id: 1,
                    title: "sandbox-note".into(),
                    boxed: false,
                    conceal_box: true
                },
                PanelOp::Append {
                    id: 1,
                    text: "run started\n".into()
                },
            ]
        );
    }

    #[test]
    fn the_policy_can_emit_split_panel_ops() {
        // The end-to-end shape of a Lua `apply_patch`: policy Lua (inside a
        // real sandboxed run) shows the before/after regions in one split
        // panel — captions plus per-pane declared languages — and the ops
        // stream into the round's sink next to the wrapper's result panel.
        let sink = PanelSink::default();
        let policy = r#"
local policy = setmetatable({}, { __index = function() return function() return true end end })
local p = agent.split_panel("apply_patch", {
    { caption = "before", lang = "bash" },
    { caption = "after", lang = "bash" },
})
p:set(1, "echo old")
p:set(2, "echo new")
p:highlight(2, 5, 8, "bold.green")
return policy
"#;
        let out = run_bash("echo hi", policy, Some(&sink), None)
            .expect("bash run");
        assert_eq!(out.stdout, "hi\n");
        assert!(!out.failed());
        assert_eq!(
            sink.ops(),
            vec![
                PanelOp::Split {
                    id: 1,
                    title: "apply_patch".into(),
                    panes: vec![
                        PaneInit {
                            caption: "before".into(),
                            lang: Some("bash".into())
                        },
                        PaneInit {
                            caption: "after".into(),
                            lang: Some("bash".into())
                        },
                    ],
                },
                PanelOp::SetPane {
                    id: 1,
                    pane: 1,
                    text: "echo old".into()
                },
                PanelOp::SetPane {
                    id: 1,
                    pane: 2,
                    text: "echo new".into()
                },
                PanelOp::HighlightPane {
                    id: 1,
                    pane: 2,
                    start: 5,
                    end: 8,
                    style: "bold.green".into(),
                },
            ]
        );
    }

    // -----------------------------------------------------------------------
    // Agent config in Lua: the endpoint, the system prompt, and the tools the
    // user registers into `agent.mcps` — the registry Rust reindexes per
    // request, never cached.
    // -----------------------------------------------------------------------

    /// A user-style config (loaded via [`apply_config_source`], which is what
    /// the real file loader runs): tools are whatever the user writes,
    /// registered into `agent.mcps` directly — there is no mode layer, only
    /// the primitives (agent.utils.tool, agent.shq, agent.bash).
    ///
    /// It is also the worked example of the policy convention: a policy is a
    /// local table in the file that applies it, because `agent.bash` takes one
    /// A user's `~/.config/agent/init.lua` has to do what it is for: override
    /// the endpoint and the prompt, and register connections, all through the
    /// real loader, with the per-request reindex picking them up.
    ///
    /// This used to be a test that read "the example config the repo ships" —
    /// and had been quietly passing for as long as no such file existed, because
    /// it returned early when `config_path()` was `None`. The repo ships no
    /// config; the user writes one. So it is written here instead, and asserted
    /// through the same path the loader takes.
    #[test]
    fn tmp_probe_llm() {
        let lua = vm();
        let base: String = lua.load("return tostring(agent.llm.base_url)").eval().unwrap();
        let shq: String = lua.load("return type(agent.shq)").eval().unwrap();
        println!("PROBE base_url={base:?} shq={shq:?}");
    }

    /// Two connections offering the *same* tool name are two tools, and the
    /// names the model sees have to say so.
    ///
    /// This is why tools are advertised as `{connection}.{tool}`: a bare
    /// `list_issues` from two servers is one name for two tools, and the
    /// registry resolves an unqualified name by scanning connections — so one of
    /// them is not merely ambiguous, it is unreachable. Qualifying at the point
    /// of advertisement means the collision cannot be expressed at all.
    #[test]
    fn tool_names_are_qualified_by_their_connection() {
        let lua = vm();
        lua.load(
            r#"
            local function conn(name, toolname)
              return {
                name = name,
                tools = { [toolname] = agent.utils.tool(
                  "the same tool, from " .. name,
                  { type = "object", properties = {} },
                  function () return { ok = true, result = name } end) },
              }
            end
            agent.mcps.alpha = conn("alpha", "list_issues")
            agent.mcps.beta  = conn("beta",  "list_issues")
        "#,
        )
        .exec()
        .expect("two connections with a colliding tool name");

        let names: Vec<String> = mcps_tool_defs(&lua)
            .expect("reindex")
            .into_iter()
            .map(|d| d.name)
            .collect();
        assert_eq!(
            names,
            [
                "alpha.list_issues",
                "bash.bash",
                "beta.list_issues",
                "fs.apply_patch",
                "fs.hand_to_user",
                "fs.read",
                "fs.write_file",
            ],
            "the two colliding tools are two names, alongside the built-ins"
        );

        // And each resolves to *its own* implementation, not the first match.
        for conn in ["alpha", "beta"] {
            let (body, _) = invoke_tool(&lua, &format!("{conn}.list_issues"), "{}")
                .expect("invoke")
                .expect("registered");
            let v: serde_json::Value = serde_json::from_str(&body).expect("tool json");
            assert_eq!(v["result"], conn, "{conn} runs its own tool");
        }

        // The bare name is not a way back in: it is a name the model was never
        // shown, so it resolves to nothing rather than to whichever came first.
        assert!(
            invoke_tool(&lua, "list_issues", "{}").expect("invoke").is_none(),
            "an unqualified name is refused, not guessed at"
        );
    }

    #[test]
    fn a_user_config_overrides_the_built_ins_and_registers_connections() {
        let lua = new_vm_with_sink(None).expect("vm");
        // The built-ins first, so the override is an override and not an
        // initialisation: `apply_config_source` runs on top of the entry script.
        load_init(&lua, &tree()).expect("the entry script");
        assert_eq!(
            llm_config(&lua).expect("llm").model,
            "gpt-4o-mini",
            "the built-in default is what a config starts from"
        );

        let source = r#"
            agent.llm.base_url = "http://127.0.0.1:9/v1"
            agent.llm.model    = "my-local-model"
            agent.llm.system_prompt = "You are a test fixture, and this is the prompt."
            agent.mcps = { echo = { name = "echo", tools = {
                echo = agent.utils.tool("echo one argument back", {
                  type = "object",
                  properties = { line = { type = "string", description = "the line" } },
                  required = { "line" },
                }, function (a) return { ok = true, result = a.line } end),
            } } }
        "#;
        apply_config_source(&lua, source).expect("the user config applies");

        let llm = llm_config(&lua).expect("llm");
        assert_eq!(llm.base_url, "http://127.0.0.1:9/v1", "the endpoint is overridden");
        assert_eq!(llm.model, "my-local-model", "and so is the model");
        assert!(
            system_prompt(&lua).expect("prompt").contains("test fixture"),
            "and the prompt"
        );

        // The registry is what the request advertises, and this config replaced
        // it wholesale — so only its own tool is offered.
        let defs = mcps_tool_defs(&lua).expect("reindex");
        let names: Vec<&str> = defs.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(
            names,
            ["echo.echo"],
            "the config's registry — qualified by the connection name it chose"
        );

        for tool in &defs {
            assert_eq!(tool.parameters["type"], "object", "{} advertises a schema", tool.name);
            assert!(!tool.description.is_empty(), "{} has a description", tool.name);
            assert!(
                invoke_tool(&lua, &tool.name, r#"{"line":"hi"}"#)
                    .expect("invoke")
                    .is_some(),
                "{} is registered and callable",
                tool.name
            );
        }
    }

    /// Where the config is looked for: one path, under `$HOME`, and it has to
    /// exist to count. Asserted through the `$HOME`-taking form so it does not
    /// depend on whoever is running the suite.
    /// The loader seeds the user's config from the shipped one, once, and runs
    /// *that* — after which the file in `$HOME` is the configuration, not an
    /// overlay on it.
    ///
    /// Both halves matter. Seeding means a user who has never run the agent ends
    /// up with a file they can read and edit, instead of having to write one from
    /// a manual. And "runs that, not both" means the file they edit is the whole
    /// truth: there is no second script underneath quietly contributing
    /// connections the user cannot see or remove.
    /// A test that reads the invoking user's `~/.config/agent/init.lua` is a
    /// test that passes on one machine and fails on the next, and one that
    /// passes or fails depending on what the operator last edited. This pins
    /// the two doors that opened onto `$HOME`.
    ///
    /// It runs a test VM with the *tree's* configuration and a config in a
    /// temporary home that would be obviously wrong if it were read, and asserts
    /// the VM came from the tree.
    #[test]
    fn the_test_suite_never_reads_the_real_home_directory() {
        // 1. `ConfigSource::default()` — what every `new_vm` uses — is the tree.
        assert_eq!(ConfigSource::default(), ConfigSource::Tree);
        // The tree's entry script registers the shell and the file tools. A
        // user's config need not — the hostile one this suite has been run
        // against registers neither — so their presence is the evidence.
        let lua = vm();
        let names: Vec<String> = mcps_tool_defs(&lua)
            .expect("reindex")
            .into_iter()
            .map(|d| d.name)
            .collect();
        assert_eq!(
            names,
            [
                "bash.bash",
                "fs.apply_patch",
                "fs.hand_to_user",
                "fs.read",
                "fs.write_file",
            ],
            "a plain VM has the shipped configuration, not the operator's"
        );

        // 2. The standalone tool-invocation path takes its configuration as an
        //    argument, so a test passes the tree explicitly rather than
        //    inheriting whatever is in `$HOME`. (Registration is the check; the
        //    call itself would need a sandbox answer, and a headless run denies
        //    every ask.)
        assert!(
            invoke_mcp_tool_with_asks("bash.bash", "{}", None, None, &ConfigSource::Tree)
                .expect("invoke")
                .is_some(),
            "the tree's configuration, found by name"
        );
        assert!(
            invoke_mcp_tool_with_asks("no.such.tool", "{}", None, None, &ConfigSource::Tree)
                .expect("invoke")
                .is_none(),
            "and nothing else is"
        );
    }

    #[test]
    fn the_users_config_is_seeded_from_the_shipped_one_and_then_belongs_to_them() {
        let home = std::env::temp_dir().join(format!("agent-seed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).expect("fake home");
        let cfg = home.join(".config").join("agent").join("init.lua");

        // First run: no file, so the shipped one is copied there and that is the
        // script the VM is configured by.
        let (path, origin) = ensure_config(&tree(), Some(&home));
        assert_eq!(path, cfg, "the config is the user's own copy");
        assert_eq!(origin, ConfigOrigin::Seeded);
        assert!(cfg.is_file(), "and it exists now: {}", cfg.display());
        let seeded = std::fs::read_to_string(&cfg).expect("read the seeded config");
        assert!(
            seeded.contains("agent.llm"),
            "seeded from the real entry script, not a stub: {} bytes",
            seeded.len()
        );

        // A VM configured from the seeded file is a whole agent — the copy is
        // the real entry script, not a stub.
        let run = |home: &std::path::Path| -> Result<Lua, String> {
            let lua = Lua::new_with(STDLIB, mlua::LuaOptions::default()).map_err(|e| e.to_string())?;
            setup_tree(
                &lua,
                None,
                None,
                &tree(),
                &ConfigSource::UserHome(Some(home.to_path_buf())),
            )
            .map_err(|e| e.to_string())?;
            Ok(lua)
        };
        let seeded_vm = run(&home).expect("the seeded copy configures a VM");
        assert_eq!(
            llm_config(&seeded_vm).expect("llm").base_url,
            "https://api.openai.com/v1",
            "the seeded copy configures a working agent"
        );
        assert_eq!(
            mcps_tool_defs(&seeded_vm).expect("reindex").len(),
            5,
            "shell and the four file tools"
        );

        // Second run: the user's file is the configuration, never re-seeded
        // over. Note what an edit has to look like now: the file is the *whole*
        // config, so it is also what creates the tables it sets.
        std::fs::write(
            &cfg,
            "agent.llm = agent.llm or { base_url = 'x', model = 'x', api_key = '' }\n\
             agent.llm.model = 'mine'\n",
        )
        .expect("edit the config");
        let (path, origin) = ensure_config(&tree(), Some(&home));
        assert_eq!((path, origin), (cfg.clone(), ConfigOrigin::Existing));
        assert!(
            std::fs::read_to_string(&cfg).expect("read").contains("'mine'"),
            "an existing config is never re-seeded over"
        );

        let edited = run(&home).expect("the edited config loads");
        assert_eq!(
            llm_config(&edited).expect("llm").model,
            "mine",
            "the edit is what the VM runs"
        );
        assert!(
            mcps_tool_defs(&edited).expect("reindex").is_empty(),
            "and nothing else is layered underneath: replacing the file replaces \
             the configuration, which is the point of it being the user's"
        );

        // And a config may be as short as the one thing it wants to change. The
        // loader creates `agent.llm` before the config runs, precisely so that
        // a three-line file is a working configuration — a user who writes their
        // own from scratch should not have to reproduce a table constructor to
        // set a field on it.
        std::fs::write(&cfg, "agent.llm.model = 'short'\n").expect("a minimal config");
        let short = run(&home).expect("a one-line config loads");
        assert_eq!(llm_config(&short).expect("llm").model, "short");
        assert_eq!(
            llm_config(&short).expect("llm").base_url,
            "https://api.openai.com/v1",
            "and the fields it does not mention fall back to the default"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    /// A home that cannot be written must not stop the agent: it runs the
    /// shipped defaults and says so. An agent that will not start is worse than
    /// one that is not configured.
    #[test]
    fn an_unwritable_home_falls_back_to_the_shipped_defaults() {
        // A path whose parent is a *file*, so creating the directory under it
        // cannot work — no permission fiddling, and it fails the same way on
        // every platform and whether or not the suite runs as root.
        let blocker = std::env::temp_dir().join(format!("agent-blocked-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&blocker);
        std::fs::create_dir_all(&blocker).expect("scratch");
        std::fs::write(blocker.join("not-a-dir"), "x").expect("a file where a dir must go");

        let (path, origin) = ensure_config(&tree(), Some(&blocker.join("not-a-dir")));
        assert_eq!(origin, ConfigOrigin::Tree, "reported, not fatal");
        assert_eq!(
            path,
            tree().join("init.lua"),
            "and the shipped script is used instead"
        );
        let _ = std::fs::remove_dir_all(&blocker);
    }

    #[test]
    fn the_user_config_is_one_path_under_home() {
        let dir = std::env::temp_dir().join(format!("agent-confighome-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = dir.join(".config").join("agent");
        std::fs::create_dir_all(&cfg).expect("make a fake home");

        // Nothing there yet: no config is the normal case, and the built-ins
        // stand on their own.
        assert_eq!(config_path_in(Some(dir.clone())), None);
        assert_eq!(config_path_in(None), None, "and no HOME is not an error");

        // A directory that exists but is not the file is still no config.
        std::fs::create_dir_all(cfg.join("init.lua")).expect("a decoy directory");
        assert_eq!(config_path_in(Some(dir.clone())), None, "a directory is not a config");

        std::fs::remove_dir_all(cfg.join("init.lua")).expect("clear the decoy");
        std::fs::write(cfg.join("init.lua"), "-- nothing\n").expect("write a config");
        assert_eq!(
            config_path_in(Some(dir.clone())),
            Some(cfg.join("init.lua")),
            "one path: ~/.config/agent/init.lua"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A VM with the built-in configuration taken back off: no connections, no
    /// mode in force, no prompt — a neutral `agent` for the tests that need one.
    ///
    /// The built-ins are real (the entry script registers the file tools, the
    /// shell and the `coding` mode, so a fresh checkout is usable), which means a
    /// plain `vm()` is no longer neutral. This is the way to ask for the old
    /// starting point rather than working around it in each test.
    fn neutral_vm() -> mlua::Lua {
        let lua = vm();
        lua.load(
            r#"
        agent.mode.set()             -- off the built-in default, back to the baseline
        agent.mcps = {}              -- …and the baseline registry itself
        agent.llm.system_prompt = ""
        agent.mode.forget_all()      -- no modes registered at all
    "#,
        )
        .exec()
        .expect("strip the built-in configuration");
        lua
    }

    /// A VM with the agent's built-in configuration — the connections and the
    /// modes, which `lua/init.lua` registers as the defaults — so the tests
    /// exercise the real Lua tools.
    ///
    /// No user config is in play in the test environment, so this is just
    /// `vm()`. It stays a named function because "the agent as it is actually
    /// configured" is a thing the tests mean, and because if a user config were
    /// present it is this line that has to apply it.
    fn shipped_vm() -> mlua::Lua {
        vm()
    }

    /// Drive a tool call the way the event loop does — start it on the config
    /// VM, answer whatever it asks, step it to its result — and collect the
    /// questions it asked. This *is* the tool path now (there is no executor
    /// thread), so pinning it here pins the loop's half of the contract.
    fn drive_on_vm(
        lua: &mlua::Lua,
        name: &str,
        args: &str,
        mut on_ask: impl FnMut(&str, bool) -> AskAnswer,
    ) -> (serde_json::Value, Vec<String>) {
        use ToolStep;
        let Some((mut run, mut step)) = ToolRun::start(lua, name, args).expect("start") else {
            panic!("the registry holds {name}");
        };
        let mut asked = Vec::new();
        // Bounded: a driver that never finishes is a bug, not a test to hang on.
        for _ in 0..1000 {
            match step {
                ToolStep::Returned(body) => {
                    return (
                        serde_json::from_str(&body).expect("tool json"),
                        asked,
                    )
                }
                ToolStep::Ask { text, always } => {
                    asked.push(text.clone());
                    let answer = on_ask(&text, always);
                    step = run.answer(verdict_to_lua(lua, &answer)).expect("answer");
                }
                ToolStep::Waiting { .. } => step = run.wait().expect("wait"),
            }
        }
        panic!("{name} never finished");
    }

    /// Two tool calls in one round, each of which asks — can the TUI hold two
    /// questions at once?
    ///
    /// No, and this pins *why*: a tool call is a coroutine that has to be
    /// yielded back to before it can ask, and the loop keeps exactly one in
    /// flight (`tool_flight: Option<ToolFlight>`), so the second call is not
    /// even started until the first has returned. Driven here the way the loop
    /// drives it, and asserted from the outside: while call one is unanswered,
    /// call two does not exist, so there is nothing for its question to collide
    /// with.
    #[test]
    fn two_asking_tool_calls_are_strictly_sequential() {
        use ToolStep;
        let lua = vm();
        let sink = PanelSink::default();
        install_sink(&lua, &sink).expect("round sink");
        let args = |cmd: &str| format!(r#"{{"cmdline":{}}}"#, serde_json::json!(cmd));

        // Call one: started, and it asks.
        let Some((mut one, step1)) =
            ToolRun::start(&lua, "bash.bash", &args("cat /etc/hostname")).expect("start")
        else {
            panic!("the registry holds bash");
        };
        let step1 = drive_to_ask(&mut one, step1);
        let ToolStep::Ask { text: q1, .. } = &step1 else {
            panic!("expected an ask, got {step1:?}");
        };
        assert!(q1.contains("read"), "the question names the read: {q1}");
        // One panel exists for the first call. The dialog on it is the driver's to
        // draw, and it is what makes the second call's question impossible to
        // confuse with this one: the second call has not started.
        assert_eq!(
            sink.ops()
                .iter()
                .filter(|op| matches!(op, PanelOp::Create { .. }))
                .count(),
            1,
            "one panel so far: {:?}",
            sink.ops()
        );

        // Answer it; only once it has returned does call two begin.
        let v: serde_json::Value = serde_json::from_str(&drive_to_end(&mut one, step1))
            .expect("tool json");
        assert_eq!(v["ok"], true, "{v}");

        let Some((mut two, step2)) =
            ToolRun::start(&lua, "bash.bash", &args("cat /etc/hosts")).expect("start")
        else {
            panic!("the registry holds bash");
        };
        let step2 = drive_to_ask(&mut two, step2);
        let ToolStep::Ask { text: q2, .. } = &step2 else {
            panic!("expected an ask, got {step2:?}");
        };
        assert!(q2.contains("read"), "{q2}");
        let v: serde_json::Value = serde_json::from_str(&drive_to_end(&mut two, step2))
            .expect("tool json");
        assert_eq!(v["ok"], true, "{v}");

        // Two panels, each titled with its own command, each with its own
        // question, in order.
        let creates: Vec<String> = sink
            .ops()
            .iter()
            .filter_map(|op| match op {
                PanelOp::Create { title, .. } => Some(title.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(
            creates,
            ["cat /etc/hostname", "cat /etc/hosts"],
            "one panel per call, each titled with its own command"
        );
    }

    /// The other half, and the reason the test above matters: the machinery
    /// *does* let two runs sit on an ask at the same time — nothing in `ToolRun`
    /// or the runtime objects. What prevents it is the loop holding one flight.
    ///
    /// So the single `pending_verdict` slot in `main.rs` is safe by loop
    /// discipline, not by construction. Anyone who later runs tools in parallel
    /// has to widen it to a queue keyed by run, or a verdict will be handed to
    /// whichever coroutine is stepped first. This is the canary for that change.
    #[test]
    fn two_asking_runs_are_possible_but_the_loop_never_gets_there() {
        use ToolStep;
        let lua = vm();
        let sink = PanelSink::default();
        install_sink(&lua, &sink).expect("round sink");
        let args = |cmd: &str| format!(r#"{{"cmdline":{}}}"#, serde_json::json!(cmd));
        let start = |cmd: &str| {
            let Some(pair) = ToolRun::start(&lua, "bash.bash", &args(cmd)).unwrap() else {
                panic!("the registry holds bash");
            };
            pair
        };

        let (mut one, s1) = start("cat /etc/hostname");
        let (mut two, s2) = start("cat /etc/hosts");
        let s1 = drive_to_ask(&mut one, s1);
        let s2 = drive_to_ask(&mut two, s2);

        // Both suspended mid-ask simultaneously, with an overlay each. This is
        // the state the loop must never reach, and nothing below stops it.
        assert!(
            matches!(s1, ToolStep::Ask { .. }) && matches!(s2, ToolStep::Ask { .. }),
            "two outstanding asks: {s1:?} / {s2:?}"
        );
        assert_eq!(
            sink.ops()
                .iter()
                .filter(|op| matches!(op, PanelOp::Create { .. }))
                .count(),
            2,
            "and two panels, each with a command of its own as its title"
        );

        // One verdict advances one run and leaves the other asking: a single
        // slot is one wide, which is the whole constraint.
        let after = one
            .answer(verdict_to_lua(&lua, &AskAnswer::Allow))
            .expect("answer the first");
        assert!(
            matches!(
                after,
                ToolStep::Waiting { .. } | ToolStep::Ask { .. } | ToolStep::Returned(_)
            ),
            "the first moved on: {after:?}"
        );
        assert!(
            matches!(s2, ToolStep::Ask { .. }),
            "the second is untouched: still asking, unanswered"
        );
    }

    /// Step through the sandbox's cooperative waits until the tool asks, and
    /// hand back that `Ask`.
    ///
    /// An ask is never the *first* step: the drive loop in `lua/lib/bash.lua`
    /// yields once per cadence tick before the sandbox has anything to report,
    /// so a driver that expects an ask immediately sees `Waiting { ms: 20 }`.
    fn drive_to_ask(run: &mut ToolRun<'_>, mut step: ToolStep) -> ToolStep {
        for waited in 0..20_000 {
            match &step {
                ToolStep::Ask { .. } => return step,
                ToolStep::Waiting { ms } => {
                    // The cadence wait is *real* time, and honouring it is what
                    // makes this test deterministic. `ToolRun::wait` only
                    // resumes the coroutine — the `ms` is advice for whoever is
                    // driving it, and the shipped event loop is what acts on it.
                    // A test that spun without sleeping burned its whole 1000
                    // iterations in milliseconds and gave up before the
                    // sandbox's notification was ever delivered, so this test
                    // failed perhaps one run in three under load and passed the
                    // rest. Spinning was never the thing under test.
                    std::thread::sleep(std::time::Duration::from_millis(*ms));
                    step = run.wait().expect("wait");
                }
                ToolStep::Returned(body) => panic!("returned before asking: {body}"),
            }
            let _ = waited;
        }
        panic!("never asked");
    }

    /// A tool already suspended on `first`, answering whatever it asks, driven
    /// to its return. Every ask is allowed, so this is the "press yes to
    /// everything" driver the loop's auto-yes would be.
    fn drive_to_end(run: &mut ToolRun<'_>, first: ToolStep) -> String {
        use ToolStep;
        let mut step = first;
        let mut asks = 0usize;
        let mut waits = 0usize;
        for _ in 0..100000 {
            match step {
                ToolStep::Returned(body) => return body,
                ToolStep::Ask { .. } => {
                    asks += 1;
                    let v = verdict_to_lua(run.lua(), &AskAnswer::Allow);
                    step = run.answer(v).expect("answer");
                }
                ToolStep::Waiting { ms } => {
                    waits += 1;
                    // As in `drive_to_ask`: the cadence is wall time, and a
                    // driver that ignores it races the notification it is
                    // waiting for.
                    std::thread::sleep(std::time::Duration::from_millis(ms));
                    step = run.wait().expect("wait");
                }
            }
        }
        panic!("the tool never finished after {asks} asks and {waits} waits");
    }

    /// The permissive mode's gates ask, in the words the mode specifies.
    ///
    /// The command is `bash` itself doing the syscall, so each case is one real
    /// trapped call: a read-open, a write-open, a TCP connect. A plain allow
    /// lets each through, and what the user was *asked* is the contract.
    ///
    /// (These run on a bare VM that never loaded `lua/init.lua`, so the working
    /// directory is *not* trusted here — which is why even a read asks. The cwd
    /// grant is pinned by `the_working_directory_is_trusted_at_startup`.)
    #[test]
    fn the_permissive_mode_asks_about_writes_connects_and_binds() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        let dir = std::env::temp_dir().join(format!("agent-permissive-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let target = dir.join("out.txt");
        // Seeded so the write is an overwrite. Creating a name nothing holds is
        // deliberately not a question — `creating_a_new_name_is_not_a_question`
        // is that test's whole subject — and this one is about the *question*.
        std::fs::write(&target, "before\n").expect("seed the target");
        let path = target.to_string_lossy().to_string();

        // A write-open is asked, and the question names the file and the flags.
        let (v, asked) =
            run_policy_bash(&lua, &format!("echo hi > {path}"), AskAnswer::Allow);
        assert_eq!(v["ok"], true, "an allowed write runs: {v}");
        let q = asked
            .iter()
            .find(|q| q.contains("want to write"))
            .unwrap_or_else(|| panic!("a write is asked: {asked:?}"));
        assert!(q.contains(&path), "the write question names the file: {q:?}");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "hi\n", "and it wrote");

        // A *read* is asked too, and with the read question: "may I read here"
        // and "may I write here" are two decisions, and the flag reaching the ask
        // is what keeps them apart.
        let (v, asked) = run_policy_bash(&lua, &format!("cat {path}"), AskAnswer::Allow);
        assert_eq!(v["ok"], true, "{v}");
        let q = asked
            .iter()
            .find(|q| q.contains("want to read"))
            .unwrap_or_else(|| panic!("a read is asked: {asked:?}"));
        assert!(q.contains(&path), "with the read question and the path: {q:?}");

        // A refused write leaves the file alone, and says it was denied. Seeded,
        // because a refused *create* is no longer refusable — creating a name
        // nothing holds is deliberately silent
        // (`creating_a_new_name_is_not_a_question`). Overwriting something that
        // is there is still a question, and refusing it must leave the old
        // contents exactly as they were.
        let other_path = dir.join("refused.txt");
        std::fs::write(&other_path, "untouched\n").expect("seed the refused target");
        let other = other_path.to_string_lossy().to_string();
        let (v, asked) = run_policy_bash(
            &lua,
            &format!("echo nope > {other}"),
            AskAnswer::Deny(Some("denied by user".to_string())),
        );
        assert_eq!(v["ok"], false, "a refused write is not ok: {v}");
        assert!(asked_about(&asked, &other), "and it was asked: {asked:?}");
        assert!(
            v["error"].as_str().unwrap_or("").contains("denied by user"),
            "and carries the reason: {v}"
        );
        assert_eq!(
            std::fs::read_to_string(&other_path).unwrap_or_default(),
            "untouched\n",
            "a refused overwrite left the file exactly as it was: {v}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A `connect` is asked with the endpoint it wanted: the port, and the
    /// address with its reverse-resolved name when it has one. Loopback resolves
    /// without a network, so the name is `localhost` and the question reads
    /// "localhost (127.0.0.1)" — both halves, as the mode's wording asks.
    #[test]
    fn the_permissive_mode_asks_about_a_connection_with_its_endpoint() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        // A listener with nothing on it, so `connect` fails *after* the gate:
        // what is under test is the question, not the connection.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();

        let (v, asked) = run_policy_bash(
            &lua,
            &format!("exec 3<>/dev/tcp/127.0.0.1/{port}"),
            AskAnswer::Allow,
        );
        let q = asked
            .iter()
            .find(|q| q.contains("want to access"))
            .unwrap_or_else(|| panic!("a connect is asked: {asked:?} {v}"));
        assert!(
            q.contains("127.0.0.1") && q.contains("localhost"),
            "the question names the host and its address: {q:?}"
        );
        assert_eq!(
            q.matches(&port.to_string()).count(),
            1,
            "and the port exactly once, not folded into the address too: {q:?}"
        );
        assert!(
            q.contains("at port"),
            "in the mode's own wording: {q:?}"
        );
    }

    /// A `bind` is asked with the port being opened. The listener is never
    /// actually reached — `listen()` names no address, so the gate that can ask
    /// about it is `bind`, and the question is about opening a port.
    #[test]
    fn the_permissive_mode_asks_about_opening_a_port() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        // A port nothing holds, so the bind succeeds and the gate is the only
        // thing that stops it.
        let taken = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let _port = taken.local_addr().expect("addr").port();
        drop(taken);

        // Pick a free port by binding and releasing it, then ask bash to open it.
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = probe.local_addr().expect("addr").port();
        drop(probe);

        let (v, asked) = run_policy_bash(
            &lua,
            &format!("exec 3<>/dev/tcp/127.0.0.1/{port}"),
            AskAnswer::Deny(None),
        );
        // A refused connect never reaches the port, so this asserts the connect
        // gate refused; the bind gate is pinned by the same policy table and is
        // covered by the mask assertion below.
        assert_eq!(asked.len(), 1, "{asked:?} {v}");
        assert!(asked[0].contains("want to access"), "{:?}", asked[0]);
    }

    /// The shipped policy's mask, spelled out. A policy that named fewer would
    /// silently let a connect — or an `rm`, or a `chmod` — through, so the set is
    /// pinned exactly; and it is a list rather than a count, so that adding a
    /// gate is a visible edit here and not a silent one.
    const MASK: &str = "bind,chmod,connect,fchmodat,lremovexattr,lsetxattr,openat,removexattr,renameat,renameat2,sendto,setxattr,unlinkat";

    /// The mask is the whole policy: these thirteen syscalls are the ones the
    /// shipped policy decides, and nothing else. A policy that named fewer would silently
    /// `unlinkat` is gated on **write** trust, so `rm` asks — and a path trusted
    /// only for reading is not enough to delete it. The contents are never read
    /// to answer, so the question is about the name and nothing leaks about what
    /// Creating a name nothing holds is **not** a question. Nothing is there to
    /// disturb, and a prompt per created file is how a user learns to stop
    /// reading prompts and start pressing `a`.
    ///
    /// The path is then write-trusted, so the edits that follow a create are one
    /// decision rather than one per write. That is the "trust it for writing"
    /// half, and this asserts both: the create is silent, *and* the write that
    /// follows it is. The answer is set to deny throughout, so a silent case is
    /// The system tree is trusted at startup **for reading only**, which is what
    /// makes it safe: a cold command stops asking about libc, the dynamic linker
    /// and the locale files, and every write under there still asks.
    ///
    /// The second half is the one that matters and the one a careless grant would
    /// lose, so it is asserted rather than assumed. `/usr` and `/lib` are read
    /// silently; writing *into* them is a question, and so is creating a name
    /// there — the "a create needs no ask" rule is about names nothing holds,
    /// The `/dev` entries that carry nothing are granted: read for the lot, and
    /// write for `/dev/null` alone, because `> /dev/null` is the commonest
    /// redirect there is and asking about it every time is noise.
    ///
    /// The second half is the one that keeps "safe" honest. "Safe `/dev`" is not
    /// a self-defining set, and the entries that are *not* granted are named
    /// here so the boundary is a decision rather than an accident: your terminal,
    /// The strings in a tool result field, whether it arrived as a JSON array or
    /// as `{}`.
    ///
    /// An empty Lua table is ambiguous and the encoder emits `{}` for it, so a
    /// list that came back empty is an object with no keys rather than an array
    /// with no elements. Asserting on `as_array()` alone would read that as a
    /// missing field, which is how the first run of this test failed on a tool
    /// that had worked.
    fn entries(v: &serde_json::Value) -> Vec<String> {
        if let Some(a) = v.as_array() {
            return a
                .iter()
                .map(|x| x.as_str().unwrap_or_default().to_string())
                .collect();
        }
        match v.as_object() {
            Some(o) => o.keys().cloned().collect(),
            None => Vec::new(),
        }
    }

    /// `hand_to_user` gives write-trust back, so the files a command created stop
    /// being writable without a question.
    ///
    /// The round trip is the point: a create records write-trust on its own (see
    /// `creating_a_new_name_is_not_a_question`), so without this the agent's own
    /// output is the one thing it can keep rewriting in silence forever, and
    /// nothing else in the system revokes a grant the agent made to itself.
    #[test]
    fn hand_to_user_takes_write_trust_back_so_later_writes_ask_again() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        let dir = std::env::temp_dir().join(format!("agent-hand-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("mine.txt");
        let path_s = path.to_string_lossy().to_string();

        // The create is silent and records write-trust.
        let (v, asked) =
            run_policy_bash(&lua, &format!("echo mine > {path_s}"), AskAnswer::Deny(None));
        assert_eq!(v["ok"], true, "the create ran: {v}");
        assert!(
            !asked.iter().any(|q| q.contains("want to write")),
            "and asked nothing: {asked:?}"
        );
        // ...which is why a second write is also silent.
        let (_, asked) =
            run_policy_bash(&lua, &format!("echo again > {path_s}"), AskAnswer::Deny(None));
        assert!(
            !asked.iter().any(|q| q.contains("want to write")),
            "the create trusted the name: {asked:?}"
        );

        // Hand it over, through the tool so the advertised shape is what gets
        // exercised — and on **this** VM, which is the whole mechanism. The trust
        // lives in the config VM's ask tables, and the event loop runs every tool
        // on that one VM; the `call_tool_asking` helper builds a fresh VM per
        // call, so reaching for it here would have tested a tool looking at an
        // empty table and quietly reporting "not trusted" for everything.
        let handover = |args: &str| -> serde_json::Value {
            let (body, _) = invoke_tool_asking(&lua, "fs.hand_to_user", args, None)
                .expect("invoke")
                .expect("the shipped config registers fs.hand_to_user");
            serde_json::from_str(&body).expect("tool json")
        };
        let r = handover(&serde_json::json!({ "paths": [&path_s] }).to_string());
        assert_eq!(r["ok"], true, "the handover ran: {r}");
        assert_eq!(
            entries(&r["result"]["handed_over"]),
            vec![path_s.clone()],
            "and it names what it gave up: {r}"
        );
        assert!(
            entries(&r["result"]["not_write_trusted"]).is_empty(),
            "with nothing left over: {r}"
        );

        // Now the third write asks, and a refusal stops it. This is the whole
        // point of the tool: the file is the user's to look after now.
        let (v, asked) =
            run_policy_bash(&lua, &format!("echo nope > {path_s}"), AskAnswer::Deny(None));
        assert_eq!(v["ok"], false, "a refused write is not ok: {v}");
        assert!(
            asked.iter().any(|q| q.contains("want to write") && q.contains(&path_s)),
            "the write asks again: {asked:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap_or_default(),
            "again\n",
            "and the refusal left the file alone"
        );

        // Handing over something the agent never held is not an error, and says
        // so — a confused call has to be visible rather than quietly do nothing.
        // The already-handed-over path is in here too, and being reported back as
        // un-held is the honest answer: there is nothing left of it to give.
        let r = handover(
            &serde_json::json!({ "paths": ["/no/such/path", &path_s] }).to_string(),
        );
        assert_eq!(r["ok"], true, "{r}");
        assert!(
            entries(&r["result"]["handed_over"]).is_empty(),
            "nothing was given up a second time: {r}"
        );
        let mut missed = entries(&r["result"]["not_write_trusted"]);
        missed.sort();
        let mut want = vec!["/no/such/path".to_string(), path_s.clone()];
        want.sort();
        assert_eq!(missed, want, "both are named as un-held: {r}");

        // Reading stays silent: only the write half was given up.
        let (v, asked) = run_policy_bash(&lua, &format!("cat {path_s}"), AskAnswer::Deny(None));
        assert_eq!(v["ok"], true, "the read ran: {v}");
        assert!(
            !asked.iter().any(|q| q.contains(&path_s)),
            "and a read of a handed-over file is still silent: {asked:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The advertised shape: a `paths` array, and a single `path` accepted under
    /// the same name every other fs tool takes, because a model reaching for
    /// The pair that needed a blocklist: trust the working directory, then take
    /// one file back out of it.
    ///
    /// A directory grant covers its whole subtree, so there is no entry for
    /// `.env` to drop — `forget` removed nothing, reported success, and left the
    /// file exactly as trusted as before. That is the shape a config reaches for
    /// when it wants the repository to be quiet but not its secrets, so it is
    /// pinned here against the real working directory rather than a fixture.
    #[test]
    fn a_trusted_working_directory_can_have_a_file_taken_back_out_of_it() {
        let lua = new_vm_with_sink(None).expect("vm");
        let cwd = std::env::var("PWD").expect("PWD");
        let secret = format!("{cwd}/.env");
        let other = format!("{cwd}/README.md");

        // The shipped config trusts the cwd at startup.
        for p in [&secret, &other] {
            let trusted: bool = lua
                .load(format!("return agent.ask.is_trusted({p:?})"))
                .eval()
                .unwrap_or_else(|e| panic!("is_trusted({p}): {e}"));
            assert!(trusted, "{p} is trusted by the cwd grant");
        }

        // Take the one back out.
        let forgot: bool = lua
            .load(format!("return agent.ask.forget({secret:?})"))
            .eval()
            .expect("forget");
        assert!(forgot, "and forgetting it reports it stopped being trusted");

        let still: bool = lua
            .load(format!("return agent.ask.is_trusted({secret:?})"))
            .eval()
            .expect("is_trusted");
        assert!(!still, "so the file inside the trusted cwd is not trusted");
        let sibling: bool = lua
            .load(format!("return agent.ask.is_trusted({other:?})"))
            .eval()
            .expect("is_trusted");
        assert!(sibling, "while the rest of the cwd is untouched");

        // It is a preference, so trusting the same path again is how you change
        // your mind: the block is lifted and the grant stands.
        let retrusted: String = lua
            .load(format!("return agent.ask.trust({secret:?})"))
            .eval()
            .expect("trust");
        assert_eq!(retrusted, secret, "re-trusting it works");
        let blocked: bool = lua
            .load(format!("return agent.ask.is_blocked({secret:?})"))
            .eval()
            .expect("is_blocked");
        assert!(!blocked, "and it lifted the block on the way");
        let trusted_again: bool = lua
            .load(format!("return agent.ask.is_trusted({secret:?})"))
            .eval()
            .expect("is_trusted");
        assert!(trusted_again, "so the file is trusted again");
        // ...but only exactly. A block on a *directory* is a statement about a
        // tree, so naming something inside it is still refused.
        lua.load("agent.ask.block('/usr')").exec().expect("block /usr");
        let refused: bool = lua
            .load("return not pcall(agent.ask.trust, '/usr/lib/inside-blocked.so')")
            .eval()
            .expect("pcall");
        assert!(
            refused,
            "a path inside a blocked directory is still refused: only an exact \
             block is a preference"
        );
        lua.load("agent.ask.unblock('/usr')").exec().expect("unblock /usr");

        // Back to blocked, for the ask assertions below: the re-trust lifted it,
        // and a trusted path answers itself rather than asking.
        lua.load(format!("agent.ask.block({secret:?})"))
            .exec()
            .expect("re-block");

        // The exclusion reaches the ask path, which is the part that matters: a
        // read of the file is a question again. Asked of `ask_trust_read` on a
        // coroutine — the helper the policy itself calls — because a real `cat`
        // would mean creating a file inside the repository to read back, and
        // because a file that does not exist never reaches the question at all.
        let asked: bool = lua
            .load(format!(
                r#"
            local co = coroutine.create(function()
              return agent.ask.ask_trust_read({secret:?}, "may I read it?")
            end)
            local ok, value = coroutine.resume(co)
            assert(ok, "the helper ran: " .. tostring(value))
            return coroutine.status(co) == "suspended"
        "#
            ))
            .eval()
            .expect("ask");
        assert!(asked, "reading the excluded file asks again rather than answering itself");

        // And a sibling still answers itself, so the exclusion is narrow.
        let silent: bool = lua
            .load(format!(
                r#"
            local co = coroutine.create(function()
              return agent.ask.ask_trust_read({other:?}, "may I read it?")
            end)
            local ok, value = coroutine.resume(co)
            assert(ok, "the helper ran: " .. tostring(value))
            return coroutine.status(co) == "dead"
        "#
            ))
            .eval()
            .expect("ask");
        assert!(silent, "while a file next to it still answers itself");

        // Unblocking puts the cwd grant back — it was never revoked, only stood
        // in front of.
        let lifted: bool = lua
            .load(format!("return agent.ask.unblock({secret:?})"))
            .eval()
            .expect("unblock");
        assert!(lifted, "unblocking reports it lifted the block");
        let back: bool = lua
            .load(format!("return agent.ask.is_trusted({secret:?})"))
            .eval()
            .expect("is_trusted");
        assert!(back, "and the cwd grant applies to it again");
    }


    /// `path` should not be met with an error it has to reason about.
    #[test]
    fn hand_to_user_takes_both_a_paths_array_and_a_single_path() {
        let dir = std::env::temp_dir().join(format!("agent-hand2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let a = dir.join("a.txt");
        let b = dir.join("b.txt");
        std::fs::write(&a, "a\n").expect("seed a");
        std::fs::write(&b, "b\n").expect("seed b");

        // Neither path was ever granted, so both come back as "not held" — which
        // is what makes this a test of the argument handling and nothing else.
        let lua = shipped_vm();
        let handover = |args: &str| -> serde_json::Value {
            let (body, _) = invoke_tool_asking(&lua, "fs.hand_to_user", args, None)
                .expect("invoke")
                .expect("the shipped config registers fs.hand_to_user");
            serde_json::from_str(&body).expect("tool json")
        };
        let one = handover(&serde_json::json!({ "path": a.to_string_lossy() }).to_string());
        assert_eq!(one["ok"], true, "a single path is accepted: {one}");

        let many = handover(
            &serde_json::json!({
                "paths": [a.to_string_lossy(), b.to_string_lossy()],
            })
            .to_string(),
        );
        assert_eq!(many["ok"], true, "an array is accepted: {many}");
        assert_eq!(
            entries(&many["result"]["not_write_trusted"]).len(),
            2,
            "and both are accounted for: {many}"
        );

        // Nothing at all is refused, with a message that says what to give.
        let none = handover(&serde_json::json!({}).to_string());
        assert_eq!(none["ok"], false, "an empty call is refused: {none}");
        assert!(
            none["error"].as_str().unwrap_or("").contains("paths"),
            "and the error names the argument: {none}"
        );
        let wrong = handover(&serde_json::json!({ "paths": "not an array" }).to_string());
        assert_eq!(wrong["ok"], false, "a non-array is refused: {wrong}");

        let _ = std::fs::remove_dir_all(&dir);
    }


    /// the console, a world-writable tmpfs, and the disks all stay questions.
    #[test]
    fn the_empty_devices_are_granted_and_the_rest_of_dev_is_not() {
        let lua = new_vm_with_sink(None).expect("vm");
        prime_the_sandbox(&lua);

        // Readable without a question: no data, no device, nothing to keep.
        for p in ["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/full"] {
            let trusted: bool = lua
                .load(format!("return agent.ask.is_trusted({p:?})"))
                .eval()
                .unwrap_or_else(|e| panic!("is_trusted({p}): {e}"));
            assert!(trusted, "{p} is readable without a question");
        }
        // ...and read-only, except the one that is meant to be written.
        for p in ["/dev/zero", "/dev/random", "/dev/urandom", "/dev/full"] {
            let writable: bool = lua
                .load(format!("return agent.ask.is_write_trusted({p:?})"))
                .eval()
                .unwrap_or_else(|e| panic!("is_write_trusted({p}): {e}"));
            assert!(!writable, "{p} is granted to be looked at, not written");
        }
        let null_writable: bool = lua
            .load("return agent.ask.is_write_trusted('/dev/null')")
            .eval()
            .expect("is_write_trusted");
        assert!(null_writable, "/dev/null is meant to be written to");

        // The boundary. Each of these is a question, and naming them is the
        // point: a grant for "the safe devices" that swept up /dev would be a
        // grant for the disks.
        for p in ["/dev/tty", "/dev/console", "/dev/shm", "/dev/pts/0", "/dev/ptmx", "/dev/sda"] {
            let trusted: bool = lua
                .load(format!("return agent.ask.is_trusted({p:?})"))
                .eval()
                .unwrap_or_else(|e| panic!("is_trusted({p}): {e}"));
            assert!(!trusted, "{p} is not granted: it is not one of the empty ones");
        }

        // And the effect, on a real run: a redirect into /dev/null is silent,
        // while a write to a device that was not granted still asks.
        let (v, asked) = run_policy_bash(
            &lua,
            "echo hello > /dev/null",
            AskAnswer::Deny(None),
        );
        assert_eq!(v["ok"], true, "the redirect ran: {v}");
        assert_eq!(v["result"]["denied"], 0, "and nothing was refused: {v}");
        assert!(
            !asked.iter().any(|q| q.contains("/dev/null")),
            "writing to /dev/null asks nothing: {asked:?}"
        );

        let (v, asked) = run_policy_bash(
            &lua,
            "echo hello > /dev/full",
            AskAnswer::Deny(None),
        );
        assert!(
            asked.iter().any(|q| q.contains("/dev/full")),
            "a device that was only granted for reading still asks to write: {asked:?} {v}"
        );
    }


    /// and it does not get to skip a write inside a granted tree.
    #[test]
    fn the_system_tree_is_trusted_to_read_and_still_asked_to_write() {
        let lua = new_vm_with_sink(None).expect("vm");
        // The *grants* are asserted before anything is run, on purpose.
        // `prime_the_sandbox` below drives real programs with `AllowAndTrust`,
        // and every path they touch is recorded as trusted — including
        // `/proc/filesystems`, which they read. Asserting the table after that
        // would have this test pass on its own warm-up rather than on the
        // config, and it did: it reported a grant the shipped config never made.
        // A cold run is the only thing that can answer this question.
        let _ = &lua;

        // Trusted to look, at both the tree and a file inside it.
        for p in ["/usr", "/lib", "/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6"] {
            let trusted: bool = lua
                .load(format!("return agent.ask.is_trusted({p:?})"))
                .eval()
                .unwrap_or_else(|e| panic!("is_trusted({p}): {e}"));
            assert!(trusted, "{p} is readable without a question");
        }
        // …and trusted *only* to look. The write table is the whole difference
        // between "you may read the system tree" and "you may install into it",
        // and this is where a read-only grant that had leaked into the general
        // table would show up.
        for p in ["/usr", "/lib", "/etc/ld.so.cache"] {
            let writable: bool = lua
                .load(format!("return agent.ask.is_write_trusted({p:?})"))
                .eval()
                .unwrap_or_else(|e| panic!("is_write_trusted({p}): {e}"));
            assert!(!writable, "{p} is not write-trusted: it was granted to be read");
        }
        // The two procfs reads the C library makes on every exec. Granted as
        // files rather than as /proc, because a blanket grant there would be a
        // grant for every other procfs file as well.
        for p in ["/proc/self/maps", "/proc/filesystems"] {
            let trusted: bool = lua
                .load(format!("return agent.ask.is_trusted({p:?})"))
                .eval()
                .unwrap_or_else(|e| panic!("is_trusted({p}): {e}"));
            assert!(trusted, "{p} is read on every exec, and is granted");
        }
        // ...but /proc itself is not.
        let proc: bool = lua
            .load("return agent.ask.is_trusted('/proc')")
            .eval()
            .expect("is_trusted");
        assert!(!proc, "/proc is not granted as a tree — only those two files are");
        // `/etc/ld.so.preload` decides what gets loaded into every process, so it
        // is the one loader file deliberately left as a question.
        let preload: bool = lua
            .load("return agent.ask.is_trusted('/etc/ld.so.preload')")
            .eval()
            .expect("is_trusted");
        assert!(
            !preload,
            "ld.so.preload is not granted: trusting it would mean trusting whatever \
             it names, and those names are not the loader's to hold"
        );
        // The dynamic linker's cache is in /etc, not /usr, and is granted on its
        // own: it is read on every exec, so without it a cold command still asks
        // once per program it starts.
        let cache: bool = lua
            .load("return agent.ask.is_trusted('/etc/ld.so.cache')")
            .eval()
            .expect("is_trusted");
        assert!(cache, "the loader cache is trusted");
        // And the rest of /etc is not: this grant is one file, not a directory.
        let shadow: bool = lua
            .load("return agent.ask.is_trusted('/etc/shadow')")
            .eval()
            .expect("is_trusted");
        assert!(!shadow, "but nothing else in /etc is — the grant is one file");

        // From here on, real runs. Primed first: on this machine something on
        // `PATH` is a rustup shim, so a cold `cat` also reads
        // `~/.rustup/toolchains/...`, which is correctly still a question and is
        // not what this test is about.
        prime_the_sandbox(&lua);

        // The read is genuinely silent, and it names something that is really
        // there, so the quiet is the grant's doing rather than a missing file.
        //
        // A *directory* rather than `cat /etc/ld.so.cache`: the cache is granted
        // and checked above, but it is binary, and the tool result has to encode
        // as JSON text — so `cat`ing it fails on an invalid UTF-8 sequence. That
        // is a pre-existing rough edge in the result encoding, not something the
        // grant introduced, and it is not what this test is about.
        let (v, asked) = run_policy_bash(&lua, "ls -d /usr/lib", AskAnswer::Deny(None));
        assert_eq!(v["ok"], true, "the read ran: {v} asked={asked:?}");
        assert_eq!(v["result"]["denied"], 0, "and nothing was refused: {v}");
        assert!(
            v["result"]["stdout"].as_str().unwrap_or("").contains("/usr/lib"),
            "and it listed the directory: {v}"
        );
        assert!(
            !asked.iter().any(|q| q.contains("/usr/lib")),
            "reading inside the trusted tree asks nothing: {asked:?}"
        );

        // The write still asks — even with every answer set to deny, so a silent
        // case would be silent because nothing was asked and not because the
        // answer was ignored.
        let (v, asked) = run_policy_bash(
            &lua,
            "echo x > /usr/share/agent-should-not-exist.txt",
            AskAnswer::Deny(None),
        );
        assert_eq!(v["ok"], false, "a refused write into /usr is not ok: {v}");
        assert!(
            asked
                .iter()
                .any(|q| q.contains("want to write") && q.contains("/usr/share")),
            "writing into the trusted tree still asks: {asked:?}"
        );
        assert!(
            !std::path::Path::new("/usr/share/agent-should-not-exist.txt").exists(),
            "and wrote nothing"
        );
    }


    /// silent because nothing was asked and not because nothing was refused.
    #[test]
    fn creating_a_new_name_is_not_a_question() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        let dir = std::env::temp_dir().join(format!("agent-new-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("brand-new.txt");
        let path_s = path.to_string_lossy().to_string();

        // Nothing under /tmp is granted, so without the rule this would ask.
        let (v, asked) = run_policy_bash(&lua, &format!("echo hi > {path_s}"), AskAnswer::Deny(None));
        assert_eq!(v["ok"], true, "the create ran: {v}");
        assert_eq!(v["result"]["denied"], 0, "and nothing was refused: {v}");
        assert!(
            !asked.iter().any(|q| q.contains("want to write")),
            "a create is not a question, even when every answer is deny: {asked:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap_or_default(),
            "hi\n",
            "and the file is there"
        );

        // "Trust it for writing": the second write is silent too.
        let (v, asked) =
            run_policy_bash(&lua, &format!("echo there > {path_s}"), AskAnswer::Deny(None));
        assert_eq!(v["ok"], true, "the rewrite ran: {v}");
        assert!(
            !asked.iter().any(|q| q.contains("want to write")),
            "and it did not ask: the create trusted the name: {asked:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap_or_default(),
            "there\n",
            "the second write landed"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An **overwrite** is still a question, and a refused one leaves the file
    /// exactly as it was.
    ///
    /// This is the half that could go wrong silently: the new rule turns on
    /// whether the name is taken, so a permissive mistake in the existence test
    /// would show up here and nowhere else.
    #[test]
    fn an_overwrite_is_still_a_question() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        let dir = std::env::temp_dir().join(format!("agent-over-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("existing.txt");
        std::fs::write(&path, "original\n").expect("seed");
        let path_s = path.to_string_lossy().to_string();

        let (v, asked) =
            run_policy_bash(&lua, &format!("echo nope > {path_s}"), AskAnswer::Deny(None));
        assert_eq!(v["ok"], false, "a refused overwrite is not ok: {v}");
        assert!(
            asked.iter().any(|q| q.contains("want to write") && q.contains(&path_s)),
            "an overwrite asks, naming the file: {asked:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap_or_default(),
            "original\n",
            "and the refusal left the old contents alone"
        );

        // Deliberately *not* asserted: a name below something that is not a
        // directory reads as "not taken" (ENOTDIR), so the create is silent. That
        // is safe rather than lax — the open cannot succeed either way, and the
        // sandbox is a bare fork, so the command has the user's own permissions.
        // An earlier version of this test asserted the opposite and was wrong.

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The existence test has to see a file the process **cannot read**, because
    /// that is the case a naive one misses.
    ///
    /// `io.open` follows the name and fails on anything not readable, so a locked
    /// file — `/etc/shadow` is the real one — reads as absent, and absent is the
    /// answer that skips the ask. `os.rename(p, p)` is a documented no-op that
    /// succeeds exactly when the name is taken, whatever its mode. This test is
    /// what tells the two implementations apart.
    #[test]
    fn a_file_the_process_cannot_read_still_counts_as_taken() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        let dir = std::env::temp_dir().join(format!("agent-unread-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("locked.txt");
        std::fs::write(&path, "secret\n").expect("seed");

        // mode 000: unreadable *and* unwritable by us, and plainly present.
        let mut perms = std::fs::metadata(&path).expect("stat").permissions();
        {
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(0o000);
        }
        std::fs::set_permissions(&path, perms).expect("chmod 000");
        assert!(
            std::fs::File::open(&path).is_err(),
            "precondition: the file really is unreadable, or this test is vacuous"
        );

        let path_s = path.to_string_lossy().to_string();
        // The gate runs before the kernel, so it asks even though the write would
        // then fail with EACCES: the ask is the contract, not the write's success.
        let (_, asked) = run_policy_bash(&lua, &format!("echo x > {path_s}"), AskAnswer::Allow);
        assert!(
            asked.iter().any(|q| q.contains("want to write") && q.contains(&path_s)),
            "an unreadable existing file is an overwrite, and asks: {asked:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }


    /// `chmod` asks on **write** trust, and a refused one leaves the mode alone.
    ///
    /// This was a genuine hole: the mask named files and endpoints, and a
    /// sandboxed command could still make one of your files executable, or take
    /// the bits off it. `chmod +x` is how a payload becomes runnable, and it was
    /// the one permission change the gate did not ask about.
    #[test]
    fn changing_a_files_mode_asks_and_a_refusal_leaves_it_alone() {
        use std::os::unix::fs::PermissionsExt;
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        let dir = std::env::temp_dir().join(format!("agent-chmod-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("payload");
        std::fs::write(&path, "#!/bin/sh\necho hi\n").expect("seed");
        let path_s = path.to_string_lossy().to_string();
        let mode_of = |p: &std::path::Path| {
            std::fs::metadata(p).expect("stat").permissions().mode() & 0o777
        };
        let before = mode_of(&path);
        // Not the exact bits — the temp dir's umask decides those — but the one
        // thing that matters: no execute bit yet.
        assert_eq!(before & 0o111, 0, "precondition: not executable yet");

        // Refused: asked, and the mode is untouched.
        let (v, asked) =
            run_policy_bash(&lua, &format!("chmod 0700 {path_s}"), AskAnswer::Deny(None));
        assert_eq!(v["ok"], false, "a refused chmod is not ok: {v}");
        assert!(
            asked
                .iter()
                .any(|q| q.contains("change the mode") && q.contains(&path_s)),
            "it asks, naming the file and the change: {asked:?}"
        );
        assert_eq!(mode_of(&path), before, "and the mode did not change");

        // Allowed: it goes through, and only then.
        let (v, asked) =
            run_policy_bash(&lua, &format!("chmod 0700 {path_s}"), AskAnswer::Allow);
        assert_eq!(v["ok"], true, "an allowed chmod runs: {v}");
        assert!(
            asked.iter().any(|q| q.contains("change the mode")),
            "and it still asked: {asked:?}"
        );
        assert_eq!(mode_of(&path), 0o700, "so the mode changed");

        // A *different* mode this time, because `chmod` to the mode a file
        // already has makes no syscall at all — so there would be nothing to
        // gate, and the run would pass for the wrong reason.
        let (v, asked) =
            run_policy_bash(&lua, &format!("chmod 0644 {path_s}"), AskAnswer::Deny(None));
        assert_eq!(v["ok"], false, "and refused again: {v}");
        assert!(
            asked.iter().any(|q| q.contains("change the mode")),
            "so it asks each time the mode really changes: {asked:?}"
        );
        assert_eq!(mode_of(&path), 0o700, "and the mode is still untouched");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A shell run whose handler answers `deny` to questions mentioning
    /// `marker` and `allow` to everything else.
    ///
    /// Needed because a cold `python3` reads a handful of unrelated files on the
    /// way to running anything, and a handler that denies everything kills the run
    /// before it reaches the call under test. Denying one question by its text is
    /// the only way to say "this is the gate" without also enumerating
    /// everything the interpreter happens to want.
    fn run_policy_bash_except(
        lua: &mlua::Lua,
        cmdline: &str,
        marker: &str,
    ) -> (serde_json::Value, Vec<String>) {
        let asked: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let seen = asked.clone();
        let mark = marker.to_string();
        let handler: AskHandler = Rc::new(move |text: &str, _always: bool| {
            seen.borrow_mut().push(text.to_string());
            if text.contains(&mark) {
                AskAnswer::Deny(Some("refused by the test".into()))
            } else {
                AskAnswer::Allow
            }
        });
        let args = serde_json::json!({ "cmdline": cmdline }).to_string();
        let Some((body, _)) =
            invoke_tool_asking(lua, "bash.bash", &args, Some(handler)).expect("invoke")
        else {
            panic!("the permissive mode registers bash")
        };
        let v: serde_json::Value = serde_json::from_str(&body).expect("tool json");
        (v, asked.borrow().clone())
    }

    /// Setting an extended attribute asks, and the question names the attribute —/ gated**, so a command holding an open descriptor can change that file's
    /// mode without a question — and `cp --preserve=mode` is exactly that.
    ///
    /// It is not gated because it names no path, and a question needs one: there
    /// is nothing to put in `ask_trust_write`, and a nameless question would be
    /// unanswerable in the only way that matters. The descriptor is not free,
    /// though — opening it cost read or write trust, so what this actually means
    /// is that *read*-trust on a path implies being able to make it executable.
    /// Closing that needs the engine to resolve an fd to a path through
    /// `/proc/<pid>/fd`, which is real work and a decision rather than a policy
    /// key. Pinned here so the gap is visible.
    #[test]
    fn fchmod_is_not_gated_because_it_names_no_path() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        let dir = std::env::temp_dir().join(format!("agent-fchmod-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let src = dir.join("src");
        let dst = dir.join("dst");
        std::fs::write(&src, "x\n").expect("seed");

        let (v, asked) = run_policy_bash(
            &lua,
            &format!(
                "cp --preserve=mode {0} {1}",
                src.to_string_lossy(),
                dst.to_string_lossy()
            ),
            // Allow, not deny: the question here is whether a *mode* question
            // appears, and denying everything would just stop the copy early.
            AskAnswer::Allow,
        );
        assert_eq!(v["ok"], true, "the copy ran: {v}");
        assert!(
            !asked.iter().any(|q| q.contains("change the mode")),
            "and asked nothing about the mode: the descriptor path is ungated, \
             which is the gap this test names"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Setting an extended attribute asks, and the question names the attribute —
    /// because `security.capability` is `setcap`, and that is a different thing to
    /// be told about than an app writing its own `user.*` metadata.
    #[test]
    fn setting_an_extended_attribute_asks_and_names_which_one() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        // `python3` here resolves through the rustup toolchain, so its own
        // libraries ask unless they are warmed first — and a Deny to those would
        // kill the run before it ever reached the attribute, which is not what
        // this test is about.
        let (warm, _) = run_policy_bash(&lua, "python3 -c pass", AskAnswer::AllowAndTrust);
        assert_eq!(warm["ok"], true, "warmed python3: {warm}");
        let dir = std::env::temp_dir().join(format!("agent-xattr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("tagged");
        std::fs::write(&path, "x\n").expect("seed");
        let path_s = path.to_string_lossy().to_string();

        // Driven through python's `os.setxattr`, which is the same
        // `setxattr(2)` call `setcap` makes for `security.capability`. In a
        // script file rather than `python3 -c`, because a path inside a
        // double-quoted `-c` string needs its own layer of quoting and gets it
        // wrong in a way that reads as a policy failure.
        let script = dir.join("setx.py");
        std::fs::write(
            &script,
            "import os, sys\nos.setxattr(sys.argv[1], 'user.agent-test', b'v')\n",
        )
        .expect("write the helper");
        let script_s = script.to_string_lossy().to_string();
        let read_script = dir.join("getx.py");
        std::fs::write(
            &read_script,
            "import os, sys\nsys.stdout.write(os.getxattr(sys.argv[1], 'user.agent-test').decode())\n",
        )
        .expect("write the reader");
        // Only the attribute question is denied, so the interpreter's own
        // startup reads do not get in the way.
        let (v, asked) = run_policy_bash_except(
            &lua,
            &format!("python3 {script_s} {path_s}"),
            "user.agent-test",
        );
        assert_eq!(v["ok"], false, "a refused setxattr is not ok: {v}");
        assert!(
            asked
                .iter()
                .any(|q| q.contains("user.agent-test") && q.contains(&path_s)),
            "the question names the attribute and the file: {asked:?}"
        );

        // Allowed, the attribute lands — so the gate was the only thing in the
        // way, and it is a gate rather than a block.
        let (v, asked) = run_policy_bash_except(
            &lua,
            &format!("python3 {script_s} {path_s}"),
            "\u{0}never-matches",
        );
        assert_eq!(v["ok"], true, "an allowed setxattr runs: {v}");
        assert!(
            asked.iter().any(|q| q.contains("user.agent-test")),
            "and it asked: {asked:?}"
        );
        // Read it back, rather than trusting that a silent run did the work. The
        // read is ungated (only the *setting* of an attribute asks), so this is
        // the same interpreter again and asks nothing.
        let (read, _) = run_policy_bash_except(
            &lua,
            &format!("python3 {} {path_s}", read_script.to_string_lossy()),
            "\u{0}never-matches",
        );
        assert_eq!(read["ok"], true, "the read-back ran: {read}");
        assert_eq!(
            read["result"]["stdout"], "v",
            "and the attribute really is set: {read}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }


    /// was in the file.
    #[test]
    fn deleting_a_file_asks_on_write_trust_and_rm_goes_through_it() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        let dir = std::env::temp_dir().join(format!("agent-rm-{0}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("doomed.txt");
        std::fs::write(&path, "about to go\n").expect("seed the file to delete");
        let path = path.to_string_lossy().to_string();

        // Read-trust is not enough: the gate is the write table, and this is the
        // whole reason unlinkat is not on `ask_trust_read`.
        let asked: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let seen = asked.clone();
        let handler: AskHandler = Rc::new(move |text: &str, _always: bool| {
            seen.borrow_mut().push(text.to_string());
            AskAnswer::Deny(None)
        });
        let () = lua
            .load(format!("return agent.ask.trust({:?})", path))
            .eval()
            .expect("trust the path for *reading* only");

        let args = serde_json::json!({ "cmdline": format!("rm -f -- {path}") }).to_string();
        let (body, _) = invoke_tool_asking(&lua, "bash.bash", &args, Some(handler.clone()))
            .expect("invoke")
            .expect("the shipped config registers bash.bash");
        let v: serde_json::Value = serde_json::from_str(&body).expect("tool json");
        let questions = asked.borrow().clone();
        // A refused syscall is `ok = false` with `denied`, not a crash: the gate
        // did its job and the run reports it.
        assert_eq!(v["ok"], false, "the delete was refused: {v}");
        assert!(
            v["result"]["denied"].as_u64().unwrap_or(0) >= 1,
            "and counted as denied: {v}"
        );
        assert!(
            questions.iter().any(|q| q.contains("want to delete") && q.contains(&path)),
            "rm asked to delete the file: {questions:?}"
        );
        assert!(
            std::path::Path::new(&path).exists(),
            "so read-trust did not delete it: the gate refused"
        );

        // Write-trust does delete it, and says nothing more about it.
        let asked2: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let seen2 = asked2.clone();
        let handler2: AskHandler = Rc::new(move |text: &str, _always: bool| {
            seen2.borrow_mut().push(text.to_string());
            AskAnswer::Allow
        });
        let args = serde_json::json!({ "cmdline": format!("rm -f -- {path}") }).to_string();
        let (body, _) = invoke_tool_asking(&lua, "bash.bash", &args, Some(handler2))
            .expect("invoke")
            .expect("registered");
        let v: serde_json::Value = serde_json::from_str(&body).expect("tool json");
        assert_eq!(v["ok"], true, "the run completed: {v}");
        assert!(
            !std::path::Path::new(&path).exists(),
            "write-trust let the delete through: {v}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `renameat` asks twice when the target already exists — once for the source
    /// and once for the name it would destroy — and once when it does not, since
    /// creating a name is already covered by the source's permission.
    ///
    /// The two answers differ, which is the point: a runner that pressed one key
    /// for every question could not tell "allowed the move, refused the
    /// overwrite" from "allowed both".
    #[test]
    fn a_move_asks_twice_only_when_the_target_exists() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        let dir = std::env::temp_dir().join(format!("agent-mv-{0}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let src = dir.join("from.txt");
        let dst = dir.join("to.txt");
        let src_s = src.to_string_lossy().to_string();
        let dst_s = dst.to_string_lossy().to_string();
        std::fs::write(&src, "source\n").expect("seed source");
        // Warm `mv`'s own shared libraries, so the questions left are the move's
        // and not the loader's. Granting write-trust on the scratch directory
        // would be the obvious way to quiet those — and it would silence the
        // questions under test too, which is how the first run of this asserted
        // "one question" and got six library reads and no move at all.
        let (warm, _) = run_policy_bash(&lua, "/bin/mv --version", AskAnswer::AllowAndTrust);
        assert_eq!(warm["ok"], true, "warmed mv: {warm}");

        // A fresh name: one question, about the source.
        std::fs::write(&src, "source\n").expect("seed source");
        let (v, asked) =
            run_policy_bash(&lua, &format!("mv -f -- {src_s} {dst_s}"), AskAnswer::Allow);
        assert_eq!(v["ok"], true, "the move ran: {v}");
        assert!(
            !std::path::Path::new(&src_s).exists() && std::path::Path::new(&dst_s).exists(),
            "and it moved: {v}"
        );
        assert_eq!(
            asked.len(),
            1,
            "creating a name is one question, the source's: {asked:?}"
        );
        assert!(
            asked[0].contains("want to move") && asked[0].contains(&src_s),
            "about the move: {asked:?}"
        );

        // An occupied name: two, and refusing the second must stop the move while
        // leaving both files as they were.
        std::fs::write(&src, "new source\n").expect("seed source again");
        std::fs::write(&dst, "existing target\n").expect("seed target");
        let asked3: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let seen3 = asked3.clone();
        let handler3: AskHandler = Rc::new(move |text: &str, _always: bool| {
            seen3.borrow_mut().push(text.to_string());
            // Allow the move, refuse the overwrite.
            if text.contains("want to overwrite") {
                AskAnswer::Deny(Some("no".into()))
            } else {
                AskAnswer::Allow
            }
        });
        let args =
            serde_json::json!({ "cmdline": format!("mv -f -- {src_s} {dst_s}") }).to_string();
        let (body, _) = invoke_tool_asking(&lua, "bash.bash", &args, Some(handler3))
            .expect("invoke")
            .expect("registered");
        let v: serde_json::Value = serde_json::from_str(&body).expect("tool json");
        let questions = asked3.borrow().clone();
        assert_eq!(questions.len(), 2, "an occupied name asks twice: {questions:?}");
        assert!(
            questions[0].contains("want to move") && questions[0].contains(&src_s),
            "the source first: {questions:?}"
        );
        assert!(
            questions[1].contains("want to overwrite") && questions[1].contains(&dst_s),
            "then the name it would destroy: {questions:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&src).unwrap_or_default(),
            "new source\n",
            "the refused overwrite left the source alone: {v}"
        );
        assert_eq!(
            std::fs::read_to_string(&dst).unwrap_or_default(),
            "existing target\n",
            "and left the target alone: {v}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every pathname a syscall names, checked against the kernel's own
    /// signatures — the tables that decide which `args` slots get dereferenced
    /// as C strings, and which of them resolve against a dirfd.
    ///
    /// There was no test here, which is how `renameat` kept `&[1, 2]` for years:
    /// slot 2 is *newdirfd*, so the second path was read out of a small integer
    /// instead of a pointer and came back nil. Nothing had ever asked a question
    /// about a rename's target, so nothing noticed. The signatures are spelled
    /// out here rather than derived, because a typo in a table is invisible until
    /// something reads the slot it mistyped.
    #[test]
    fn the_pathname_and_dirfd_tables_match_the_kernel_signatures() {
        // (syscall, its 0-based string slots) straight from the man pages.
        let signatures: &[(&str, &[usize])] = &[
            ("open", &[0]),
            ("openat", &[1]),
            ("openat2", &[1]),
            ("unlinkat", &[1]),
            ("mkdirat", &[1]),
            ("renameat", &[1, 3]),
            ("renameat2", &[1, 3]),
            ("linkat", &[1, 3]),
            ("symlinkat", &[0, 2]),
            ("execveat", &[1]),
            ("newfstatat", &[1]),
            ("readlinkat", &[1]),
            ("fchmodat", &[1]),
            ("fchownat", &[1]),
            ("utimensat", &[1]),
            ("name_to_handle_at", &[1]),
            ("chmod", &[0]),
            ("fchmodat", &[1]),
            ("setxattr", &[0, 1]),
            ("lsetxattr", &[0, 1]),
            ("removexattr", &[0, 1]),
            ("lremovexattr", &[0, 1]),
        ];
        for (name, want) in signatures {
            assert_eq!(
                cstring_positions(name),
                Some(*want),
                "{name}: which args hold a C string"
            );
        }

        // And the dirfd each of those paths resolves against. A two-path call
        // has two dirfds, and resolving the target against the source's
        // directory is a wrong answer rather than a missing one.
        let cases: &[(&str, usize, Option<usize>)] = &[
            ("openat", 1, Some(0)),
            ("chmod", 0, None),
            ("fchmodat", 1, Some(0)),
            ("unlinkat", 1, Some(0)),
            ("renameat", 1, Some(0)),
            ("renameat", 3, Some(2)),
            ("renameat2", 1, Some(0)),
            ("renameat2", 3, Some(2)),
            ("linkat", 1, Some(0)),
            ("linkat", 3, Some(2)),
            // symlinkat's target is cwd-relative; only its linkpath is behind
            // the fd.
            ("symlinkat", 0, None),
            ("symlinkat", 2, Some(1)),
            ("open", 0, None),
            ("unlink", 0, None),
        ];
        for (name, path, want) in cases {
            assert_eq!(
                dirfd_slot_for(name, *path),
                *want,
                "{name} path slot {path}: which dirfd it resolves against"
            );
        }
    }

    /// The dirfd decision is per *path*, so a rename's target resolves against
    /// the cwd only when the caller said `AT_FDCWD` in the slot that governs
    /// it — the target's own slot, not the source's.
    #[test]
    fn a_rename_target_resolves_against_its_own_dirfd() {
        let cwd = libc::AT_FDCWD as u64;
        let other_fd = 7u64;
        // renameat(olddirfd, oldpath, newdirfd, newpath): the target is slot 3
        // and its dirfd is slot 2.
        // olddirfd, oldpath, newdirfd, newpath — slots 0 and 2 govern slots 1
        // and 3 respectively.
        let both_cwd = [cwd, 0, cwd, 0, 0, 0];
        let new_only = [cwd, 0, other_fd, 0, 0, 0];
        let both_fds = [other_fd, 0, other_fd, 0, 0, 0];

        // Both slots say the cwd: both paths resolve.
        assert!(cwd_resolution_ok("renameat", 1, both_cwd), "source, both AT_FDCWD");
        assert!(cwd_resolution_ok("renameat", 3, both_cwd), "target, both AT_FDCWD");

        // Only the target names a real dirfd: the source still resolves and the
        // target must not. The old table had one slot for the whole syscall —
        // slot 0 — so it read "AT_FDCWD" here and resolved the target against
        // the cwd, which is a wrong answer rather than a missing one.
        assert!(cwd_resolution_ok("renameat", 1, new_only), "source, its own slot");
        assert!(
            !cwd_resolution_ok("renameat", 3, new_only),
            "target, behind a caller-held dirfd"
        );

        // Neither does: neither resolves.
        assert!(!cwd_resolution_ok("renameat", 1, both_fds), "source, behind an fd");
        assert!(!cwd_resolution_ok("renameat", 3, both_fds), "target, behind an fd");
    }

    /// let a connect — or a `rm` — through, so the set is pinned exactly.
    #[test]
    fn the_default_policy_traps_exactly_thirteen_syscalls() {
        assert_default_shell(&shipped_vm());
    }

    /// A remembered endpoint goes quiet, and only for the endpoint that was
    /// remembered: a plain yes asks again, an "always" does not, and a different
    /// port still does. This is the trustworthy-server table doing its job.
    #[test]
    fn the_permissive_mode_remembers_a_server_on_always_only() {
        let lua = shipped_vm();
        prime_the_sandbox(&lua);
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = probe.local_addr().expect("addr").port();
        drop(probe);
        let cmd = format!("exec 3<>/dev/tcp/127.0.0.1/{port}");

        // A plain yes is for that one call: the endpoint is asked again.
        let (v, asked) = run_policy_bash(&lua, &cmd, AskAnswer::Allow);
        assert!(asked_about(&asked, &port.to_string()), "asked: {asked:?} {v}");
        let (v, asked) = run_policy_bash(&lua, &cmd, AskAnswer::Allow);
        assert!(
            asked_about(&asked, &port.to_string()),
            "a plain yes is not remembered: {asked:?} {v}"
        );

        // "always" records host:port, and the next call does not ask about it at
        // all — even though the answer it would have got is a denial.
        let (v, asked) = run_policy_bash(&lua, &cmd, AskAnswer::AllowAndTrust);
        assert!(asked_about(&asked, &port.to_string()), "asked once: {asked:?} {v}");
        let (v, asked) = run_policy_bash(&lua, &cmd, AskAnswer::Deny(None));
        assert!(
            !asked_about(&asked, &port.to_string()),
            "the remembered endpoint is silent: {asked:?} {v}"
        );

        // A different port on the same host is a different question.
        let other = {
            let p = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            let port = p.local_addr().expect("addr").port();
            drop(p);
            port
        };
        let (v, asked) = run_policy_bash(
            &lua,
            &format!("exec 3<>/dev/tcp/127.0.0.1/{other}"),
            AskAnswer::Allow,
        );
        assert!(
            asked_about(&asked, &other.to_string()),
            "another port still asks: {asked:?} {v}"
        );

        // And forgetting it puts the question back. The key is the *name* the
        // question showed — `localhost`, since 127.0.0.1 reverse-resolves
        // without a network — which is the whole point of keying on what the user
        // read.
        let trusted: i64 = lua
            .load("return #agent.ask.trusted_servers()")
            .eval()
            .expect("listed");
        assert_eq!(trusted, 1, "exactly one server was remembered: {trusted}");
        let forgotten: bool = lua
            .load(format!("return agent.ask.forget_server('localhost', {port})"))
            .eval()
            .expect("forget");
        assert!(forgotten, "the endpoint was trusted");
        let (v, asked) = run_policy_bash(&lua, &cmd, AskAnswer::Allow);
        assert!(
            asked_about(&asked, &port.to_string()),
            "a forgotten endpoint asks again: {asked:?} {v}"
        );
    }

    /// The shell the tests below drive *is* the shipped one: `lua/policy.lua` is
    /// the default sandbox policy, so `require("bash_tool")` already runs under
    /// the four gates and there is nothing to install. Asserted here so a change
    /// to the default fails loudly at the point the tests start rather than as a
    /// baffling "asked nothing".
    fn assert_default_shell(lua: &mlua::Lua) {
        // The real table, not the source: this used to grep
        // `policy.<name> = function` out of `lua/policy.lua`, which cannot see a
        // gate assigned from a named local — and `renameat` is exactly that,
        // because it and `renameat2` are one callback. The grep would have
        // reported five gates while the sandbox trapped seven.
        let gates: String = lua
            .load(
                r#"
        local policy = require("policy")
        local names = {}
        for name in pairs(policy) do names[#names + 1] = name end
        table.sort(names)
        return table.concat(names, ",")
    "#,
            )
            .eval()
            .expect("mask");
        assert_eq!(gates, MASK, "the default policy's mask is exactly this set");
    }

    /// `lua/init.lua` trusts the working directory at startup, so the mode's
    /// every-read gate is silent inside the project and asks about everything
    /// else. That is a *full config load* (the entry script plus any user
    /// config), which is why this is not just another `shipped_vm()` assertion.
    #[test]
    fn the_working_directory_is_trusted_at_startup() {
        let lua = new_vm_with_sink(None).expect("vm");
        let cwd = std::env::var("PWD").expect("PWD");

        // The grant is a *directory* entry, so it covers the whole subtree — a
        // file that does not exist yet is inside it too.
        let trusted: bool = lua
            .load(format!("return agent.ask.is_trusted({cwd:?})"))
            .eval()
            .expect("is_trusted");
        assert!(trusted, "the working directory is trusted: {cwd}");
        let inside: bool = lua
            .load(format!("return agent.ask.is_trusted({:?})", format!("{cwd}/lua/init.lua")))
            .eval()
            .expect("a file inside it");
        assert!(inside, "and so is a file in it");
        let outside: bool = lua
            .load("return agent.ask.is_trusted('/etc')")
            .eval()
            .expect("is_trusted");
        assert!(!outside, "but nothing outside it is — that is the point");

        // And the effect the grant exists for: inside the cwd nothing asks, and
        // the same read outside it does.
        // Read a file that is really there, so the grant is what made it quiet
        // rather than the file being absent.
        let (v, asked) =
            run_policy_bash(&lua, &format!("cat {cwd}/lua/init.lua"), AskAnswer::Allow);
        assert_eq!(v["ok"], true, "the read ran: {v}");
        assert!(
            !asked_about(&asked, "init.lua"),
            "a read inside the trusted cwd asks nothing: {asked:?}"
        );
        let outside_path = std::env::temp_dir().join("agent-cwd-trust-probe.txt");
        std::fs::write(&outside_path, "x\n").expect("seed outside the cwd");
        let (v, asked) = run_policy_bash(
            &lua,
            &format!("cat {}", outside_path.to_string_lossy()),
            AskAnswer::Allow,
        );
        assert_eq!(v["ok"], true, "the outside read ran: {v}");
        assert!(
            asked_about(&asked, &outside_path.to_string_lossy()),
            "and the same read outside the cwd is asked: {asked:?}"
        );
        let _ = std::fs::remove_file(&outside_path);
    }

    /// Did any of the questions name `needle`? A command's own reads are not the
    /// only ones: `bash` also opens locale and NSS data, and it does some of
    /// that lazily — an error message is what triggers the locale load — so a
    /// count is fragile where "was this asked" is not.
    fn asked_about(asked: &[String], needle: &str) -> bool {
        asked.iter().any(|q| q.contains(needle))
    }

    /// `bash`'s own startup reads — its binary, libc, the NSS files — are asked
    /// like any other read now that every open is gated. A test that cares about
    /// one particular file would otherwise drown in a dozen library questions, and
    /// so would a user's first command, which is why the working directory trust
    /// in `lua/init.lua` is not the whole answer.
    ///
    /// This is what a user does after the first run: answer "always" once for
    /// the libraries, and stop being asked about them. Leaving those grants in
    /// place is the point — the next command's question is then about the work.
    fn prime_the_sandbox(lua: &mlua::Lua) {
        assert_default_shell(lua);
        // Real binaries, not the `true` builtin: what is expensive to answer is
        // each *program's* own shared libraries, and they differ per program.
        for warm in ["/bin/true", "/bin/cat /dev/null", "/bin/ls /dev/null"] {
            let (v, _) = run_policy_bash(lua, warm, AskAnswer::AllowAndTrust);
            assert_eq!(v["ok"], true, "the warm-up {warm:?} ran: {v}");
        }
    }

    /// One command through the permissive mode's shell, on `lua`, with the
    /// questions it asked. `answers` is what the user presses every time.
    ///
    /// Driven the way the probe drives a tool (to completion on this thread), not
    /// the way the TUI does: a sandbox run needs either a reactor giving it
    /// slices or a blocking step, and this is the second.
    fn run_policy_bash(
        lua: &mlua::Lua,
        cmdline: &str,
        answers: AskAnswer,
    ) -> (serde_json::Value, Vec<String>) {
        let asked: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let seen = asked.clone();
        let handler: AskHandler = Rc::new(move |text: &str, _always: bool| {
            seen.borrow_mut().push(text.to_string());
            answers.clone()
        });
        let args = serde_json::json!({ "cmdline": cmdline }).to_string();
        let Some((body, _)) =
            invoke_tool_asking(lua, "bash.bash", &args, Some(handler)).expect("invoke")
        else {
            panic!("the permissive mode registers bash")
        };
        let v: serde_json::Value = serde_json::from_str(&body).expect("tool json");
        let questions = asked.borrow().clone();
        (v, questions)
    }

    /// A tool call runs on the agent's own VM, so what it decides *persists*:
    /// a path trusted with `[a]lways` is not asked about again on the next call.
    /// That is the whole point of running tools on the config VM rather than a
    /// throwaway one — the trust tables used to die with the tool's own VM, so
    /// every operation asked, every time.
    #[test]
    fn a_tool_calls_trust_outlives_the_call_that_granted_it() {
        let lua = shipped_vm();
        let dir = std::env::temp_dir().join(format!("agent-toolrun-trust-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let args = |name: &str| {
            serde_json::json!({
                "path": dir.join(name).to_string_lossy(),
                "content": "payload\n",
            })
            .to_string()
        };

        // A plain yes is for that one operation: the next call asks again.
        let (v, asked) = drive_on_vm(&lua, "fs.write_file", &args("a.txt"), |_, _| AskAnswer::Allow);
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(asked.len(), 1, "asked: {asked:?}");
        let (v, asked) = drive_on_vm(&lua, "fs.write_file", &args("a.txt"), |_, _| AskAnswer::Allow);
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(asked.len(), 1, "a plain yes is not remembered: {asked:?}");

        // "always" *is* remembered, because the tables live on this VM now.
        let (v, asked) = drive_on_vm(&lua, "fs.write_file", &args("a.txt"), |_, _| {
            AskAnswer::AllowAndTrust
        });
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(asked.len(), 1, "asked once: {asked:?}");
        let (v, asked) =
            drive_on_vm(&lua, "fs.write_file", &args("a.txt"), |_, _| AskAnswer::Deny(None));
        assert_eq!(v["ok"], true, "the remembered path needs no answer: {v}");
        assert!(asked.is_empty(), "and asks nothing at all: {asked:?}");

        // A different path is a different question: trust is a path, not a
        // blanket permission.
        let (v, asked) = drive_on_vm(&lua, "fs.write_file", &args("b.txt"), |_, _| AskAnswer::Allow);
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(asked.len(), 1, "another path still asks: {asked:?}");

        // And forgetting the *write* trust puts that question back — while the
        // path stays trusted for reading, which is the narrow revocation
        // `forget_write` exists for. (It is also the check that catches a write
        // being allowed on read-trust alone: the general entry is still here.)
        let forgotten = dir.join("a.txt").to_string_lossy().to_string();
        let hit: bool = lua
            .load(format!("return agent.ask.forget_write({forgotten:?})"))
            .eval()
            .expect("forget_write");
        assert!(hit, "the path was write-trusted: {forgotten}");
        let read_still: bool = lua
            .load(format!("return agent.ask.is_trusted({forgotten:?})"))
            .eval()
            .expect("is_trusted");
        assert!(read_still, "and read-trust is untouched by a write revocation");
        let (v, asked) = drive_on_vm(&lua, "fs.write_file", &args("a.txt"), |_, _| AskAnswer::Allow);
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(asked.len(), 1, "a forgotten path asks again: {asked:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The other half of the loop's contract: a question reaches the loop as a
    /// step, with the wording the user sees and Lua's own `always` flag — and
    /// the answer is delivered back to the yield site as a plain value.
    #[test]
    fn a_tool_question_is_a_step_the_driver_answers() {
        let lua = shipped_vm();
        let dir = std::env::temp_dir().join(format!("agent-toolrun-ask-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let target = dir.join("notes.txt");
        let args = serde_json::json!({ "path": target.to_string_lossy() }).to_string();

        // A read that is refused: the tool reports the denial, and the loop's
        // answer is what decided it.
        let (mut run, step) = ToolRun::start(&lua, "fs.read", &args)
            .expect("start")
            .expect("registered read");
        let (text, always) = match step {
            ToolStep::Ask { text, always } => (text, always),
            other => panic!("expected a question, got {other:?}"),
        };
        assert_eq!(
            text,
            format!("Allow read {}", target.to_string_lossy()),
            "the question names the path"
        );
        assert!(always, "a file operation can be remembered, so `always` is offered");
        let step = run
            .answer(verdict_to_lua(
                &lua,
                &AskAnswer::Deny(Some("user said no".to_string())),
            ))
            .expect("answer");
        let ToolStep::Returned(body) = step else {
            panic!("a denial finishes the call, got {step:?}")
        };
        let v: serde_json::Value = serde_json::from_str(&body).expect("tool json");
        assert_eq!(v["ok"], false, "{v}");
        assert_eq!(v["denied"], true, "{v}");
        assert!(
            v["error"].as_str().unwrap_or("").contains("user said no"),
            "and it carries the reason the user gave: {v}"
        );
        assert!(!target.exists(), "a refused read creates nothing");

        // A question with nothing to remember does not offer "always": a bare
        // string ask has no path, so `[a]lways` would have nothing to record.
        lua.load(
            r#"
            agent.mcps.askonce = { name = "askonce", tools = { askonce = {
              description = "ask once",
              callback = function() return agent.ask("a question with no path") end,
            } } }
        "#,
        )
        .exec()
        .expect("register a bare-ask tool");
        let (mut run, step) = ToolRun::start(&lua, "askonce.askonce", "{}").expect("start").unwrap();
        match step {
            ToolStep::Ask { text, always } => {
                assert_eq!(text, "a question with no path");
                assert!(!always, "nothing to remember, so no `always`");
            }
            other => panic!("expected a question, got {other:?}"),
        }
        let step = run
            .answer(verdict_to_lua(&lua, &AskAnswer::Allow))
            .expect("answer");
        assert!(matches!(step, ToolStep::Returned(_)), "{step:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Run the shipped pure-Lua patch engine (`require("fs").patch.apply`) over
    /// two globals and return its JSON result: `{ ok, content, added, removed,
    /// before, after }` or `{ ok = false, error }`. Requiring the module (rather
    /// than reading it off `agent`) keeps this usable on a bare VM.
    fn patch_apply(lua: &mlua::Lua, old: &str, diff: &str) -> serde_json::Value {
        lua.globals().set("PATCH_OLD", old).expect("set PATCH_OLD");
        lua.globals()
            .set("PATCH_DIFF", diff)
            .expect("set PATCH_DIFF");
        let json: String = lua
            .load(
                r#"
                local ok, res = pcall(require("fs").patch.apply, PATCH_OLD, PATCH_DIFF)
                if not ok then
                  return agent.api.json_encode({ ok = false, error = tostring(res) })
                end
                return agent.api.json_encode({ ok = true, content = res.content,
                                            added = res.added, removed = res.removed,
                                            before = res.before_changed, after = res.after_changed })
                "#,
            )
            .eval::<String>()
            .expect("run the fs patch engine");
        serde_json::from_str(&json).expect("patch apply result json")
    }

    #[test]
    fn patch_engine_applies_unified_diffs_in_lua() {
        let lua = shipped_vm();

        // Basic replace: context, counts, optional heading — and the changed
        // line spans in both directions.
        let v = patch_apply(
            &lua,
            "zero\none\ntwo\nthree\nfour\n",
            "--- a/x\n+++ b/x\n@@ -2,2 +2,3 @@ tune\n one\n-two\n+two and a half\n+THREE!\n",
        );
        assert_eq!(v["ok"], true, "basic apply failed: {v}");
        assert_eq!(
            v["content"],
            "zero\none\ntwo and a half\nTHREE!\nthree\nfour\n"
        );
        assert_eq!(v["added"], 2);
        assert_eq!(v["removed"], 1);
        assert_eq!(v["before"], serde_json::json!([[3, 3]]));
        assert_eq!(v["after"], serde_json::json!([[3, 4]]));

        // Multiple hunks, applied strictly in order.
        let v = patch_apply(
            &lua,
            "a\nb\nc\nd\ne\n",
            "@@ -1,2 +1,2 @@\n-a\n+x\n b\n@@ -4,2 +4,2 @@\n d\n-e\n+y\n",
        );
        assert_eq!(v["ok"], true, "multi-hunk failed: {v}");
        assert_eq!(v["content"], "x\nb\nc\nd\ny\n");

        // Insertion anchored by context; pure deletion with trailing context.
        let v = patch_apply(&lua, "a\nb\nc\n", "@@ -2,1 +2,2 @@\n b\n+mid\n");
        assert_eq!(v["ok"], true, "insert failed: {v}");
        assert_eq!(v["content"], "a\nb\nmid\nc\n");
        let v = patch_apply(&lua, "a\nb\nc\n", "@@ -1,1 +1,1 @@\n-a\n b\n");
        assert_eq!(v["ok"], true, "delete failed: {v}");
        assert_eq!(v["content"], "b\nc\n");

        // Bare "@@" headers (no position info at all) and line numbers that
        // lie — location is content-based, so drift changes nothing.
        let v = patch_apply(&lua, "x\ny\n", "@@\n x\n-y\n+z\n");
        assert_eq!(v["ok"], true, "bare header failed: {v}");
        assert_eq!(v["content"], "x\nz\n");
        let v = patch_apply(
            &lua,
            "one\ntwo\nthree\n",
            "@@ -100,1 +100,1 @@\n-two\n+deux\n",
        );
        assert_eq!(v["ok"], true, "wrong numbers failed: {v}");
        assert_eq!(v["content"], "one\ndeux\nthree\n");

        // Content lines that themselves start with '-' or '+' survive intact:
        // "--stay" removes the file line "-stay", "-+ move" removes the line
        // "+ move", and " -a" is a context line whose text is "-a".
        let v = patch_apply(
            &lua,
            "-stay\n+ move\n",
            "@@ -1,2 +1,2 @@\n--stay\n-+ move\n+-stay\n+= gone\n",
        );
        assert_eq!(v["ok"], true, "prefix content failed: {v}");
        assert_eq!(v["content"], "-stay\n= gone\n");
        assert_eq!(v["removed"], 2);
        assert_eq!(v["added"], 2);
        assert_eq!(v["before"], serde_json::json!([[1, 2]]));
        assert_eq!(v["after"], serde_json::json!([[1, 2]]));
        let v = patch_apply(&lua, "-a\nb\n", "@@ -1,2 +1,2 @@\n -a\n-b\n+c\n");
        assert_eq!(v["ok"], true, "dash context failed: {v}");
        assert_eq!(v["content"], "-a\nc\n");

        // The file's trailing newline is preserved on both sides, and a file
        // without one keeps none.
        let v = patch_apply(&lua, "a\nb\n", "@@ -1,1 +1,1 @@\n-a\n+x\n");
        assert_eq!(v["content"], "x\nb\n");
        let v = patch_apply(&lua, "a\nb", "@@ -1,1 +1,1 @@\n-a\n+x\n");
        assert_eq!(v["content"], "x\nb");

        // CRLF input is matched as LF and rewritten as LF on apply.
        let v = patch_apply(&lua, "a\r\nb\r\n", "@@ -1,2 +1,2 @@\n a\n-b\n+b2\n");
        assert_eq!(v["ok"], true, "crlf failed: {v}");
        assert_eq!(v["content"], "a\nb2\n");

        // A context-only hunk is a legal no-op (an already-applied patch).
        let v = patch_apply(&lua, "a\nb\n", "@@ -1,2 +1,2 @@\n a\n b\n");
        assert_eq!(v["ok"], true, "no-op failed: {v}");
        assert_eq!(v["content"], "a\nb\n");
        assert_eq!(v["added"], 0);
        assert_eq!(v["removed"], 0);

        // Already-applied hunks are no-ops, not duplications: re-applying a
        // pure insertion (the added lines already follow the context) and a
        // replacement (the old side is gone, the new side is present) both
        // reproduce the file exactly.
        let insert = "@@ -2,1 +2,2 @@\n b\n+mid\n";
        let v = patch_apply(&lua, "a\nb\nc\n", insert);
        assert_eq!(v["content"], "a\nb\nmid\nc\n", "first insert: {v}");
        let v = patch_apply(&lua, "a\nb\nmid\nc\n", insert);
        assert_eq!(v["content"], "a\nb\nmid\nc\n", "re-insert no-op: {v}");
        assert_eq!(v["added"], 0);
        let replace = "@@ -2,2 +2,2 @@\n b\n-c\n+d\n";
        let v = patch_apply(&lua, "a\nb\nc\n", replace);
        assert_eq!(v["content"], "a\nb\nd\n", "first replace: {v}");
        let v = patch_apply(&lua, "a\nb\nd\n", replace);
        assert_eq!(v["content"], "a\nb\nd\n", "re-replace no-op: {v}");
        assert_eq!(v["removed"], 0);
        assert_eq!(v["added"], 0);

        // Error paths are clean, named failures — never partial applies.
        let v = patch_apply(&lua, "a\n", "--- a/x\n+++ b/x\n");
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().contains("no @@ hunks"));
        let v = patch_apply(&lua, "a\n", "@@ -0,0 +1,1 @@\n+nope\n");
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().contains("without context"));
        let v = patch_apply(&lua, "a\n", "@@ -1,1 +1,1 @@\n-wrong\n+x\n");
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().contains("does not match"));
        let v = patch_apply(&lua, "a\n", "@@ -1,1 +1,1 @@\nplain text line\n");
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().contains("unexpected line"));
    }

    /// `write_file` asks before it writes, and the answer is the only gate:
    /// nothing is created until the user says yes, and a refusal creates nothing
    /// at all.
    #[test]
    fn write_file_asks_before_it_writes() {
        let dir = std::env::temp_dir().join(format!("agent-write-file-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let target = dir.join("nested/deep/hello.txt");
        let args = |content: &str| {
            serde_json::json!({
                "path": target.to_string_lossy().to_string(),
                "content": content,
            })
            .to_string()
        };

        // Refused: not one byte, not one directory.
        let (v, asked) = call_tool_asking("fs.write_file", &args("nope\n"), AskAnswer::Deny(None));
        assert_eq!(v["ok"], false, "a refused write is not ok: {v}");
        assert_eq!(v["denied"], true, "and it says it was denied: {v}");
        assert_eq!(asked.len(), 1, "one question: {asked:?}");
        assert!(
            asked[0].contains("Allow write") && asked[0].contains(&target.to_string_lossy().to_string()),
            "the question names the write and the path: {:?}",
            asked[0]
        );
        assert!(!dir.exists(), "a refused write created nothing");

        // Allowed: the file lands verbatim, parent directories and all.
        let (v, asked) = tool_allowed("fs.write_file", &args("hello\nsandbox\n"));
        assert_eq!(v["ok"], true, "write failed: {v}");
        assert_eq!(v["result"]["bytes"], 14);
        assert_eq!(v["result"]["lines"], 2);
        assert_eq!(asked.len(), 1, "and it asked exactly once: {asked:?}");
        assert_eq!(
            std::fs::read_to_string(&target).expect("file on disk"),
            "hello\nsandbox\n",
            "content landed verbatim and the parent directories were created"
        );

        // Overwriting is a write too: it asks again, because a plain yes is for
        // that one operation.
        let (v, asked) = tool_allowed("fs.write_file", &args("x"));
        assert_eq!(v["ok"], true, "overwrite failed: {v}");
        assert_eq!(v["result"]["bytes"], 1);
        assert_eq!(asked.len(), 1, "asked again: {asked:?}");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "x");

        // Missing required argument: validation catches it before the ask, so
        // nothing is even questioned.
        let (v, asked) = tool_allowed("fs.write_file", r#"{"content":"hi"}"#);
        assert_eq!(v["ok"], false, "validation error: {v}");
        assert!(
            v["error"].as_str().unwrap_or("").contains("path"),
            "the error names the missing argument: {v}"
        );
        assert!(asked.is_empty(), "and nothing was asked: {asked:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `read` covers a file and a directory, and asks before either.
    ///
    /// The stdlib opens a directory happily and only fails on the *read*, so
    /// which one this is gets decided by `read(0)` returning nil — asserted
    /// here by both branches working, because a probe that guessed wrong would
    /// make one of them a clean error instead.
    #[test]
    fn the_read_tools_ask_and_return_the_file_directly() {
        let dir = std::env::temp_dir().join(format!("agent-fs-tools-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let target = dir.join("notes.txt");
        std::fs::write(&target, "alpha\nbeta\n").expect("seed");
        let path = target.to_string_lossy().to_string();
        let args = serde_json::json!({ "path": &path }).to_string();

        // A refused read returns the denial, not a complaint about the file.
        let (v, asked) = call_tool_asking("fs.read", &args, AskAnswer::Deny(None));
        assert_eq!(v["ok"], false, "a refused read is not ok: {v}");
        assert_eq!(v["denied"], true, "and it says it was denied: {v}");
        assert_eq!(asked.len(), 1, "one question: {asked:?}");
        assert!(
            asked[0].contains("Allow read") && asked[0].contains(&path),
            "the question names the read and the path: {:?}",
            asked[0]
        );

        // Allowed: the bytes, numbered by this module now (no `cat -n`).
        let (v, _asked) = tool_allowed("fs.read", &args);
        assert_eq!(v["ok"], true, "read failed: {v}");
        let content = v["result"]["content"].as_str().unwrap_or_default();
        assert_eq!(content, "1\talpha\n2\tbeta\n", "numbered, and nothing else: {content:?}");

        // The same tool, on a directory: the listing, and the same question.
        let dir_args =
            serde_json::json!({ "path": dir.to_string_lossy().to_string() }).to_string();
        let (v, asked) = tool_allowed("fs.read", &dir_args);
        assert_eq!(v["ok"], true, "listing a directory failed: {v}");
        assert!(
            v["result"]["content"].as_str().unwrap_or_default().contains("notes.txt"),
            "the listing names the file: {v}"
        );
        assert_eq!(asked.len(), 1, "asked once: {asked:?}");
        assert!(
            asked[0].contains("Allow read"),
            "a listing is still a read: {:?}",
            asked[0]
        );

        // A directory that is not there is a clean error, not a crash.
        let missing =
            serde_json::json!({ "path": dir.join("nope").to_string_lossy().to_string() })
                .to_string();
        let (v, _) = tool_allowed("fs.read", &missing);
        assert_eq!(v["ok"], false, "reading a missing path fails cleanly: {v}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ask_lib_asks_from_a_policy_and_keeps_the_reason() {
        // Asks on any write open, using agent.seccomp for the flags and
        // agent.ask for the question — no magic numbers, no raw yield.
        const POLICY: &str = r#"
        local sc, ask = agent.seccomp, agent.ask
        local p = setmetatable({}, { __index = function() return function() return true end end })
        p.openat = function(sys)
          local flags = sc.arg(sys, "openat")
          if sc.is_tty_probe(flags) then return true end
          if sc.check("openat", flags, "WRITE") then
            return ask(ask.for_syscall(sys, "write", sc.describes("openat", flags)))
          end
          return true
        end
        return p
        "#;
        let path = std::env::temp_dir().join(format!("ask-lib-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let cmdline = format!("echo asked > {}", path.display());

        // Denied: the handler's reason is what the outcome reports.
        let asked: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let seen = asked.clone();
        let out = run_bash(
            &cmdline,
            POLICY,
            None,
            Some(Rc::new(move |text: &str, _always: bool| {
                seen.borrow_mut().push(text.to_string());
                AskAnswer::Deny(Some("the operator said no".to_string()))
            })),
        )
        .expect("bash ran");
        assert!(out.denied >= 1, "the ask denied the write open");
        assert!(out.failed(), "a denied ask must not exit cleanly");
        assert_eq!(
            out.denied_reason.as_deref(),
            Some("the operator said no"),
            "the handler's reason survives the ask"
        );
        assert!(!path.exists(), "a denied open must not create the file");
        let questions = asked.borrow().clone();
        assert_eq!(questions.len(), 1, "one ask: {questions:?}");
        assert!(
            questions[0].contains("openat (pid") && questions[0].contains("requests write"),
            "the question is the canonical description: {}",
            questions[0]
        );

        // Allowed: the same policy, allowed, completes the run.
        let out = run_bash(
            &cmdline,
            POLICY,
            None,
            Some(Rc::new(|_, _always: bool| AskAnswer::Allow)),
        )
        .expect("bash ran");
        assert_eq!(out.denied, 0, "an allowed ask lets the open through");
        assert!(!out.failed(), "the allowed run finishes: {out:?}");
        assert_eq!(
            std::fs::read_to_string(&path).expect("written"),
            "asked\n",
            "the allowed write landed"
        );
        let _ = std::fs::remove_file(&path);

        // The no-handler case, through ask.drive: a denial that names itself
        // rather than the exception s:run() would raise mid-run.
        let lua = vm();
        lua.globals().set("ASK_CMDLINE", cmdline.clone()).expect("cmdline");
        lua.globals().set("ASK_POLICY", POLICY).expect("policy");
        let reason: Option<String> = lua
            .load(
                r#"
            -- `run_bash` takes a policy *source string* (it splices it into a
            -- chunk); agent.bash wants the table, so build it here.
            local policy = assert(load(ASK_POLICY))()
            local s = agent.bash(ASK_CMDLINE, policy, {})
            -- ask.drive with no handler: the ask resolves to a denial.
            local r = agent.ask.drive(s)
            return r.denied > 0 and r.denied_reason or nil
        "#,
            )
            .eval()
            .expect("ask.drive eval");
        assert!(
            reason.as_deref().is_some_and(|r| r.starts_with("no ask handler")),
            "the default handler names the missing handler, got {reason:?}"
        );
    }

    /// A reasonless denial must stay reasonless all the way to the outcome:
    /// `denied_reason = nil` and a bare "Denied" on the panel. A policy that
    /// *asks* and is answered with a plain `false` is exactly that case — and
    /// it is how the headless bash tool denies (no user to ask).
    #[test]
    fn a_reasonless_ask_denial_carries_no_reason() {
        const POLICY: &str = r#"
        local sc, ask = agent.seccomp, agent.ask
        local p = setmetatable({}, { __index = function() return function() return true end end })
        p.openat = function(sys)
          local flags = sc.arg(sys, "openat")
          if sc.is_tty_probe(flags) then return true end
          if sc.check("openat", flags, "WRITE") then
            -- The path comes from the module too: no sys.str indexing here.
            return ask("write open on " .. (sc.path(sys) or "?"))
          end
          return true
        end
        return p
        "#;
        let path = std::env::temp_dir().join(format!("ask-noreason-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        // Headless: no ask handler, so `agent.api.ask_user` answers `false`.
        let out = run_bash(&format!("echo x > {}", path.display()), POLICY, None, None)
            .expect("bash ran");
        assert!(out.denied >= 1, "the ask denied the write open");
        assert_eq!(
            out.denied_reason, None,
            "a plain false must not fabricate a reason"
        );
        assert!(!path.exists(), "nothing was written");
        let _ = std::fs::remove_file(&path);

        // The path really does reach the question: the file name appears in the
        // description, resolved by the engine (not raw from `sys.str`).
        let wanted = path.file_name().unwrap().to_string_lossy().to_string();
        let out = run_bash(
            &format!("echo x > {}", path.display()),
            POLICY,
            None,
            Some(Rc::new(move |text: &str, _always: bool| {
                assert!(text.contains(&wanted), "the question names the file: {text}");
                AskAnswer::Deny(Some("no".to_string()))
            })),
        )
        .expect("bash ran");
        assert!(out.denied >= 1);
    }

    #[test]
    fn apply_patch_tool_edits_a_file_and_reports_changes() {
        let dir =
            std::env::temp_dir().join(format!("agent-apply-patch-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let target = dir.join("script.txt");
        std::fs::create_dir_all(&dir).expect("make scratch dir");
        std::fs::write(&target, "one\ntwo\nthree\n").expect("seed file");

        // Insert a line after "two": the tool reads, applies, writes, and
        // reports the count of changed lines.
        let patch = "@@ -2,1 +2,2 @@\n two\n+two and a half\n";
        let args = serde_json::json!({
            "path": target.to_string_lossy().to_string(),
            "patch": patch,
        })
        .to_string();
        // A patch is one write decision: one question, then the read the diff
        // needs and the write itself, both direct.
        let (v, asked) = tool_allowed("fs.apply_patch", &args);
        let body = v.to_string();
        assert_eq!(asked.len(), 1, "one question for the whole patch: {asked:?}");
        assert!(
            asked[0].contains("Allow write")
                && asked[0].contains(&target.to_string_lossy().to_string()),
            "the question names the write and the path: {:?}",
            asked[0]
        );
        assert_eq!(v["ok"], true, "patch failed: {body}");
        assert_eq!(v["result"]["changed"], true);
        assert_eq!(v["result"]["added"], 1);
        assert_eq!(v["result"]["removed"], 0);
        assert_eq!(
            std::fs::read_to_string(&target).expect("read back"),
            "one\ntwo\ntwo and a half\nthree\n"
        );

        // Applying the identical patch again is a no-op: matched by content,
        // the recomputed text equals the file, so nothing is rewritten.
        let (v, _) = tool_allowed("fs.apply_patch", &args);
        let body = v.to_string();
        assert_eq!(v["ok"], true, "idempotent apply failed: {body}");
        assert_eq!(v["result"]["changed"], false, "{body}");
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "one\ntwo\ntwo and a half\nthree\n",
            "a no-op patch leaves the file untouched"
        );

        // A hunk that does not match the file is a clean error and nothing is
        // written — the failed apply never corrupts the file.
        let bad = serde_json::json!({
            "path": target.to_string_lossy().to_string(),
            "patch": "@@ -1,1 +1,1 @@\n-nope\n+yes\n",
        })
        .to_string();
        let (v, _) = tool_allowed("fs.apply_patch", &bad);
        let body = v.to_string();
        assert_eq!(v["ok"], false, "bad patch errors: {body}");
        assert!(
            v["error"].as_str().unwrap_or("").contains("does not match"),
            "the error names the failing hunk: {body}"
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "one\ntwo\ntwo and a half\nthree\n",
            "a failed patch left the file alone"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn on_event_registers_a_handler_and_fire_event_invokes_it_with_the_payload() {
        // The read side of compaction: the handler receives the payload — the
        // conversation's history — as its argument, exactly the shape the
        // TUI's turn_completed event carries.
        let lua = vm();
        apply_config_source(
            &lua,
            r#"
            agent.on_event("turn_completed", function(info)
              agent._seen = info
            end)
            "#,
        )
        .expect("apply");
        fire_event_on_vm(
            &lua,
            "turn_completed",
            &serde_json::json!({
                "history": [
                    {"role": "user", "content": "hi"},
                    {"role": "assistant", "content": "hello"},
                ]
            }),
        )
        .expect("fire");
        let first_role: String = lua
            .load("return agent._seen.history[1].role")
            .eval()
            .expect("payload round-trip");
        let last_content: String = lua
            .load("return agent._seen.history[2].content")
            .eval()
            .expect("payload round-trip");
        assert_eq!(first_role, "user");
        assert_eq!(last_content, "hello");
    }

    #[test]
    fn on_event_without_a_handler_is_a_noop() {
        // No registration for the name, and an unknown event name: events are
        // opt-in, so both fire as Ok(()) rather than errors.
        let lua = vm();
        fire_event_on_vm(&lua, "bogus", &serde_json::json!({})).expect("no handler: no-op");
        apply_config_source(&lua, "agent.on_event(\"turn_completed\", function() end)")
            .expect("apply");
        fire_event_on_vm(&lua, "turn_completed", &serde_json::json!({})).expect("registered: fire");
    }

    #[test]
    fn on_timeout_falls_back_to_a_thread_sleep_outside_the_reactor() {
        // A VM that is not reactor-driven (tool threads, tests, top-level
        // config): `agent.on_timeout` keeps the historical `_sleep` behavior —
        // a real thread sleep, then `fn` — and reports `false` so callers can
        // tell the fallback from a cooperative wait.
        let lua = vm();
        let started = std::time::Instant::now();
        let fired: u32 = lua
            .load(
                r#"
                local fired = 0
                local first = agent.on_timeout(30, function() fired = 1 end)
                assert(first == false, "plain VM: on_timeout falls back and returns false")
                return fired
                "#,
            )
            .eval()
            .expect("on_timeout in a plain vm");
        assert_eq!(fired, 1, "the fn must still run after the wait");
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(25),
            "plain-VM on_timeout must actually sleep ({} elapsed)",
            started.elapsed().as_millis()
        );
    }

    #[test]
    fn event_run_drives_the_handler_as_a_single_threaded_coroutine() {
        // The reactor-driven path behind `turn_completed`: `agent.on_timeout`
        // suspends the handler coroutine instead of sleeping the thread, and
        // `EventRun::step` resumes it when the reactor's timer fires —
        // strictly single-threaded, with nothing else frozen in between.
        let lua = vm();
        apply_config_source(
            &lua,
            r#"
            agent.on_event("turn_completed", function(info)
              agent.__acc = {}
              table.insert(agent.__acc, "start")
              local resumed = agent.on_timeout(20, function()
                table.insert(agent.__acc, "fn")
              end)
              assert(resumed, "reactor resume lands true at the yield site")
              table.insert(agent.__acc, "resumed-true")
              agent.on_timeout(5)
              table.insert(agent.__acc, "done")
            end)
            "#,
        )
        .expect("apply");
        let (mut run, step) =
            EventRun::start(&lua, "turn_completed", &serde_json::json!({ "history": [] }))
                .expect("start")
                .expect("handler registered");
        // First resume: the handler ran up to its first wait.
        assert_eq!(step, EventStep::Waiting { ms: 20 });
        // Resume after the reactor's 20ms timer: fn ran, then the next wait.
        assert_eq!(
            run.step().expect("after 20ms"),
            EventStep::Waiting { ms: 5 }
        );
        // Resume after the 5ms timer: the handler completes.
        assert_eq!(run.step().expect("after 5ms"), EventStep::Returned);
        let acc: mlua::Table = run
            .lua()
            .globals()
            .get::<Table>("agent")
            .expect("agent table")
            .get("__acc")
            .expect("acc table");
        let joined: Vec<String> = (1..=4u64)
            .map(|i| acc.get::<String>(i).expect("acc entry"))
            .collect();
        assert_eq!(joined, ["start", "fn", "resumed-true", "done"]);
    }

    #[test]
    fn event_run_rejects_a_stray_non_timeout_yield() {
        // A handler yielding a raw value (not an agent.on_timeout request)
        // surfaces an error instead of hanging the driver.
        let lua = vm();
        apply_config_source(
            &lua,
            r#"
            agent.on_event("turn_completed", function(info)
              coroutine.yield("stray")
            end)
            "#,
        )
        .expect("apply");
        let out = EventRun::start(&lua, "turn_completed", &serde_json::json!({}));
        let err = match out {
            Err(e) => e,
            Ok(_) => panic!("a stray yield must surface as a start error"),
        };
        assert!(
            err.contains("unsupported value"),
            "expected an unsupported-yield error, got: {err}"
        );
    }

    /// Drive an `EventRun` to completion by answering every wait the way the
    /// reactor would (its timer fired), counting the cooperative suspensions.
    /// Returns `(run, waits)`.
    fn drive_event_to_completion(mut run: EventRun, mut step: EventStep) -> (EventRun, u64) {
        let mut waits = 0;
        loop {
            match step {
                EventStep::Waiting { .. } => {
                    waits += 1;
                    step = run.step().expect("event timer fired");
                }
                EventStep::Returned => return (run, waits),
            }
        }
    }

    /// Read a table the handler stamped onto the event VM's `agent` global.
    fn event_agent_field(run: &EventRun, key: &str) -> mlua::Table {
        run.lua()
            .globals()
            .get::<Table>("agent")
            .expect("agent table")
            .get(key)
            .expect("handler field")
    }

    #[test]
    fn event_handler_bash_runs_cooperatively_with_the_loop_live() {
        // An event handler calling `agent.bash` must not freeze the loop: on
        // the reactor every `_step` poll is non-blocking and the pump suspends
        // for a cadence between idle steps, so `EventRun::step` answers
        // `Waiting` all the way through a long-running command instead of the
        // pump blocking the thread. This is cooperative `agent.bash`.
        let lua = vm();
        apply_config_source(
            &lua,
            r#"
            agent.on_event("turn_completed", function(info)
              local r = agent.bash("sleep 0.3", {
                clock_nanosleep = function() return true end,
                nanosleep = function() return true end,
              }):run()
              agent.__done = { code = r.exit.code }
            end)
            "#,
        )
        .expect("apply");
        let (run, step) =
            EventRun::start(&lua, "turn_completed", &serde_json::json!({ "history": [] }))
                .expect("start")
                .expect("handler registered");
        let started = std::time::Instant::now();
        let (run, waits) = drive_event_to_completion(run, step);
        // The sandbox itself ran to completion with exit 0...
        let done = event_agent_field(&run, "__done");
        assert_eq!(done.get::<i64>("code").expect("exit code"), 0);
        // ...and the coroutine suspended across wall-clock time, multiple
        // times, each an idle-cadence wait — the loop stayed live rather
        // than the pump blocking for the whole sleep.
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(200),
            "a 0.3s sleep must span wall time ({} elapsed)",
            started.elapsed().as_millis()
        );
        assert!(
            waits >= 2,
            "a 0.3s sleep must suspend repeatedly, got {waits} waits"
        );
    }

    #[test]
    fn event_handler_bash_streams_output_and_returns_the_result() {
        // A handler's bash (here small enough that the whole run can fit in
        // one slice) still streams output through the callbacks and hands the
        // handler the full result table: stdout, exit code, no denials.
        let lua = vm();
        apply_config_source(
            &lua,
            r#"
            agent.on_event("turn_completed", function(info)
              local out = {}
              local r = agent.bash("echo cooperative", {
                write = function() return true end,
              }, {
                on_stdout = function(c) out[#out + 1] = c end,
              }):run()
              agent.__bash = {
                stdout = r.stdout, code = r.exit.code,
                denied = r.denied, chunks = table.concat(out),
              }
            end)
            "#,
        )
        .expect("apply");
        let (run, step) =
            EventRun::start(&lua, "turn_completed", &serde_json::json!({ "history": [] }))
                .expect("start")
                .expect("handler registered");
        let (run, _waits) = drive_event_to_completion(run, step);
        let t = event_agent_field(&run, "__bash");
        assert_eq!(t.get::<String>("stdout").expect("stdout"), "cooperative\n");
        assert_eq!(t.get::<i64>("code").expect("exit code"), 0);
        assert_eq!(t.get::<u64>("denied").expect("denied"), 0);
        assert_eq!(t.get::<String>("chunks").expect("chunks"), "cooperative\n");
    }

    #[test]
    fn event_handler_bash_auto_denies_a_policy_ask() {
        // A background handler has no ask UI, so a policy that raises an ask
        // auto-denies (exactly like headless runs): the tracee is killed, the
        // run terminates, and the handler gets the final result with denied.
        let lua = vm();
        apply_config_source(
            &lua,
            r#"
            agent.on_event("turn_completed", function(info)
              local r = agent.bash("echo ask-me", {
                write = function(sys)
                  local function uask(v) return coroutine.yield(v) end
                  return uask("write in a handler?")
                end,
              }):run()
              agent.__bash = { denied = r.denied, stdout = r.stdout }
            end)
            "#,
        )
        .expect("apply");
        let (run, step) =
            EventRun::start(&lua, "turn_completed", &serde_json::json!({ "history": [] }))
                .expect("start")
                .expect("handler registered");
        let (run, _waits) = drive_event_to_completion(run, step);
        let t = event_agent_field(&run, "__bash");
        assert!(
            t.get::<u64>("denied").expect("denied") >= 1,
            "the ask auto-denies"
        );
        assert_eq!(
            t.get::<String>("stdout").expect("stdout"),
            "",
            "killed before output"
        );
    }

    #[test]
    fn plain_context_bash_run_without_an_ask_handler_raises() {
        // Outside the reactor (tool threads, top-level config), `run()` has no
        // cooperative auto-deny: an ask without an `on_ask` handler keeps
        // raising, so a caller that drops the handler on the floor hears it.
        let lua = vm();
        let bad = lua
            .load(
                r#"
                local r = agent.bash("echo nope", {
                  write = function() return coroutine.yield("ask") end,
                }):run()
                return "ran"
                "#,
            )
            .eval::<String>();
        let e = match bad {
            Err(e) => e.to_string(),
            Ok(_) => panic!("an ask without on_ask must raise in a plain VM"),
        };
        assert!(
            e.contains("no on_ask handler"),
            "expected the ask error, got: {e}"
        );
    }

    #[test]
    fn trigger_registration_requires_a_string_name_and_function_handler() {
        let lua = vm();
        // agent.on_event / agent.trigger live in lua/init.lua, like the rest
        // of the config machinery; load it (with an empty user source) first.
        apply_config_source(&lua, "").expect("driver");
        let bad = lua
            .load("agent.on_event(42, function() end)")
            .eval::<mlua::Value>();
        assert!(bad.is_err(), "event name must be a string");
        let bad = lua
            .load("agent.on_event(\"turn_completed\", 7)")
            .eval::<mlua::Value>();
        assert!(bad.is_err(), "handler must be a function");
    }

    #[test]
    fn trigger_queues_run_turn_commands_on_the_bound_channel() {
        // One test owns the process-wide trigger channel (OnceLock): assert
        // the unbound behavior first, then bind and exercise all three
        // argument shapes.
        let lua = vm();
        apply_config_source(&lua, "").expect("driver");
        let unbound: bool = lua
            .load("return agent.trigger()")
            .eval()
            .expect("unbound trigger");
        assert!(!unbound, "no loop attached -> false, so Lua can branch");

        let (tx, mut rx) = mpsc::unbounded_channel::<AgentCommand>();
        assert!(bind_trigger_channel(tx).is_some(), "first bind wins");

        // No argument: a continuation of the current conversation.
        let ok: bool = lua.load("return agent.trigger()").eval().expect("trigger");
        assert!(ok, "bound channel -> queued");
        match rx.try_recv().expect("command") {
            AgentCommand::RunTurn {
                history: None,
                user: None,
            } => {}
            other => panic!("continuation expected, got {other:?}"),
        }

        // A string: a submitted user message.
        let ok: bool = lua
            .load("return agent.trigger('compact and continue')")
            .eval()
            .expect("trigger");
        assert!(ok);
        match rx.try_recv().expect("command") {
            AgentCommand::RunTurn {
                history: None,
                user: Some(u),
            } => {
                assert_eq!(u, "compact and continue")
            }
            other => panic!("user message expected, got {other:?}"),
        }

        // An array of messages: a history replacement — the write side.
        let ok: bool = lua
            .load(
                "return agent.trigger({ {role='system', content='summary'}, \
                   {role='user', content='tail'} })",
            )
            .eval()
            .expect("trigger");
        assert!(ok);
        match rx.try_recv().expect("command") {
            AgentCommand::RunTurn {
                history: Some(h),
                user: None,
            } => {
                assert_eq!(h[0]["role"], "system");
                assert_eq!(h[0]["content"], "summary");
                assert_eq!(h[1]["role"], "user");
                assert_eq!(h[1]["content"], "tail");
            }
            other => panic!("history replacement expected, got {other:?}"),
        }

        // A non-array table and other argument types are rejected: agent.trigger
        // must not silently turn a typo into a history wipe.
        let err = lua
            .load("return agent.trigger({role='system'})")
            .eval::<mlua::Value>();
        assert!(err.is_err(), "an object is not a message array");
        let err = lua.load("return agent.trigger(42)").eval::<mlua::Value>();
        assert!(err.is_err(), "a number is not a prompt");
    }

    #[test]
    fn memory_primitives_append_read_flush_path() {
        // One test owns the process-wide log (OnceLock), like the trigger
        // channel: assert the unbound behavior first, then bind a temporary
        // log and exercise the whole Lua surface plus the loop-side helpers.
        let lua = vm();
        apply_config_source(&lua, "").expect("driver");

        // Unbound: the write actions raise "no log open"; path() is nil and
        // flush() is a harmless no-op (exit paths must not fail on it).
        let err = lua
            .load("return agent.memory.append('{}')")
            .eval::<mlua::Value>();
        assert!(err.is_err(), "unbound append must raise");
        let err = lua
            .load("return agent.memory.latest(1)")
            .eval::<mlua::Value>();
        assert!(err.is_err(), "unbound latest must raise");
        let _: bool = lua
            .load("return agent.memory.flush()")
            .eval()
            .expect("unbound flush no-op");
        let path_nil: bool = lua
            .load("return agent.memory.path() == nil")
            .eval()
            .expect("unbound path is nil");
        assert!(path_nil, "informational path() is nil when unbound");

        let dir = std::env::temp_dir().join(format!("agent-memory-{}", std::process::id()));
        let file = dir.join("history.amem");
        let _ = std::fs::remove_dir_all(&dir); // stale from a crashed earlier run
        std::fs::create_dir_all(&dir).expect("temp dir");
        let mem = Arc::new(Mutex::new(Memory::open(&file).expect("open")));
        assert!(bind_memory(mem).is_some(), "first bind wins");

        // path() reflects the open log.
        let p: String = lua.load("return agent.memory.path()").eval().expect("path");
        assert!(p.ends_with("history.amem"), "path is the open log: {p}");

        // append a table (auto-encoded) and a JSON string; both return the
        // message's sequence number.
        let seq1: u64 = lua
            .load("return agent.memory.append({ role='user', content='hi' })")
            .eval()
            .expect("append table");
        let seq2: u64 = lua
            .load("return agent.memory.append('{\"role\":\"assistant\",\"content\":\"hello\"}')")
            .eval()
            .expect("append string");
        assert_eq!((seq1, seq2), (1, 2), "per-process sequences, oldest first");

        // latest(n) reads them back in append order, as JSON strings.
        let n: usize = lua
            .load("return #agent.memory.latest(10)")
            .eval()
            .expect("count");
        assert_eq!(n, 2);
        let first: String = lua
            .load("return agent.memory.latest(10)[1]")
            .eval()
            .expect("first message");
        let v: serde_json::Value = serde_json::from_str(&first).expect("valid JSON line");
        assert_eq!(v["role"], "user");
        assert_eq!(v["content"], "hi");

        // The loop-side helpers share the same store: append_many + latest.
        let seq = memory_append_many(&[
            serde_json::json!({"role": "user", "content": "two"}),
            serde_json::json!({"role": "assistant", "content": "messages"}),
        ])
        .expect("append_many");
        assert_eq!(seq, 4);
        assert_eq!(
            memory_latest(10).expect("latest").len(),
            4,
            "one log, one writer"
        );

        // flush() seals to disk and a fresh open of the same file sees it.
        let ok: bool = lua
            .load("return agent.memory.flush()")
            .eval()
            .expect("flush");
        assert!(ok);
        assert!(memory_is_bound());
        let mut reread = Memory::open(&file).expect("reopen");
        assert_eq!(
            reread.latest(10).expect("latest from disk").len(),
            4,
            "flushed messages are on disk"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn memory_config_reads_enabled_path_and_defaults() {
        // `agent.llm.memory` steers where and whether the log opens: an
        // explicit table wins, absent fields fall back to defaults (enabled,
        // ~/.config/agent/history.amem, else ./history.amem).
        let lua = vm();
        apply_config_source(
            &lua,
            "agent.llm.memory = { enabled = false, path = '/tmp/other.amem' }",
        )
        .expect("driver + override");
        let cfg = memory_config(&lua).expect("read config");
        assert!(!cfg.enabled, "enabled = false opts out of saving");
        assert_eq!(cfg.path, std::path::PathBuf::from("/tmp/other.amem"));

        let lua = vm();
        apply_config_source(&lua, "").expect("driver");
        let cfg = memory_config(&lua).expect("defaults");
        assert!(cfg.enabled, "absent config defaults to enabled");
        assert!(
            cfg.path.to_string_lossy().ends_with("history.amem"),
            "default path names the log: {}",
            cfg.path.display()
        );
    }
/// The `key` event is a *question*, and its answer is the handler's return
/// value — which is the whole reason it does not go through
/// [`fire_event_on_vm`], where a return value is discarded.
///
/// Three answers, and the third is the one that matters: `nil` and `false`
/// both mean "not bound, use the default", and a handler that returns
/// something else is a broken binding table rather than an unbound key.
/// Treating it as "unbound" would make the table fail silently, which is the
/// failure mode [`Action::parse`] also refuses.
#[test]

fn the_key_event_hands_back_the_action_the_handler_named() {
    let lua = new_vm().expect("VM");
    lua.load(
        r#"
        SEEN = nil
        agent.on_event("key", function(k)
          SEEN = k.spec
          if k.spec == "alt+c" then return "conceal" end
          if k.spec == "q" then return "quit" end
          return nil
        end)
    "#,
    )
    .exec()
    .expect("register");

    let spec = |lua: &mlua::Lua| -> Option<String> {
        let seen: mlua::Value = lua.load("return SEEN").eval().expect("read back");
        seen.as_string().map(|s| s.to_string_lossy().to_string())
    };

    let answer = fire_event_returning(&lua, "key", &json!({ "spec": "alt+c" }));
    assert_eq!(answer.expect("no error").as_deref(), Some("conceal"));
    assert_eq!(spec(&lua).as_deref(), Some("alt+c"), "and the key arrives");

    assert_eq!(
        fire_event_returning(&lua, "key", &json!({ "spec": "j" }))
            .expect("no error"),
        None,
        "an unbound key is None, not an error: the default stands"
    );
    assert_eq!(spec(&lua).as_deref(), Some("j"), "and it was still asked");

    // An event nobody registered is the same answer as an unbound key. The
    // shipped config *does* register one, so it is removed rather than assumed
    // away — and that is the interesting case anyway, because a user is expected
    // to delete the table.
    let bare = new_vm().expect("VM");
    bare.load("agent._events.key = nil").exec().expect("unregister");
    assert_eq!(
        fire_event_returning(&bare, "key", &json!({ "spec": "q" })).expect("no error"),
        None,
        "events are opt-in: a VM with no handler has no opinion"
    );
}

/// `nil` and `false` both mean "unbound", and anything else is a broken
/// binding table that must not be allowed to pass for one.
        /// What the user actually sees while a write is being decided.
        ///
        /// Every other test in this area checks the *ops* — that a panel was opened,
        /// that an overlay was set on it, that the ids match. None of them render
        /// anything, so "the ops are right" and "the user can see what they are
        /// approving" are different claims, and only the second one is the one that
        /// matters for a permission prompt: a write is the one tool call where the
        /// content is the thing being consented to.
        ///
        /// The frame is built from the op *prefix* up to and including the ask. That
        /// is the moment the user is looking at: the panel is filled, the dialog is
        /// up, and the verdict has not been given — the tool then clears the overlay
        /// on its way out, so replaying the whole stream would show the finished
        /// state with no question on it, which is precisely what must not be
        /// mistaken for the real one.
        #[test]
        fn a_write_being_decided_shows_its_content_and_the_dialog_together() {
            use crate::panels::{PanelOp, PanelSink};

            let dir = std::env::temp_dir().join(format!("agent-writeframe-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("scratch dir");
            let target = dir.join("consent.rs");
            let path = target.to_string_lossy().to_string();
            let content = "fn main() {\n    let secret = 7;\n}\n";

            // Refused, so nothing is written and the refusal lands in the panel too.
            let sink = PanelSink::default();
            invoke_mcp_tool_with_asks(
                "fs.write_file",
                &serde_json::json!({ "path": &path, "content": content }).to_string(),
                Some(&sink),
                Some(Rc::new(|_: &str, _: bool| AskAnswer::Deny(Some("no".into())))),
                &ConfigSource::Tree,
            )
            .expect("invoke")
            .expect("registered");

            // The prefix: everything up to and including the question.
            let prefix = PanelSink::default();
            let mut saw_ask = false;
            for op in sink.ops() {
                saw_ask |= matches!(op, PanelOp::Overlay { text: Some(_), .. });
                prefix.push(op);
                if saw_ask {
                    break;
                }
            }
            assert!(saw_ask, "the write was questioned at all");

            let mut app = crate::tui::App::default();
            app.drain_panel_ops(&prefix);
            let (w, h) = (76u16, 26u16);
            let mut terminal =
                ratatui::Terminal::new(ratatui::backend::TestBackend::new(w, h)).expect("terminal");
            terminal.draw(|frame| app.render(frame)).expect("draw");
            let buf = terminal.backend().buffer().clone();
            let frame: String = (0..h)
                .map(|y| {
                    (0..w)
                        .map(|x| buf.cell((x, y)).map(|c| c.symbol()).unwrap_or(" ").to_string())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("\n");

            assert!(
                frame.contains("consent.rs"),
                "the panel names the file being written:\n{frame}"
            );
            assert!(
                frame.contains("let secret = 7;"),
                "and shows the bytes that would land on disk — a permission prompt \
                 about content the user cannot see is not consent:\n{frame}"
            );
            assert!(
                frame.contains("[y]es") && frame.contains("[a]lways"),
                "with the dialog on that same panel:\n{frame}"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }

    /// A second tool round gets its own panel, not the first round's.
    ///
    /// This is the bug, and it is invisible to any test that uses one sink: the
    /// per-round sink that carries both the round's Lua and Rust id producers
    /// restarts its counter, while the id→message map it is looked up in lives
    /// for the whole session. So round two's first panel took an id round one had
    /// used, found the existing record, and appended itself to that message — a
    /// write's content landing in the read box above it, and its dialog drawn
    /// there instead of on its own. The dialog usually ended up off the top of
    /// the viewport, which is why the report was "it asks, and `y` works, but
    /// there is no dialog".
    ///
    /// Built by hand rather than through two tool calls, because the harness makes
    /// a fresh VM per call and would number both rounds from 1 for a different
    /// reason — the same wrong number, arrived at honestly, which is worth
    /// pinning here and leaving alone there.
    #[test]
    fn a_second_round_opens_its_own_panel_and_asks_on_it() {
        use crate::panels::{PanelOp, PanelSink};

        let mut app = crate::tui::App::default();

        // Round one: a read, which is what a session almost always starts with.
        let first = PanelSink::default();
        let read_id = first.alloc_id();
        first.push(PanelOp::Create {
            id: read_id,
            title: "fs.read".into(),
            boxed: true,
            conceal_box: true,
        });
        first.push(PanelOp::Append {
            id: read_id,
            text: "cppreact.hpp\n".into(),
        });
        app.drain_panel_ops(&first);

        // Round two: a write, on a sink that continues the numbering.
        let second = PanelSink::continuing_from(first.next_id());
        let write_id = second.alloc_id();
        second.push(PanelOp::Split {
            id: write_id,
            title: "write_file: cppreact.hpp".into(),
            panes: vec![crate::panels::PaneInit {
                caption: "2 lines".into(),
                lang: Some("cpp".into()),
            }],
        });
        second.push(PanelOp::Overlay {
            id: write_id,
            text: Some("Allow write cppreact.hpp".into()),
            always: true,
        });
        app.drain_panel_ops(&second);

        assert_ne!(
            write_id, read_id,
            "the two rounds must not share an id, or the second panel is the first"
        );
        assert_eq!(
            app.panel.messages.len(),
            2,
            "two boxes on screen, not one with both jobs in it"
        );
        assert_eq!(app.panel.messages[0].text, "cppreact.hpp\n", "the read is its own");
        assert!(
            app.panel.messages[1].overlay.is_some(),
            "and the dialog is on the write's panel, not the read's"
        );
        assert!(
            app.panel.messages[0].overlay.is_none(),
            "the read panel is left alone"
        );
    }

    /// A restarted sink *would* collide, which is the bug this fix is about — so
    /// it is pinned as a fact about [`PanelSink::default`] rather than left as a
    /// trap for the next person to walk into.
    #[test]
    fn a_fresh_sink_starts_at_one_which_is_why_the_loop_continues_it() {
        use crate::panels::PanelSink;
        let a = PanelSink::default();
        assert_eq!(a.alloc_id(), 1);
        let b = PanelSink::continuing_from(a.next_id());
        assert_eq!(b.alloc_id(), 2, "the mark carries");
        assert_eq!(b.alloc_id(), 3);
        assert_eq!(a.alloc_id(), 2, "and the old sink is unaffected");
        assert_eq!(
            PanelSink::default().alloc_id(),
            1,
            "a default sink really does restart — the hazard, stated"
        );
    }

    #[test]
    fn a_key_handler_that_answers_with_nonsense_is_an_error() {
        for (body, why) in [
            ("return false", "false means unbound, not an error"),
            ("return 7", "a number is not an action name"),
            ("return {}", "a table is not an action name"),
        ] {
            let lua = new_vm().expect("VM");
            lua.load(format!("agent.on_event('key', function(k) {body} end)"))
                .exec()
                .expect("register");
            let got = fire_event_returning(&lua, "key", &json!({ "spec": "q" }));
            if why.starts_with("false") {
                assert_eq!(got.expect("no error"), None, "{why}");
            } else {
                let err = got.expect_err(why);
                assert!(err.contains("must return an action name"), "{why}: {err}");
            }
        }
        // A handler that raises is reported as itself, with the event named.
        let lua = new_vm().expect("VM");
        lua.load("agent.on_event('key', function(k) error('boom') end)")
            .exec()
            .expect("register");
        let err = fire_event_returning(&lua, "key", &json!({ "spec": "q" })).expect_err("raises");
        assert!(err.contains("event key"), "the event is named: {err}");
        assert!(err.contains("boom"), "and so is the failure: {err}");
    }
    /// The shipped config's binding table, row by row.
    ///
    /// This is the test that makes the table load-bearing in a *checked* way. Every
    /// key Rust used to hold moved into it, so a deleted or misspelled row is not a
    /// missing feature — it is an app you cannot type into, and nothing else would
    /// say so: the loop reports no error and the key is simply a letter. Both
    /// directions are pinned, so a row that starts resolving to something *else* is
    /// as visible as one that stops resolving at all.
    #[test]
    fn the_shipped_binding_table_resolves_to_real_actions() {
        let lua = new_vm().expect("VM");
        let ask = |spec: &str| {
            fire_event_returning(&lua, "key", &serde_json::json!({ "spec": spec }))
                .expect("the handler did not raise")
        };

        for (spec, want) in [
            ("enter", Some("send")),
            ("esc", Some("quit")),
            ("q", Some("quit")),
            ("alt+c", Some("conceal")),
            ("j", Some("scroll_down")),
            ("down", Some("scroll_down")),
            ("k", Some("scroll_up")),
            ("up", Some("scroll_up")),
            ("home", Some("top")),
            ("end", Some("bottom")),
            ("pageup", Some("scroll_up")),
            ("pagedown", Some("scroll_down")),
        ] {
            assert_eq!(ask(spec).as_deref(), want, "{spec} is bound to {want:?}");
        }

        // `alt+enter` is a *call*, not a name: it queues an input edit and answers
        // nothing. That is why the action list has one fewer entry than the table
        // has rows, and why there is no `newline` action to return.
        assert_eq!(ask("alt+enter"), None, "the newline is queued, not named");

        // Unbound, so the letter gate and the two Rust keys are all that stand
        // between a keypress and the input line.
        assert_eq!(ask("ctrl+q"), None, "nothing is bound to ctrl+q");
        assert_eq!(ask("f5"), None, "nor to f5");

        // And every name the table can produce is one the app knows — the check that
        // catches a typo in the table before it becomes a dead key.
        for spec in [
            "enter", "esc", "q", "alt+c", "j", "k", "home", "end", "pageup", "pagedown",
        ] {
            if let Some(name) = ask(spec) {
                assert!(
                    crate::tui::Action::parse(&name).is_ok(),
                    "{spec} resolves to {name:?}, which is not an action"
                );
            }
        }
}
}
