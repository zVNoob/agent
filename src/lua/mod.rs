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
//! The mask is not merely additive, and this is the one thing worth knowing
//! before writing one. A syscall can be an alternative *route* to work another
//! gate already covers: `IORING_OP_OPENAT` and its siblings are io_uring
//! submission-queue opcodes, not syscalls, so a policy that asks about
//! `openat` and `unlinkat` and does not also name `io_uring_enter` has gates
//! that any program able to speak the ring protocol can walk straight around.
//! `open_by_handle_at` is the same shape for the same reason — it selects a file
//! with an opaque handle rather than a name, so no path table can constrain it.
//! When adding a gate, the question is not only "should this syscall be asked
//! about" but "what does leaving it out let a program reach".
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
//! entry points, listed in `src/lua/bridge.rs`. Emitted ops buffer in the
//! round's [`PanelSink`] and the TUI applies them; with no sink (headless) they
//! are no-ops. Panels render through the same pipelines as every other message,
//! so the UI stays the familiar one.
//!
//! `agent.split_panel(title, panes)` is the sibling for multi-region panels:
//! one titled box holds several sub-panels, each with its own text and
//! *declared highlighting language* (`:set(pane, …)`, `:lang(pane, lang)`,
//! `:highlight(pane, …)`, `:clear_regions(pane)`). That is the building block
//! for a Lua `apply_patch`: before/after code renders side-by-side with
//! tree-sitter running on each pane's own clean text (a unified diff could
//! never do that — the grammar would choke on its `+`/`-` prefixes).
//! Underneath this is [`PanelOp::Split`] plus the `agent.api.panel_pane_*`
//! primitives, mirroring the single-body `agent.panel`.
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
//! ## Where this namespace is implemented
//!
//! This file is the namespace's *contract*; its implementation is split across
//! the sibling modules, each of which owns one layer of it:
//!
//! | module | what it owns |
//! |---|---|
//! | [`vm`] | building a VM: the stdlib, the `agent` table, the ask handler type |
//! | [`tree`] | assembling a VM's Lua from the shipped `lua/` tree (`require`, `lib/*`, `init.lua`) |
//! | [`bridge`] | everything in the `agent.api` table, and the read-only lock that guards it |
//! | [`sandbox`] | the seccomp primitives (`spawn`/`step`/`decide`/…) and the syscall-introspection helpers they report through |
//! | [`config`] | `agent.llm`, the system prompt, the `agent.mcps` registry, and the event/trigger hooks |
//! | [`run`] | a tool call and an event handler as coroutines the loop steps |
//! | [`memory`] | the `agent.memory.*` binding to the conversation log |
//! | [`usage`] | `agent.llm.usage`, the read-only snapshot of the last request's token counts |
//! | [`turn`] | `agent.api.turn` and its poll/close: one model request as a polled stream |
//! | [`mcp`](crate::mcp) | the JSON and HTTP/SSE text boundary (implemented outside this tree) |
//!
//! The tests live in [`tests`], split by the *shipped Lua surface* they exercise
//! rather than by the module above, because almost all of them build a real VM,
//! load the real tree, and drive it end to end.
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

mod bridge;
mod config;
mod history;
mod memory;
mod run;
mod sandbox;
mod tree;
mod turn;
mod usage;
mod vm;

#[cfg(test)]
mod tests;

pub use config::{
    ConfigOrigin, ConfigSource, LlmConfig, McpToolDef, SEED_MARKER, apply_config_source,
    ensure_config, invoke_mcp_tool, invoke_mcp_tool_with_asks, invoke_tool, invoke_tool_asking,
    llm_config, load_config_file, mcps_tool_defs, system_prompt, verdict_to_lua,
};
pub use history::seed_history;
pub use memory::{
    MemoryConfig, bind_memory, memory_append, memory_append_many, memory_config, memory_flush,
    memory_is_bound, memory_latest, memory_path,
};
pub use run::{
    AgentCommand, EventRun, EventStep, InputOp, ToolRun, ToolStep, bind_trigger_channel,
    fire_event_on_vm, fire_event_returning,
};
pub use turn::{TurnReply, round_results_reply, stopped_reply, turn_from_lua, turn_reply_from_lua};
pub use usage::{Usage, record_usage};
pub use vm::{
    AskAnswer, AskHandler, clear_sink, install_sink, new_agent_vm, new_vm, new_vm_with_ask,
    new_vm_with_sink, setup,
};

/// `eval_reactor` is test-only: it exists so a test can drive a chunk that
/// suspends on `agent.on_timeout` without a loop to answer it. Re-exported so
/// `mcp`'s own tests can reach it through the namespace.
#[cfg(test)]
pub(crate) use vm::eval_reactor;
