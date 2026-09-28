---@meta
--
-- agent_api.meta.lua — Lua Language Server types for the locked `agent.api`
-- bridge, the Rust primitives every Lua module is built on.
--
-- `agent.api` is not a Lua file: Rust installs it as a **locked** table at VM
-- setup (`src/lua.rs`, `install_api`), and the loader refuses to start if its
-- contents and `lua/api.lua` disagree. So there is nothing for LuaLS to read
-- from the module itself, and every `agent.api.step(h)` in the tree is an
-- unknown global to a language server without this file. It is the type view of
-- the same 33 primitives, and it is a *view*: the authority is `lua/api.lua`,
-- which is prose the loader checks against the real bridge at startup.
--
-- Loading: `runtime.metaFiles` in `.luarc.json` names this file (and the
-- `.meta.lua` suffix means LuaLS also picks it up on its own). Nothing here
-- executes — it is declarations only, which is what `---@meta` means.
--
-- Conventions below:
--   * `agent.SandboxHandle` is the seccomp run's userdata; an HTTP/SSE handle is
--     a plain integer, because that is what the bridge returns (`i64`).
--   * A struct returned across the bridge is a Lua table, so it is declared as a
--     `---@class` and the functions returning it say so.
--   * Optional arguments are `?`, and an omitted optional is not `nil`-checked
--     for you: `agent.api.http_req` reads `headers` and `body` as nil-or-value,
--     so the annotation is as permissive as the bridge really is.
--   * `---@class agent.api` is a class *and* the table itself: LuaLS wants a
--     named type to hang the `agent.api` field on, and the class is that type.

-- ==========================================================================
-- The namespace
-- ==========================================================================

---@class agent
---@field api agent.api The locked Rust bridge. Assigning to it raises; every field is a primitive.
---@field api_docs table The annotations in `lua/api.lua`, as data.
---@field ask table Permission questions and the trust tables (`lua/lib/ask.lua`).
---@field allow fun(): boolean Allow a frozen syscall (`agent.allow()`).
---@field deny fun(reason?: string): table Deny one, with a reason (`agent.deny(reason)`).
---@field bash fun(cmdline: string, policy: table, opts?: table): table A sandboxed run (`lua/lib/bash.lua`).
---@field fs table The file-tool connection (`lua/fs.lua`).
---@field http table HTTP and SSE streams (`lua/lib/http.lua`).
---@field llm table Endpoint, prompt, context window, usage (`lua/init.lua`).
---@field mcp fun(name: string, func: function, opts?: table): table Open an MCP connection.
---@field mcps table<string, table> The connection registry: name -> `{ name, tools }`.
---@field memory table The conversation log (`lua/init.lua`).
---@field mode table Named prompt + tool-set pairs: new / set / current / get / names / forget (`lua/lib/mode.lua`).
---@field on_timeout fun(ms: integer, fn?: function) Suspend, or sleep off the reactor.
---@field panel fun(title: string, opts?: table): table A result panel (`lua/lib/panel.lua`).
---@field seccomp table Flag and endpoint reading (`lua/lib/seccomp.lua`).
---@field split_panel fun(title: string, panes: table[]): table A two-pane result panel.
---@field utils agent.utils String and table helpers, and the tool constructor (`lua/lib/utils.lua`).
---@field _events table<string, function> Registered event handlers.
---@field _compaction table The automatic-compaction state machine.
---@field __on_reactor boolean|nil Set by the driver: a coroutine on the event loop.
local agent

--- Rust installs `agent` as a real global, so declare it as one: the `local`
--- above exists only to hang the `---@field` annotations on, and this assignment
--- is what makes `agent.api.step(...)` resolve in every other file.
---@type agent
agent = agent or {}

-- ==========================================================================
-- `agent.utils` — the general-purpose helpers
-- ==========================================================================
--
-- Declared as a class rather than a bare `table` because it is a known shape:
-- three sections, and one of them (`tool`) is the constructor every connection
-- needs. The string and table sections are left as `table` on purpose — they are
-- a large surface that belongs to their own module, and annotating a handful of
-- it here would imply the rest was reviewed when it was not.

---@class agent.utils
---@field version string The library's own version.
---@field string table Text transformations — `snake_case`, `wrap`, `truncate`, `char_count`, … (`lua/lib/utils.lua`).
---@field table table List/table transformations — `get`, `set`, `pick`, `omit`, `group_by`, … (same file).
---@field tool fun(description: string, schema: table, callback: function): agent.Tool A callable tool object.
---@field _selftest fun(): boolean Runs the module's self-test; raises on failure.

-- ==========================================================================
-- Handles
-- ==========================================================================

---A sandboxed `bash -c` run: the userdata `agent.api.spawn` returns. Hand it to
---`step` / `decide` / `write` / `kill` / `close_stdin`.
---@class agent.SandboxHandle

---An HTTP request or SSE stream: the integer `http_req` / `sse_open` return.
---@alias agent.Transport integer

-- ==========================================================================
-- Verdicts
-- ==========================================================================

---What a question is answered with. A bare boolean is the common case; the
---tables carry the two things a boolean cannot: *why* a denial happened, and
---the "remember this" flag an `[a]lways` press produces.
---@alias agent.Verdict
---| boolean
---| agent.DenyVerdict
---| agent.AllowVerdict

---A refusal. `reason` is `nil` for a reasonless denial, which renders as a bare
---"Denied" rather than "Denied: ".
---@class agent.DenyVerdict
---@field __agent_verdict "deny"
---@field reason string?

---An allow that also asks to be remembered — the third answer. The asking side
---(which knows the path or endpoint) is what acts on `trust`.
---@class agent.AllowVerdict
---@field __agent_verdict "allow"
---@field trust true

-- ==========================================================================
-- A tool
-- ==========================================================================

---A callable tool object: what a connection's `tools` table holds, and what Rust
---reindexes into the catalog. `tool(args)` runs the callback and returns the
---MCP-shaped result — or `{ ok = false, denied = true }` when the callback
---returns `false`.
---@class agent.Tool
---@field description string What the model is told the tool does.
---@field signature table The JSON schema for its arguments.
---@field callback fun(args: table): table|boolean The implementation.

-- ==========================================================================
-- The sandbox
-- ==========================================================================

---What `step` reports. Discriminated on `kind`; `agent.bash`'s drive loop is
---written against exactly these four.
---@alias agent.StepEvent
---| agent.StepIdle
---| agent.StepOutput
---| agent.StepBlocked
---| agent.StepFinished

---Nothing was ready. On a reactor-driven coroutine the pump treats this as its
---cue to yield for a cadence, so the event loop stays live.
---@class agent.StepIdle
---@field kind "idle"

---A chunk of the tracee's stdout or stderr.
---@class agent.StepOutput
---@field kind "output"
---@field stream "stdout"|"stderr"
---@field data string

---A masked syscall is frozen pending a decision. `syscall` is the whole view the
---policy callback gets.
---@class agent.StepBlocked
---@field kind "blocked"
---@field syscall agent.Syscall

---The run is over, cleanly or not. A denied syscall ends the run by killing the
---tracee, so this is also how a refusal arrives.
---@class agent.StepFinished
---@field kind "finished"
---@field result agent.SandboxResult

---@class agent.SandboxResult
---@field stdout string
---@field stderr string
---@field exit { code: integer?, signal: integer? }
---@field syscalls integer
---@field denied integer
---@field denied_reason string? Only ever present via a policy's `agent.deny(reason)`.

---The intercepted syscall, as a policy callback receives it.
---@class agent.Syscall
---@field name string e.g. "openat", "connect"
---@field nr integer The syscall number.
---@field pid integer The caller's pid, for `/proc/<pid>/…` lookups.
---@field cmdline string The caller's argv joined with spaces; "" when unreadable.
---@field args table<integer, number> 1-based. A pointer arrives as a number — lossy for pointer-sized values.
---@field str table<integer, string> The C-string args, read out of the caller's memory and resolved against its cwd.
---@field addr table<integer, agent.Endpoint> The `struct sockaddr` each naming call takes, decoded. Empty for a call that names none.

---A named endpoint, decoded from a `struct sockaddr`.
---@class agent.Endpoint
---@field family "inet"|"inet6"|"unix"|"other"
---@field ip string? The literal address, for `inet` and `inet6`.
---@field port integer? Network byte order on the wire, host order here.
---@field path string? The socket path, for `unix`.

-- ==========================================================================
-- HTTP and SSE events
-- ==========================================================================

---@alias agent.HttpEvent
---| agent.HttpHeaders
---| agent.HttpChunk
---| agent.HttpDone
---| agent.HttpError

---@class agent.HttpHeaders
---@field kind "headers"
---@field status integer
---@field headers table<string, string>

---@class agent.HttpChunk
---@field kind "chunk"
---@field data string

---@class agent.HttpDone
---@field kind "done"

---A transport-level failure: unreachable host, timeout, and so on. `on_error`
---fires for these; a non-2xx status is not one.
---@class agent.HttpError
---@field kind "error"
---@field message string

---@alias agent.SseEvent
---| agent.SseMessage
---| agent.SseDone
---| agent.SseError

---@class agent.SseMessage
---@field kind "event"
---@field event string
---@field data string

---@class agent.SseDone
---@field kind "done"

---@class agent.SseError
---@field kind "error"
---@field message string

-- ==========================================================================
-- The bridge itself
-- ==========================================================================

---The locked Rust bridge. Every field is a primitive installed at VM setup; the
---table is a proxy, so reading an unknown name raises rather than returning nil.
---@class agent.api

-- -- the sandbox (lua/lib/bash.lua drives this) --------------------------------

---Start a sandboxed `bash -c`. `mask` is the syscall-name interception mask:
---only those are trapped, and anything unlisted runs straight through the kernel.
---An unknown name is an error, so a typo cannot silently trace nothing.
---@param cmdline string What bash runs (`bash -c <cmdline>`).
---@param mask string[]? Syscall names to intercept. `nil`/absent traps nothing but the always-on fork family.
---@return agent.SandboxHandle
function agent.api.spawn(cmdline, mask) end

---Advance the run by one step. Blocks in `poll` when off the reactor (the wait
---is here), and returns `idle` immediately on one.
---@param handle agent.SandboxHandle
---@return agent.StepEvent
function agent.api.step(handle) end

---Answer a frozen syscall. The whole policy is this call: `true` lets it run,
---`false` kills the tracee and ends the run.
---@param handle agent.SandboxHandle
---@param verdict boolean
function agent.api.decide(handle, verdict) end

---Kill the run now.
---@param handle agent.SandboxHandle
function agent.api.kill(handle) end

---Write to the tracee's stdin.
---@param handle agent.SandboxHandle
---@param data string
function agent.api.write(handle, data) end

---Close the tracee's stdin, so a command reading it sees EOF.
---@param handle agent.SandboxHandle
function agent.api.close_stdin(handle) end

-- -- the agent loop -------------------------------------------------------------

---Queue a forced inference. A string is treated as a submitted user message; a
---table replaces the history wholesale (the compaction write side). With no
---argument, it continues the current conversation. Returns whether it queued —
---`false` when no loop is bound to drain the command, which is the probe and the
---tests.
---@param args string|table|any
---@return boolean
function agent.api.trigger(args) end

---Put a question to the user and block for the answer. `always` is Lua's own
---flag and is what decides whether the prompt may offer `[a]lways`.
---
---With no handler bound — headless, the tests, the probe — this returns `false`,
---so an asking policy always terminates rather than hanging.
---@param text string The question, as shown.
---@param always boolean? Whether remembering the answer is on offer.
---@return agent.Verdict
function agent.api.ask_user(text, always) end

-- -- the conversation log ------------------------------------------------------

---Append a message to the open log. A string is stored verbatim; a table is
---stored as JSON. Raises when nothing is open.
---@param msg string|table
---@return integer The sequence number it was filed under.
function agent.api.memory_append(msg) end

---Seal everything buffered to disk now. Harmless when nothing is open.
---@return boolean
function agent.api.memory_flush() end

---The newest `n` messages as JSON strings, oldest first. Raises when nothing is open.
---@param n integer
---@return table
function agent.api.memory_latest(n) end

---Where the log is, or `nil` when nothing is open — informational either way.
---@return string?
function agent.api.memory_path() end

-- -- the JSON boundary ---------------------------------------------------------

---Encode a Lua value as JSON text.
---@param value any
---@return string
function agent.api.json_encode(value) end

---Decode JSON text into a Lua value. Non-finite numbers are an error rather than
---a silent `null`, because a NaN that becomes null is invisible later.
---@param text string
---@return any
function agent.api.json_decode(text) end

-- -- HTTP and SSE --------------------------------------------------------------

---Fire a request. The response is *polled*, never waited on: `headers`, then
---one or more `chunk`s, then `done` or `error`.
---@param method string
---@param url string Absolute.
---@param headers table<string, string>?
---@param body string?
---@param timeout_ms integer? Overall; 0 disables it.
---@return agent.Transport
function agent.api.http_req(method, url, headers, body, timeout_ms) end

---Poll for the next response event. `nil` when nothing has arrived; popping a
---terminal event unregisters the handle.
---@param handle agent.Transport
---@return agent.HttpEvent?
function agent.api.http_step(handle) end

---Drop a request handle. `true` when there was one.
---@param handle agent.Transport
---@return boolean
function agent.api.http_close(handle) end

---Open an event stream.
---@param url string
---@param headers table<string, string>?
---@return agent.Transport
function agent.api.sse_open(url, headers) end

---Poll for the next event. `nil` when nothing has arrived.
---@param handle agent.Transport
---@return agent.SseEvent?
function agent.api.sse_step(handle) end

---Close a stream. `true` when there was one.
---@param handle agent.Transport
---@return boolean
function agent.api.sse_close(handle) end

---The name for a literal address, or `nil` when it has none. A miss is normal and
---cheap, so a question can always fall back to showing the address alone.
---@param ip string
---@return string?
function agent.api.reverse_dns(ip) end

-- -- the cooperative wait ------------------------------------------------------

---Block the current Lua thread for `ms`. This is the *non-reactor* fallback for
---`agent.on_timeout`, which suspends instead when a driver is there to resume
---it. Reachable as `api.sleep`; prefer `agent.on_timeout` in portable code.
---@param ms integer
function agent.api.sleep(ms) end

-- -- panels --------------------------------------------------------------------
--
-- Ids come from the round's sink, so a Rust producer and a Lua one in the same
-- round cannot collide. Headless there is no sink and the ids only round-trip
-- through the handle's methods.

---Create a panel and return its id.
---@param title string
---@param opts { boxed: boolean?, conceal_box: boolean? }?
---@return integer
function agent.api.panel_create(title, opts) end

---Append to a panel.
---@param id integer
---@param text string
function agent.api.panel_append(id, text) end

---Replace a panel's whole contents.
---@param id integer
---@param text string
function agent.api.panel_set(id, text) end

---Tint a byte range, e.g. `"bold.red"`. Past the end of the text it is ignored.
---@param id integer
---@param start integer Byte offset, inclusive.
---@param finish integer Byte offset, exclusive.
---@param style string
function agent.api.panel_highlight(id, start, finish, style) end

---Drop every highlight.
---@param id integer
function agent.api.panel_clear_regions(id) end

---Set (`text`) or clear (`nil`) the overlay — the strip an ask is shown in.
---@param id integer
---@param text string? the question; nil clears the dialog
---@param always boolean? whether the answer is one to remember
function agent.api.panel_overlay(id, text, always) end

---Create a two-pane panel and return its id.
---@param title string
---@param panes (string|{ caption: string?, lang: string? })[] One entry per pane, in order.
---@return integer
function agent.api.panel_split(title, panes) end

---Set one pane's contents.
---@param id integer
---@param pane integer 1-based.
---@param text string
function agent.api.panel_pane_set(id, pane, text) end

---Set one pane's grammar; `nil` for plain text.
---@param id integer
---@param pane integer 1-based.
---@param lang string?
function agent.api.panel_pane_lang(id, pane, lang) end

---Tint a byte range in one pane.
---@param id integer
---@param pane integer 1-based.
---@param start integer Byte offset, inclusive.
---@param finish integer Byte offset, exclusive.
---@param style string
function agent.api.panel_pane_highlight(id, pane, start, finish, style) end

---Drop one pane's highlights.
---@param id integer
---@param pane integer 1-based.
function agent.api.panel_pane_clear_regions(id, pane) end
