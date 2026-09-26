-- The Lua entry point: the last thing the loader runs on every VM, after the
-- Rust `agent` namespace, then every `lua/lib/*.lua` module (each required and
-- cached in `package.loaded`). It is the only top-level script the loader
-- executes — everything else is a module reached through `require()`.
--
-- `require("api")` is the annotation file for the locked `agent.api` bridge
-- (the Rust primitives everything is built on). Publishing it as
-- `agent.api_docs` is also what the loader checks against the real bridge:
-- a primitive without an annotation, or an annotation for a primitive that no
-- longer exists, is a startup error.
--
-- The agent namespace itself comes from `lua/lib/`, all of it auto-required
-- before this script runs: `agent.bash` (bash.lua), `agent.panel`
-- (panel.lua), `agent.http` (http.lua), `agent.mcp` (mcp.lua), `agent.ask`
-- (ask.lua), `agent.seccomp` (seccomp.lua), `agent.utils` (utils.lua),
-- `agent.on_timeout` (on_timeout.lua). This script only adds the configuration
-- layer on top: the defaults, the event and memory hooks. (The
-- read-only `agent.llm.usage` counters are the bridge's, not this script's — Rust
-- writes them after every request.)
--
-- There is deliberately no `agent.policy` namespace here. A policy is a plain
-- table of syscall name -> callback, passed per call to `agent.bash`; the
-- syscall-name keys are the interception mask. So each caller states the
-- policy it wants, in its own closure, next to the code it applies to — the
-- shipped shell does this the same way (`lua/policy.lua`, behind
-- `lua/bash_tool.lua`), as do the shipped file tools (`lua/fs.lua`) and any
-- tool of your own.
--
agent.api_docs = require("api")

-- The agent's configuration lives in Lua (a user ./agent.lua, loaded after
-- this script) in one table, `agent.llm`:
--   1. the endpoint (formerly AGENT_BASE_URL / AGENT_MODEL / AGENT_API_KEY):
--      base_url, model, api_key;
--   2. the system prompt: system_prompt, the leading `system` message;
--   3. where and whether the conversation log opens: memory = { enabled, path };
--   4. context_size — the model's context window in tokens, which only you know
--      (llama.cpp's `-c` / `--ctx-size`, a server's model page). `nil` — the
--      default — turns the automatic compaction turn off; see the handler at the
--      bottom of this file.
--
-- `agent.llm.usage` is a fifth, and the odd one out: it is not configuration but
-- the read-only cost of the *last* request, written by Rust after every turn and
-- raising if you assign to it.
--
--   agent.llm.usage.total       -- prompt + completion of the last request
--   agent.llm.usage.prompt      -- its prompt half (the context it was sent)
--   agent.llm.usage.completion  -- what the model wrote back
--   agent.llm.usage.reported    -- false when the server reported neither
--
-- It describes the request rather than the agent's capabilities, which is why it
-- sits beside `agent.llm` and not with `agent.mcps`. It is also the automatic
-- compaction's fuel: the *current* context size, so a handler can watch it and
-- compact before the next turn gets expensive. It is not cumulative — a
-- compaction shrinks what the next turn reports — and it is read at call time,
-- because a fresh VM (a `turn_completed` handler) is seeded with the count as of
-- its own creation.
-- The *tools* are not set here either. They are the entries in `agent.mcps`,
-- which Rust reindexes per request and never caches, so an edit to the config
-- applies to the very next request. Neither is `agent.llm.usage`, the
-- read-only token counts of the last request, which Rust owns and writes.
--
-- ---------------------------------------------------------------------------
-- The registry: `agent.mcps`, and how a tool is written
-- ---------------------------------------------------------------------------
--
-- There is no built-in catalog. Not the file tools, not the shell: everything
-- the model can be offered is a line in your config, and the ones you do not
-- register do not exist.
--
-- A *connection* is a table of tools, `{ name = "...", tools = { … } }`, keyed
-- in the registry by its own name:
--
--   agent.mcps.fs = require("fs")     -- read_file, list_dir, write_file, apply_patch
--   agent.mcps.bash = require("bash_tool")
--
-- Each of those is one `require` of a module that returns a connection — exactly
-- what `agent.mcp` produces for an MCP server you run elsewhere, and the same
-- shape, so nothing downstream knows the difference. `require("mcps")` is the
-- whole shipped set as one registry, if a mode or a config wants it by name.
--
-- A tool of your own is `agent.utils.tool` (`lua/lib/utils.lua`), which wraps a
-- description, a JSON schema and a callback into the callable object the
-- registry holds:
--
--   conn.tools.sum = agent.utils.tool("Add two numbers.", {
--     type = "object",
--     properties = { a = { type = "number" }, b = { type = "number" } },
--     required = { "a", "b" },
--   }, function(args)
--     return { ok = true, result = { total = args.a + args.b } }
--   end)
--
-- The callback's return is the MCP shape: `{ ok = true, result = … }` on
-- success, `{ ok = false, error = "…" }` on failure, or a bare `false` to deny
-- (which reads as `{ ok = false, denied = true }` to the model).
--
-- The `lua/` tree is on the module search path, so a module is required by its
-- bare name from anywhere: `require("utils")` is `lua/lib/utils.lua`,
-- `require("fs")` is `lua/fs.lua`. A `lua/lib/` module also publishes itself on
-- `agent` (`agent.utils`, `agent.seccomp`, `agent.ask`, …), so a sibling can
-- reach it without requiring it again.
--
-- A sandboxed tool is built the same way, around `agent.bash(cmdline, policy)`
-- — see the note below on what a policy is. The shipped shell is
-- `lua/bash_tool.lua`; what it is allowed to do is `lua/policy.lua`, and the
-- shipped *file* tools take the other road entirely: they do no shelling out and
-- simply ask, so what they may touch is decided by your answer.
--
-- ---------------------------------------------------------------------------
-- Modes: a prompt and a tool set, switched as a pair
-- ---------------------------------------------------------------------------
--
-- `agent.mode.new(name, spec)` registers one; `agent.mode.set(name)` switches to
-- it, overwriting exactly two live values — `agent.llm.system_prompt` and
-- `agent.mcps`. Rust re-reads both per request, so the next turn already runs in
-- the new mode. A spec leaves one out to clear it (no prompt, or no tools), and
-- `agent.mode.set()` with no argument puts your configured prompt and registry
-- back.
--
--   agent.mode.new("careful", {
--     description   = "reads only",              -- for a picker, optional
--     system_prompt = "You are in read-only mode. Explain, do not edit.",
--     mcps          = { fs = require("fs") },
--   })
--   agent.mode.set("careful")
--
-- The connections are shared, not copied, so a mode can also *narrow* one by
-- holding a subset of its tools:
--
--   local fs = require("fs")
--   agent.mode.new("reads_only", { mcps = { fs = {
--     name = "fs",
--     tools = { read_file = fs.tools.read_file, list_dir = fs.tools.list_dir },
--   } } })
--
-- A tool the mode does not expose is not advertised to the model *and* cannot be
-- invoked at all — the loop refuses any name the request did not offer
-- (`main::may_run`). A sandbox policy is not part of this: it is a local table
-- written at the `agent.bash` call site, so a `bash` tool that wants one per
-- mode reads `agent.mode.current()` in its own callback.
--
-- `mcps = "all"` is the fourth option, and the only one that is not a set: it
-- leaves the registry in force and swaps the prompt alone, read at switch time so
-- it cannot go stale against a config that adds a connection later.
--
-- Two ship: `coding` (`lua/coding.lua`, the working mode — the tool set named, and
-- a prompt about working in this repository) and `compact` (`lua/compact.lua`,
-- its opposite — an *empty* connection set, so a compaction turn has no tools at
-- all and can only answer). A mode does not rewrite the history; `lua/compact.lua`
-- says what still has to answer for that.
--
-- Re-running the config (`/reload`) replaces a mode's spec rather than
-- duplicating it, and leaves the active mode active: its new spec is re-applied
-- at once. Register modes *after* `agent.mcps` is populated, and switch there too
-- — a switch captures the registry in force as the baseline to restore, so one
-- taken before the connections exist would restore an empty tool set.
--
-- ---------------------------------------------------------------------------
-- Trust: what the agent stops asking about
-- ---------------------------------------------------------------------------
--
-- A command opens the same file over and over, so `agent.ask` keeps tables of
-- paths and servers you have vouched for and answers the rest itself:
--
--   agent.ask.trust("~/src/vendor")          -- may be here at all
--   agent.ask.trust_write("/tmp/scratch")    -- and may write here
--   agent.ask.is_trusted("src/vendor/x/y")   -- true (the general table)
--   agent.ask.is_write_trusted("x")          -- true only if write-trusted
--   agent.ask.forget_write("/tmp/scratch")   -- "may write" goes, "may read" stays
--   agent.ask.forget("config/app.toml")      -- ask again (both tables)
--
--   agent.ask.trust_server("api.internal")   -- any port on that host
--   agent.ask.trust_server("db.internal", 5432)
--   agent.ask.is_server_trusted("db.internal", 5432)
--   agent.ask.forget_server("db.internal", 5432)
--
-- `trust_write` records in *both* path tables — writing implies being allowed to
-- touch — so each reader reads exactly one: `is_trusted` asks "trusted at all?",
-- `is_write_trusted` asks "writable?". That is what makes `forget_write` a narrow
-- revocation rather than a duplicate of `forget`.
--
-- Resolution is textual and cheap (stdlib only, no subprocess): `~` expands, a
-- relative path is made absolute against the working directory, and `.` / `..`
-- are tidied. A directory is matched as a subtree on a `/` boundary, so trusting
-- `src` does not trust `srcfoo`. Servers are keyed by the name the question
-- showed, which for a loopback address is `localhost` and otherwise the literal
-- address unless it has a PTR.
--
-- Trusting is also something an *answer* can do. A question that carries a path
-- or an endpoint is put with `[a]lways` on offer, so the prompt reads
-- `[y]es  [n]o  [a]lways` and choosing `a` records it. A plain `[y]es` is for
-- that one time and is forgotten; a question with nothing to remember is asked as
-- `[y]es  [n]o` only. Two helpers do the whole decision in one call — trusted
-- already, else ask, and remember *only* on "always":
--
--   agent.ask.ask_trust_read("config/app.toml", "read the app config?")
--   agent.ask.ask_trust_write("/tmp/scratch", "write scratch files here?")
--   agent.ask.ask_server("db.internal", 5432, "connect to the database?")
--
-- The write one is the narrower question, so a path trusted for reading is still
-- asked about before it is written. The tables live on the agent's own VM and a
-- tool call runs on that VM, so a grant outlives the call that made it; they do
-- not outlive the process, and `/reload` does not clear them.
--
-- The working directory is trusted at startup, further down in this file, and a
-- run with no ask handler — headless, the tests, the probe — denies every ask, so
-- a sandboxed run there reaches nothing it was not already trusted for.
-- The defaults, created once. The endpoint was the AGENT_BASE_URL / AGENT_MODEL
-- / AGENT_API_KEY environment variables before it was configuration; the
-- environment still overrides it (see `api::ChatConfig`), but Lua is where you
-- set it.
--
-- A config assigns *fields* of this table, never the table itself: it is created
-- here with a default for everything, so replacing it wholesale would drop the
-- keys you did not mention — `memory` and `usage` in particular, which nothing
-- else puts back.
agent.llm = agent.llm or {
  base_url = "https://api.openai.com/v1",
  model    = "gpt-4o-mini",
  api_key  = "",   -- empty: requests lack an Authorization header
}

-- The system prompt: the leading `system` message of every request, and `""`
-- sends none. Long-form text is written with a Lua long string, as in
-- `agent.lua`.
--
-- It is one of the two primitives you steer the agent with, and the halves are
-- different in kind: the prompt says what it should *do*, the policy tables say
-- what it *may* do. Anything more elaborate — presets, per-project personas,
-- whatever layer you want on top — is yours to build in Lua, because this is
-- just a string the next request reads.
agent.llm.system_prompt = agent.llm.system_prompt or ""

-- Shell single-quote helper for building agent.bash cmdlines.
function agent.shq(s)
  if type(s) ~= "string" then return "''" end
  return "'" .. s:gsub("'", "'\\''") .. "'"
end

-- A sandbox policy is *not* ambient state, and there is no builder to call
-- here: a tool that shells out writes the policy it wants at the call site —
--
--   local out = agent.bash("cat -n -- " .. agent.shq(path), policy, nil):run()
--
-- where `policy` is a local in the same file, a table mapping syscall names to
-- callbacks. Only the named syscalls are trapped and decided; anything left
-- out is not intercepted at all, so it runs straight through the kernel
-- (default allow) without reaching a callback. An empty table `{}` therefore
-- traps nothing, and naming a syscall — `openat`, say — is what puts a floor
-- under it. `agent.seccomp` does the flag reading (`arg`, `check`, `describes`)
-- so a policy is declarations, not bit arithmetic.

-- Event hooks: how Lua hears that a turn finished and can react. Register
-- handlers at agent.lua top level — `agent.on_event("turn_completed", fn)`.
-- When a full user turn completes (final answer, or the tool-round limit),
-- Rust fires the event with one argument:
--
--   { history = { ...the conversation messages... } }
--
-- the in-memory history the loop just finished — this is the **read** side
-- of compaction. To compact, summarize it (agent.http to the same LLM, or a
-- trigger with the summary as a user message), rebuild a short history
-- (summary message + recent tail), and hand it back to the loop:
--
--   agent.trigger({ { role = "system", content = summary }, ...tail })
--
-- which replaces the history (the **write** side) and immediately runs the
-- next inference. Only "turn_completed" fires today; unknown event names are
-- accepted but never fired.
--
-- Composing the two is compaction, and there is one trap in it: every triggered
-- turn also ends, so a handler that compacts unconditionally re-triggers itself
-- forever. Stop when the history is short enough — which is what the automatic
-- handler at the bottom of this file does with a `state` flag:
--
--   agent.on_event("turn_completed", function(info)
--     if #info.history <= 24 then return end
--     -- ... summarize the old part (agent.http against the same LLM) and hand
--     -- back a summary system message plus the recent tail:
--     agent.trigger({ { role = "system", content = summary }, unpack(tail) })
--   end)
agent._events = agent._events or {}

function agent.on_event(name, fn)
  if type(name) ~= "string" then error("agent.on_event: name must be a string", 2) end
  if type(fn) ~= "function" then error("agent.on_event: handler must be a function", 2) end
  agent._events[name] = fn
end

-- Force the agent loop to run a new inference. No argument: a continuation of
-- the current conversation. A string: behaves like a submitted user message.
-- An array of message tables: replaces the in-memory history, then runs.
-- Returns true when queued; false when no loop is attached (the headless
-- probe) — check it if your handler must not silently drop.
function agent.trigger(...)
  local ok, err = agent.api.trigger(...)
  if err then error(err, 2) end
  return ok
end

-- Conversation persistence: the agent loop archives every message to an
-- append-only, block-compressed log on disk through `crate::memory`
-- (`agent::lua`), shared behind a mutex. Configure where and whether:
--
--   agent.llm.memory = {
--     enabled = true,                    -- false: nothing opens, the loop saves
--                                        --   nothing, agent.memory actions raise
--     path    = "/abs/path/history.amem",-- default ~/.config/agent/history.amem
--   }
--
-- The loop writes automatically — each message exactly once (a watermark),
-- flushed at turn boundaries and on exit — so no handler is needed to get
-- saving. Lua can also reach the same store:
--
--   local seq = agent.memory.append({ role = "user", content = "hi" }) -- or a JSON string
--   local recent = agent.memory.latest(5)  -- newest 5 messages, JSON strings
--   agent.memory.flush()                   -- seal buffered messages now
--   print(agent.memory.path())             -- nil when no log is open
--
-- The log is a raw append-only transcript: compaction replaces only the
-- *in-memory* history, never what was archived. enabled / path are startup
-- decisions — editing them needs a restart, like the trigger channel.
-- The log is a raw append-only transcript: compaction replaces only the
-- *in-memory* history, never what was archived. The loop saves by itself — each
-- message exactly once, by a watermark, flushed at turn boundaries and on exit —
-- so nothing here has to be written to keep it. `enabled` / `path` are startup
-- decisions: editing them needs a restart, like the trigger channel.
agent.llm.memory = agent.llm.memory or {}

-- The conversation log reachable from Lua: `append` (a JSON string or a
-- table; returns the message sequence), `latest(n)` (newest n messages as
-- JSON strings), `flush()` (seal buffered messages now — harmless when
-- nothing is open), and `path()` (nil when nothing is open, so it is
-- informational). `append` / `latest` raise "no log open" when
-- `enabled = false` or nothing is bound.
agent.memory = agent.memory or {}
function agent.memory.append(message)
  return agent.api.memory_append(message)
end
function agent.memory.latest(n)
  return agent.api.memory_latest(n)
end
function agent.memory.flush()
  return agent.api.memory_flush()
end
function agent.memory.path()
  return agent.api.memory_path()
end

-- ==========================================================================
-- The working directory is trusted
-- ==========================================================================
--
-- A permission question is only worth asking when the answer is a decision the
-- user would want to make. "May the agent read the project it was pointed at"
-- is not that question — it is the premise of the session — so the working
-- directory is trusted outright here, once, at startup: reads and writes inside
-- it are silent, and `agent.ask`'s own questions stay free for everything else.
--
-- It is trusted as a *directory*, which is what covers its whole subtree, so a
-- file created later under it needs no second grant. Everything outside it is
-- asked about, every time, until an "always" remembers it.
--
-- Trusting the cwd is a grant and a real one: it includes every file in your
-- project, including the ones you would not want an agent to read. Move the
-- agent somewhere disposable, or narrow it, if that is not the arrangement you
-- want — this line is the whole policy, and deleting it asks about everything.
--
-- `$PWD` is the same source `agent.ask` resolves relative paths against, so a
-- relative path and an absolute one land on the same entry. A shell that has
-- been `cd`ed out from under the agent will disagree with it; that is the one
-- case where the trust is not where you think, and it fails *toward* asking.
do
  local cwd = os.getenv("PWD")
  if type(cwd) == "string" and cwd ~= "" then
    agent.ask.trust(cwd)
  end
end

-- ==========================================================================
-- Automatic compaction
--
-- When the conversation grows until less than COMPACT_HEADROOM tokens are left
-- in the context window, this handler runs a compaction turn and puts the
-- history back in shape. It is three steps of state, kept in `agent._compaction`
-- (a table on `agent`, so it survives from one event to the next — the handler
-- runs as a coroutine on the config VM, and the VM outlives each turn):
--
--   idle     nothing is pending. Check the headroom; if it is thin, arm.
--   armed   the compaction turn is running (or about to). The next event
--           carries its summary, which becomes the new history.
--
-- Arming also records how long the conversation was at that moment
-- (`state.mark`), which is where the new history is cut: the summary replaces
-- everything up to that point, and only the recent tail is carried over. The
-- boundary is a *count taken when arming*, not the position of the summary —
-- the tail must stop before the compaction turn itself, or the summary would
-- end up in the new history twice.
--
-- A turn's own completion fires this handler too, so the arming step must not
-- re-arm: that is what the state is for. The check alone is not enough — the
-- compaction turn's *own* request carries the whole history, so its
-- `usage.prompt` is just as large as the one that triggered it.
--
-- Off unless `agent.llm.context_size` is a number: with no window to measure
-- against, there is no headroom to speak of, and guessing a window would
-- compact at the wrong moment. Set it to your server's context size (llama.cpp:
-- `-c` / `--ctx-size`; an API: the model card).
-- ==========================================================================

-- How much window must be left for the conversation to be left alone. Below
-- this, compact. Big enough to finish the current task, small enough that the
-- compaction turn itself still fits.
local COMPACT_HEADROOM = 15000
-- Verbatim messages kept after the summary: the recent exchange, so the model
-- does not have to re-derive the immediate context from prose.
local COMPACT_KEEP = 6
-- The turn that asks for the summary. Sent as a user message, so it reads as a
-- request rather than a system instruction; the compact mode's prompt is what
-- shapes the answer.
local COMPACT_ASK = "Compact the conversation now: write the handoff summary."

agent._compaction = agent._compaction or { state = "idle" }

-- The last assistant message, or nil: the compaction turn's summary lands there.
local function last_assistant(history)
  for i = #history, 1, -1 do
    if history[i].role == "assistant" then
      local content = history[i].content
      if type(content) == "string" and content ~= "" then return content end
    end
  end
  return nil
end

agent.on_event("turn_completed", function(info)
  local state = agent._compaction
  local history = (type(info) == "table" and type(info.history) == "table")
      and info.history or {}

  -- Step 2: the compaction turn finished. Its summary replaces everything
  -- before the recent tail, and the mode that was in force comes back — both
  -- *before* the trigger, so the turn this starts runs in it.
  if state.state == "armed" then
    local mark = state.mark or #history
    state.state = "idle"
    state.mark = nil
    agent.mode.set(state.mode)
    state.mode = nil
    local summary = last_assistant(history)
    if summary == nil then
      -- No summary to land (an empty answer, or a turn that never ran). The
      -- mode is already back and nothing was dropped, so the conversation just
      -- carries on.
      return
    end
    -- The recent tail, verbatim: the last COMPACT_KEEP messages from *before*
    -- the compaction turn, so the model does not have to re-derive the
    -- immediate context from prose.
    local keep = {}
    for i = math.max(1, mark - COMPACT_KEEP + 1), mark do
      keep[#keep + 1] = history[i]
    end
    -- A replacement history is a new inference: the model picks the work back
    -- up from the summary. A `false` here means no loop is listening (the
    -- probe, a test) — a degraded but safe state: the mode is already back and
    -- the transcript still holds everything, summary included.
    agent.trigger({ { role = "system", content = summary }, unpack(keep) })
    return
  end

  -- Step 1: is there room left? `usage.prompt` is what the last request carried,
  -- which is the conversation as this turn left it — the next one is a little
  -- bigger, so the headroom is a slight over-estimate. That is the safe
  -- direction: compaction runs a turn early rather than a turn late.
  local window = tonumber(agent.llm.context_size)
  if not window or window <= 0 then return end   -- not configured: off
  local used = tonumber(agent.llm.usage.prompt) or 0
  if window - used >= COMPACT_HEADROOM then return end

  state.state = "armed"
  state.mark = #history               -- where the new history is cut
  state.mode = agent.mode.current()   -- nil means "the baseline", which set() restores
  agent.mode.set("compact")
  if not agent.trigger(COMPACT_ASK) then
    -- No loop to drive: undo rather than leave the agent stuck in compact mode
    -- with nothing running.
    agent.mode.set(state.mode)
    state.mode = nil
    state.mark = nil
    state.state = "idle"
  end
end)

-- The shipped modes are registered by the *config* (`agent.lua`), not here: a
-- mode is a user-facing choice, and switching to one captures the registry in
-- force as the baseline to restore. Doing that from the entry script would
-- capture it before the config had registered a single connection — so the
-- baseline would be empty, and `agent.mode.set()` (back to the baseline) would
-- quietly leave the agent with no tools at all. Registration and activation both
-- belong after `agent.mcps` is populated.
