-- ===========================================================================
-- YOUR CONFIGURATION
-- ===========================================================================
--
-- This file is `~/.config/agent/init.lua`, and it is *yours*. On the first run
-- the agent copied the built-in defaults here; from now on this copy is what
-- configures it. Edit it, and press `/reload` in the TUI to apply without a
-- restart. Delete it and the next run re-seeds it from whatever ships next.
--
-- Two things worth knowing before you change anything:
--
--   * It is the WHOLE configuration. Nothing runs underneath it. Whatever this
--     file does not set up, the agent does not have — which is why the tables
--     below are created with defaults rather than left to chance.
--   * The parts you will actually want to change are marked `>>>` below. The
--     prose around each one is the documentation for that setting; the sections
--     further down explain how the moving parts fit together, and you can ignore
--     all of it until you need it.
--
-- Run `agent` once with no config to have this file created for you, then come
-- back to it. The loader prints which of the two happened.
--
-- ===========================================================================
-- 1. THE ENDPOINT  — the first thing most people change
-- ===========================================================================
--
--   base_url    where the chat-completions API lives
--   model       the model name your server knows it by
--   api_key     sent as `Authorization: Bearer …`; empty means no header
--
-- There is deliberately no environment override for these: the endpoint is
-- configuration, not an environment variable, because a file you can read back
-- is worth more than a shell line that changes what the agent talks to without
-- a trace. (The headless probe is the one exception — it reads `AGENT_BASE_URL`,
-- `AGENT_MODEL` and `AGENT_API_KEY` when any one of them is set, so an existing
-- scripted invocation keeps working. The TUI does not.)
--
-- So: the three lines below are the whole of it.
-- `agent.llm` is a **convention**: a plain table this file declares, which Rust
-- reads and never creates or reshapes. The `or {}` is what makes a *short* config
-- work — a file that sets one field needs no boilerplate, and a key left out falls
-- back to the default (`llm_config`). Assigning fields rather than the table is
-- also what keeps a user's override from throwing away a field this file set: a
-- whole-table assignment is a replacement, not a merge.
--
-- The same convention as `agent.mcps` further down.
agent.llm      = agent.llm      or {}
agent.llm.base_url = "https://api.openai.com/v1"  -- >>> the API endpoint
agent.llm.model    = "gpt-4o-mini"                -- >>> the model
agent.llm.api_key  = ""                           -- >>> "" sends no Authorization header

-- >>> SYSTEM PROMPT — what the model is told it is for.
--
-- The leading `system` message of every request; `""` sends none. This and the
-- sandbox policy are the two halves of steering the agent, and they are
-- different in kind: the prompt says what it should *do*, the policy says what
-- it *may* do. Anything more elaborate — presets, per-project personas, whatever
-- layer you want — is yours to build, because this is just a string the next
-- request reads. Lua long strings (`[[ … ]]`) keep long prompts readable.
agent.llm.system_prompt = agent.llm.system_prompt or ""

-- ===========================================================================
-- 2. THE CONTEXT WINDOW  — turns automatic compaction on
-- ===========================================================================
--
-- >>> CONTEXT SIZE — your model's window, in tokens.
--
-- This is the one setting that is off by default, and nothing works without it:
-- the automatic compaction at the bottom of this file measures how full the
-- window is against this number, and with no number there is no headroom to
-- measure and compaction stays off. Fill in what your server actually has —
-- llama.cpp: the `-c` / `--ctx-size` you started it with; an API: the model
-- card — and long conversations start compacting themselves before they fail.
--
-- `false` (the default) means "not configured", which is different from 0.
agent.llm.context_size = agent.llm.context_size or false

-- ===========================================================================
-- 3. THE CONVERSATION LOG
-- ===========================================================================
--
-- The agent appends every message here, so the next session resumes where this
-- one stopped. A raw append-only transcript: compaction rewrites only the
-- *in-memory* history, never what was archived.
--
-- >>> enabled   false keeps no log at all. true uses the path below.
-- >>> path      where the log lives. The default is
--              `~/.config/agent/history.amem`; the folder and file are created
--              on demand.
--
-- `enabled` and `path` are startup decisions — `/reload` cannot move a log that
-- is already open — so changing them wants a restart.
agent.llm.memory = agent.llm.memory or {
  -- enabled = true,
  -- path    = os.getenv("HOME") .. "/.config/agent/history.amem",
}

-- The same log, from Lua: `agent.memory.append(msg)` (a JSON string or a table)
-- to add one, `agent.memory.latest(n)` for the newest n as JSON strings,
-- `agent.memory.flush()` to seal what is buffered now, and
-- `agent.memory.path()` for where it is. `append` and `latest` raise
-- "no log open" when the log is off — that is how you find out.
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
-- Start a fresh conversation log. The current one is flushed, closed and moved
-- aside (`<old>-<timestamp>.amem`), and a new file opens where it was. Each session
-- is its own archive: scrolling pages the new file from its start, and the old
-- session's history is still on disk next to it.
function agent.memory.new()
  return agent.api.memory_new()
end
function agent.memory.path()
  return agent.api.memory_path()
end

-- ===========================================================================
-- 4. TOOLS  — what the agent can do
-- ===========================================================================
--
-- Every tool the model may call is a *connection*, and `agent.mcps` is the whole
-- registry: nothing is built into the binary, and a tool nobody registers does
-- not exist. Each entry is `{ name = "...", tools = { … } }`.
--
-- The two below are the built-in ones. Comment one out to take that capability
-- away — there is no other switch.
agent.mcps = agent.mcps or {}
agent.mcps.fs   = require("fs")        -- >>> read, write_file, hand_to_user, apply_patch
agent.mcps.bash = require("bash_tool")  -- >>> the sandboxed shell

-- The shell runs `bash -c` under a seccomp filter (`lua/policy.lua`) that traps
-- `openat`, `unlinkat`, `renameat`/`renameat2`, `chmod`/`fchmodat`, the four
-- `*xattr` calls, `connect`, `bind` and `sendto` and *asks* about each one
-- rather than deciding — so `rm` asks, `mv` asks twice, and `chmod` and `setcap`
-- ask. Ask about something with `agent.ask.trust(path)` and it stops asking;
-- see §6.
--
-- --- Adding a tool of your own -------------------------------------------------
--
-- `agent.utils.tool(description, schema, callback)` builds one. It is the same
-- shape an MCP connection produces, so nothing else is special:
--
--   agent.mcps.mine = {
--     name = "mine",
--     tools = {
--       hello = agent.utils.tool("Say hello.", {
--         type = "object",
--         properties = { who = { type = "string", description = "who to greet" } },
--         required = { "who" },
--       }, function(args)
--         return { ok = true, result = "hello, " .. args.who }
--       end),
--     },
--   }
--
-- The model sees it as `mine.hello` — tools are advertised as
-- `{connection}.{tool}`, so two servers offering the same tool name do not
-- collide. The callback returns the MCP shape: `{ ok = true, result = … }`, or
-- `{ ok = false, error = "…" }`, or plain `false` to deny.
--
-- --- What the user sees is yours -----------------------------------------------
--
-- Calling `mine.hello` puts **nothing** in the transcript. Not the arguments,
-- not the result, not an error. The loop records the result for the model and
-- draws nothing at all, because a box of raw JSON arguments above a raw result
-- envelope is the loudest thing on screen and the least informative — and the
-- only tools that could have made it readable are the ones that now draw
-- themselves.
--
-- So a tool is in charge of its own reporting, which is also the only way it can
-- be formatted properly:
--
--   local p = agent.panel("greeting")     -- or agent.split_panel(title, opts)
--   p:append("hello, " .. args.who .. "\n")
--
-- There is no `close`: a panel is finished when you stop appending to it.
-- `lua/bash_tool.lua` is the worked example — a panel titled with the command,
-- with stdout appended as it arrives and a status line to finish it off.
-- `p:ask("…", true)` is the same idea for a question — the dialog appears
-- inside the tool's own panel, which is why it survives another panel being
-- drawn over it.
--
-- A tool that asks should ask on its own panel — `p:ask("…", true)`. A bare
-- `agent.ask` / `coroutine.yield` reaches the loop, which remembers that
-- something is outstanding so a key press can be read as a verdict, and draws
-- *nothing*: the agent sits waiting with the input line showing nothing about a
-- pending verdict, and `y` would answer something invisible. Every fs tool asks
-- this way, so every fs question is a dialog inside the box that raised it.
--
-- The rule this leaves you: a tool that wants to be seen draws itself, and a
-- tool that wants to be quiet is quiet. Both are legitimate. Note that *quiet*
-- is also what a failure looks like — if a tool can fail, it should say so in
-- its panel, because nothing else will.
--
-- --- An MCP server ------------------------------------------------------------
--
-- `agent.mcp(name, transport)` opens a real MCP connection, handshake and all;
-- `lua/lib/mcp.lua` has the protocol and the transport shapes. The result is a
-- connection like any other, so it goes in the same registry:
--
--   agent.mcps.github = agent.mcp("github", function(request) … end)
--
-- An MCP tool is the one kind that cannot report itself: its code is on the
-- other side of the wire, and nothing here runs while `tools/call` is in
-- flight. So `lua/lib/mcp.lua` draws for it — a panel titled
-- `{connection}.{tool}`, opened before the request so a slow call is visibly in
-- flight, holding the result's text blocks with `notifications/progress`
-- appended as they arrive, and a failure marked as one. It is the same panel a
-- local tool gets by asking for one, arrived at from the other direction.
--
-- To make an MCP call quiet instead — which a tool call will not do on its own
-- — opt the connection out:
--
--   agent.mcps.github = agent.mcp("github", transport, { draw = false })
--
-- That is exact: the request on the wire is byte for byte what it was.
--
-- --- A tool that shells out ---------------------------------------------------
--
-- `agent.bash(cmdline, policy)` is the sandboxed shell as a coroutine: a policy
-- is a plain table of syscall name -> callback, written as a local at the call
-- site (see `lua/policy.lua` and `lua/lib/bash.lua`), and
--
--   local out = agent.bash("cat -n -- " .. agent.shq(path), policy, nil):run()
--
-- is the whole call. `agent.shq` is the single-quote helper for building a
-- cmdline safely.

function agent.shq(s)
  if type(s) ~= "string" then return "''" end
  return "'" .. s:gsub("'", "'\\''") .. "'"
end
--
-- Only the syscalls a policy names are trapped; anything it leaves out runs
-- straight through the kernel without reaching a callback, so an empty table
-- `{}` traps nothing and naming one is what puts a floor under it.
-- `agent.seccomp` reads the flags, so a policy is declarations, not bit
-- arithmetic.

-- ===========================================================================
-- 5. MODES  — a prompt and a tool set, switched as a pair
-- ===========================================================================
--
-- A mode is what the agent is currently for. `agent.mode.set(name)` overwrites
-- `agent.llm.system_prompt` *and* `agent.mcps` together, and the next request
-- already runs in it — the two halves cannot drift apart.
--
-- Two are registered below. `coding` is the one in force; `compact` is the
-- restriction the automatic compaction switches into (§7), with no tools at
-- all, so a compaction turn can only answer.
--
-- >>> Comment one out to drop that mode, or add your own:
--
--   agent.mode.new("careful", {
--     system_prompt = "…",
--     mcps = { fs = agent.mcps.fs },   -- a subset is a narrower agent
--   })
--   agent.mode.set("careful")
--
-- The connections are shared, not copied, so a mode listing one of another's
-- tools narrows it. A tool a mode does not expose is neither advertised to the
-- model nor callable — that is checked at dispatch, not just in the tool list.
--
-- Order matters in one direction only: register modes *after* the connections
-- above, because switching captures the registry in force as the baseline to
-- restore, and a switch taken before the connections exist would restore an
-- empty tool set.
agent.mode.new("coding", require("coding"))
agent.mode.new("compact", require("compact"))
agent.mode.set("coding")   -- >>> the mode the agent starts in

-- ===========================================================================
-- 6. TRUST  — what the agent stops asking about
-- ===========================================================================
--
-- A permission question is only worth asking when the answer is a decision you
-- would want to make. Two kinds of answer are remembered, and both are yours to
-- set here rather than clicking through:
--
--   agent.ask.trust(path)       -- may read *and* write anything under it
--   agent.ask.trust_write(path)  -- may write, but not read what it cannot read
--   agent.ask.trust_readonly(p)  -- may only look; every write still asks
--   agent.ask.block(path)        -- may not touch this, whatever grants cover it
--
-- A path may be a file or a directory, and a directory covers its whole subtree.
-- Trust is a prefix, so `/usr/lib` covers everything under it.
--
-- `block` is the way back out, and it is what makes the two halves above
-- composable. A directory grant is permissive by construction, so trusting the
-- working directory trusts every file in it — `.env`, `.ssh`, a stray key — and
-- without a negative there is no way to take one back:
--
--   agent.ask.trust(cwd)              -- the project, quietly
--   agent.ask.block(cwd .. "/.env")   -- except this
--   agent.ask.block(cwd .. "/.git")   -- and this whole tree
--
-- A block is a *preference*, so it is not a one-way door: `agent.ask.trust` on
-- a path that carries a block of its own lifts the block and grants. Re-trusting
-- is the natural way to change your mind, and it needs no second mechanism.
--
-- Exact, though, and that word carries the weight. A block on a **directory** is
-- a statement about a whole tree, so naming something inside it does not lift
-- it — `block("/a")` then `trust("/a/b")` is refused, because the only way to
-- say "not in this tree" is to say it about the tree. Lift the directory block,
-- or grant the directory instead. `agent.ask.unblock(path)` lifts a block on
-- exactly that path too, and either way the enclosing grant was never revoked,
-- only stood in front of.
--
-- `forget(path)` reaches the same place: given a path with no grant of its own
-- but covered by a directory that has one, it blocks it rather than dropping
-- nothing. Calling it twice leaves nothing behind.
--
-- The block below trusts the working directory, which is the one grant that
-- makes a session bearable: "may the agent read the project it was pointed at"
-- is the premise of the session, not a question. Trusting the cwd is a real
-- grant — it includes every file in your project, including the ones you would
-- not want an agent to read — so delete it, or narrow it, if that is not the
-- arrangement you want. With it deleted, every read is asked about.
--
-- ## What else is worth trusting
--
-- A cold command asks once per shared library it loads and once per locale file
-- — dozens of questions before it does any work, which is how a user learns to
-- press `a` without reading. The system tree is granted **for reading only** —
-- so with `agent.ask.trust_readonly`, and *not* the plain `trust`:
--
--   agent.ask.trust_readonly("/lib")         -- -> /usr/lib on a merged-/usr system
--   agent.ask.trust_readonly("/usr")         -- libraries, binaries, locale, docs
--   agent.ask.trust_readonly("/etc/ld.so.cache")
--
-- `trust_readonly` is its own table rather than the general one. "You may look
-- here" and "you may make things here" are different promises, and the system
-- tree is only ever the first: a grant that let the agent quietly create a file
-- under `/usr` would not be a read-only grant at all. Keeping them apart is also
-- what lets a *working directory* stay a plain `trust` and keep creating
-- quietly, which is the point of a working directory.
--
-- So: every read under `/usr` and `/lib` is silent, and every write, create,
-- delete and move there still asks. `/etc/ld.so.cache` and `/proc/self/maps` earn
-- their lines for the same reason the tree does — the loader reads them on
-- *every* exec — and the rest of `/etc` and `/proc` stays a question, because
-- one file each is not a directory.
--
-- `/proc/filesystems` and `/proc/self/maps` are the kernel answering the two
-- questions the C library asks on every exec — "what filesystem types exist"
-- and "what is mapped". They were the last reads a cold command made that were
-- still questions. `/proc` is *not* granted as a tree: these two files are,
-- because a blanket grant there would be a grant for every other procfs file.
--
-- **`/etc/ld.so.preload` is deliberately not granted.** It is the file that
-- decides what gets loaded into every process, so trusting it would mean
-- trusting whatever it names, and the names are not the loader's business to
-- have on file. A program that needs it asked about will still be asked about.
--
-- A runtime under `$HOME` is the same kind of grant, and the reason this exists:
--
--   agent.ask.trust(os.getenv("HOME") .. "/.rustup/toolchains")
--
-- Everything else stays a question, and `always` on a question remembers it for
-- the rest of the process. `agent.ask.forget(path)` takes a grant back, and
-- `agent.ask.unblock(path)` takes a block back;
-- `agent.ask.trusted_paths()` lists them.
--
-- `$PWD` is the same source `agent.ask` resolves relative paths against, so a
-- relative path and an absolute one land on the same entry. A shell `cd`ed out
-- from under the agent will disagree with it, and that is the one case where
-- the trust is not where you think — it fails toward asking.
do
  local cwd = os.getenv("PWD")
  if type(cwd) == "string" and cwd ~= "" then
    agent.ask.trust(cwd)
  end
  -- What a dynamically-linked program reads before its first line of its own:
  -- the loader's cache, the loader's own map of the process, and every
  -- `DT_NEEDED` library and locale message it pulls from the system tree. Taken
  -- from a traced `/bin/echo`, not from a guess, and granted with
  -- `trust_readonly` so it is a promise to *look* — see the note above, and
  -- `agent.ask.trusted_readonly_paths()` for what these are.
  for _, ro in ipairs({
    "/lib", "/lib64",                       -- -> /usr/lib and /usr/lib64 here
    "/usr",                                 -- libraries, binaries, locale, docs
    "/etc/ld.so.cache",                     -- the loader's own cache
    "/proc/self/maps",                      -- read by the loader, every exec
    "/proc/filesystems",                    -- glibc lists fs types, every exec
  }) do
    agent.ask.trust_readonly(ro)
  end

  -- The `/dev` entries that carry nothing: no data, no persistence, no device
  -- behind them. A program that writes to `/dev/null` is the commonest redirect
  -- there is, and asking about it every time is noise of the worst kind —
  -- asked on a path that cannot be read back, cannot be listed, and cannot mean
  -- anything.
  for _, ro in ipairs({
    "/dev/null",     -- read: EOF, write: discarded
    "/dev/zero",     -- read: zeros
    "/dev/random",   -- read: entropy
    "/dev/urandom",  -- read: entropy, non-blocking
    "/dev/full",     -- read: zeros, write: always ENOSPC
  }) do
    agent.ask.trust_readonly(ro)
  end
  -- Write-trusted on its own: `/dev/null` is the one that is *meant* to be
  -- written to, and the redirect `> /dev/null` is the case worth never asking
  -- about. `/dev/zero` and `/dev/full` are left as questions — their writes are
  -- discarded and fail respectively, which is harmless but not what anyone means
  -- by "safe to write".
  agent.ask.trust_write("/dev/null")

  -- Deliberately **not** granted, and the line is here because "safe `/dev`"
  -- is not a self-defining set: `/dev/tty` and `/dev/pts/*` are your terminal,
  -- `/dev/console` writes to the console, `/dev/shm` is world-writable, and
  -- `/dev/sd*` and `/dev/nvme*` are the disks. Each stays a question.
end

-- ===========================================================================
-- 7. WHAT HAPPENS AT THE END OF A TURN
-- ===========================================================================
--
-- After a full user turn finishes, the agent fires one event, and this handler
-- is what receives it:
--
--   agent.on_event("turn_completed", function(info) … end)
--
-- `info.history` is the conversation the loop just finished — the **read** side
-- of compaction. To compact, summarize it (via `agent.http` against the same
-- endpoint, or a second model), rebuild a short history, and hand it back:
--
--   agent.trigger({ { role = "system", content = summary }, ...tail })
--
-- which replaces the history — the **write** side — and immediately runs the
-- next inference. Composing the two is compaction, and there is one trap in it:
-- every triggered turn also ends, so a handler that compacts unconditionally
-- re-triggers itself forever. Stop when the history is short enough, which is
-- what the automatic handler below does with a `state` flag.
--
-- Three events fire today, and they are not the same kind of thing.
--
--   "turn"            a request. Fired when the user submits a line, when a
--                     tool round needs the model again, and when
--                     `agent.trigger` forces an inference. The handler is
--                     given the conversation and drives one request; its
--                     return value *is* the assembled turn. The handler below
--                     (`agent.main_turn`, from lua/lib/main_turn.lua) is what
--                     runs every turn you watch. Unregister it and the loop
--                     falls back to driving the request itself.
--
--   "turn_completed"  a notification. The handler is told what happened and its
--                     return value is ignored. This section's own handler.
--
--   "key"             a question. The handler is given a key press and its
--                     return value *is* the answer — see §8.
--
-- Any other name is accepted and never called, so a typo registers a handler
-- that silently never runs.
agent._events = agent._events or {}

function agent.on_event(name, fn)
  if type(name) ~= "string" then error("agent.on_event: name must be a string", 2) end
  if type(fn) ~= "function" then error("agent.on_event: handler must be a function", 2) end
  agent._events[name] = fn
end

-- The main turn itself: every submitted line, every tool-round continuation and
-- every `agent.trigger` inference is driven by this handler — one request,
-- streamed into the transcript, the assembled turn handed back as the return
-- value. The mechanism is `agent.turn` (lua/lib/turn.lua); the drawing is two
-- borderless blocks, "reasoning" and "response". Replace this one line to run
-- the conversation your own way (a different prompt strategy, a router model,
-- several drafts judged and merged) — the loop only asks that a handler return
-- the assembled-turn table.
agent.on_event("turn", agent.main_turn)

-- Force the agent loop to run a new inference. No argument: a continuation of
-- the current conversation. A string: behaves like a submitted user message. An
-- array of message tables: replaces the in-memory history, then runs.
--
-- Returns true when queued; false when no loop is attached (the headless
-- probe) — check it if a handler must not silently drop, because a compaction
-- that never fires looks exactly like one that decided there was nothing to do.
function agent.trigger(...)
  local ok, err = agent.api.trigger(...)
  if err then error(err, 2) end
  return ok
end

-- --- the automatic compaction -------------------------------------------------
--
-- With §2's `context_size` set, this summarizes the conversation before the
-- window fills. Off otherwise, because with no window to measure against there
-- is no headroom to speak of and a guessed one would compact at the wrong moment.
--
-- >>> The three numbers below are the tuning.
local COMPACT_HEADROOM = 15000  -- tokens that must remain free; below this, compact
local COMPACT_KEEP     = 6      -- messages kept verbatim after the summary
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
  local window = tonumber(agent.llm.context_size)
  if not window then return end  -- no window configured: never compact

  -- Step 1: the conversation is close enough to the limit. Arm the compaction
  -- turn, remembering how long the conversation was *now* — that count is where
  -- the new history is cut, so the tail stops before the compaction turn itself
  -- and the summary cannot land in the new history twice.
  if state.state == "idle" then
    local used = tonumber(agent.llm.usage.prompt) or 0
    if used + COMPACT_HEADROOM < window then return end
    state.state, state.mark = "armed", #history
    state.mode = agent.mode.current()
    agent.mode.set("compact")
    agent.trigger(COMPACT_ASK)
    return
  end

  -- Step 2: the compaction turn finished. Its summary replaces everything
  -- before the recent tail, and the mode that was in force comes back — both
  -- *before* the trigger, so the turn this starts runs in it.
  --
  -- A turn's own completion fires this handler again, which is why the arming
  -- step above checks the state rather than re-arming: the check alone is not
  -- enough, because the compaction turn's own request carries the whole
  -- history, so its `usage.prompt` is as large as the one that triggered it.
  if state.state == "armed" then
    local mark = state.mark or #history
    state.state, state.mark = "idle", nil
    agent.mode.set(state.mode)
    state.mode = nil
    local summary = last_assistant(history)
    if summary == nil then
      return  -- nothing landed; leave the history alone
    end
    local keep = {}
    for i = math.max(1, mark - COMPACT_KEEP + 1), mark do
      keep[#keep + 1] = history[i]
    end
    agent.trigger({ { role = "system", content = summary }, unpack(keep) })
  end
end)

-- ===========================================================================
-- 8. KEYS — rebinding what a key press means
-- ===========================================================================
--
-- The "key" event is the whole keybinding mechanism. Rust owns the keys that
-- exist and the actions they can mean; you own the mapping between them.
--
--   agent.on_event("key", function(k) … end)
--
-- `k` is:
--
--   k.spec    the chord, as a table writes it — "alt+enter", "ctrl+c", "q",
--             "f5", "up". This is the string to match on.
--   k.char    the printable character, or nil for a named key.
--   k.ctrl, k.alt, k.shift    booleans, if you would rather test than match.
--
-- Return the name of an action and the agent does it; return nothing and the
-- key keeps its default meaning. A name is a shorthand, not the limit — see
-- "a binding can type" below. The actions are:
--
--   "newline"     insert a newline in the input line
--   "send"        submit the input line
--   "quit"        leave
--   "interrupt"   stop the running tool
--   "conceal"     toggle markup concealment
--   "scroll_up" / "scroll_down"    scroll the transcript one line
--   "page_up" / "page_down"        scroll the transcript one screen
--   "top" / "bottom"               jump to the start or end
--
-- So the smallest useful binding is a lookup:
--
--   local BIND = { ["ctrl+q"] = "quit", ["alt+j"] = "newline" }
--   agent.on_event("key", function(k) return BIND[k.spec] end)
--
-- Three things to know before you write one.
--
-- **A bare letter is a character first and a command second.** A letter reaches
-- the action only when the input line is empty; a chord — anything with a
-- modifier, or a named key — always does. This is the rule that makes a flat
-- table safe, and it lives in Rust (`App::key_may_act`) rather than here so that
-- every table gets it: without it, `BIND["q"] = "quit"` quits the app halfway
-- through the word "quick". A key the rule refuses is not swallowed — the letter
-- types instead.
--
-- **The keys that answer a permission question are not yours.** While a question
-- is on screen, `y`/`n`/`a` are verdicts, and the "key" event is not fired at
-- all. A binding table that could redirect those could answer a permission
-- question by accident. (`Ctrl+c` is the deliberate exception: it stops the
-- command that is asking, whose tree is frozen on that very question.)
--
-- **A typo is loud, not silent.** An action name that does not exist puts
-- `key binding: unknown action "conceall"; expected one of …` on the status
-- bar, and the key still does whatever it did before. Returning a number, or a
-- table, is the same kind of error. `nil` and `false` are the only "no opinion"
-- answers.
--
-- The bindings this config ships with. Rust keeps two keys for itself and no
-- more: `Ctrl+c` (stop the running command) and `Ctrl+d` (leave). Everything
-- below — including `Alt+Enter`, which used to be a Rust default — is yours to
-- change, delete or extend.
--
-- The rule that makes a flat table safe is in Rust, not here: **a bare letter
-- is a character first and a command second.** A letter only reaches the action
-- when the input line is empty — so `q` below quits an empty app and types a
-- `q` into a message — and a chord always does. That is why leaving is on
-- `Ctrl+d` and `Esc` as well as `q`, and why it would be a bug to add a bare
-- letter bound to something destructive without thinking about it.
local BIND = {
  ["alt+enter"] = "newline",   -- see below: a function, not a name
  ["enter"]    = "send",
  ["esc"]      = "quit",
  ["q"]        = "quit",         -- letters are gated on an empty input
  ["alt+c"]    = "conceal",
  ["j"]        = "scroll_down",
  ["down"]     = "scroll_down",
  ["k"]        = "scroll_up",
  ["up"]       = "scroll_up",
  ["home"]     = "top",
  ["end"]      = "bottom",
  ["pageup"]   = "page_up",
  ["pagedown"] = "page_down",
}

agent.on_event("key", function(k)
  local a = BIND[k.spec]
  -- "newline" is spelled as a call rather than a name because
  -- `agent.api.input_insert` can type anything, not just a newline: a chord
  -- bound to `input_insert("0")` inserts a zero mid-sentence, which is what a
  -- leader key is for. The named actions stay names because a name is the short
  -- way to say "quit", and a table of strings is easier to read than a table of
  -- closures.
  if a == "newline" then
    agent.api.input_insert("\n")
    return nil
  end
  return a
end)

-- ## A binding can type, not just choose
--
-- A handler is not restricted to the names above. `agent.api.input_insert(text)`
-- appends to the input line, and `input_backspace` / `input_clear` are its
-- mirrors — which is why `alt+enter` below is spelled as a call. A chord bound to
-- `input_insert("0")` types a zero mid-sentence, and that is the whole of what a
-- leader key is.
--
-- These are ungated, unlike a *binding*: the letter rule below governs which key
-- may mean a command, and by the time an edit is queued a command has already
-- been chosen. They return `false` when no loop is attached (headless, the
-- probe), so a binding can tell that its edit went nowhere rather than looking
-- like a key that does nothing.
--
-- Two things to know before you change the table.
--
-- **Rust binds two keys of its own**, whatever this table says: `Ctrl+c` (stop
-- the running command) and `Ctrl+d` (leave). Those two are about the agent
-- rather than about taste — `Ctrl+c` is the only way to
-- stop a tool, and `Ctrl+d` is on a key nothing else claims, so that stopping a
-- command and throwing away the session stay different gestures. This is why
-- leaving is `Ctrl+d` and not `Ctrl+c`, and why `Esc` below is a convenience
-- rather than the way out.
--
-- **A typo is loud, not silent.** An action name that does not exist puts
-- `key binding: unknown action "conceall"; expected one of …` on the status
-- bar, and the key still does whatever it did before. Returning a number, or a
-- table, is the same kind of error. `nil` and `false` are the only "no opinion"
-- answers.
--
-- **A key sequence is ten lines of Lua.** The handler is called on *every* key
-- press and can hold state, so a chord that starts on something untypable works
-- without any Rust support:
--
--   local armed = nil
--   agent.on_event("key", function(k)
--     if armed then
--       local chord = armed .. "+" .. k.spec
--       armed = nil
--       return BIND[chord] or BIND[k.spec]   -- degrade; never swallow the key
--     end
--     if k.spec == "ctrl+x" then armed = "ctrl+x"; return nil end
--     return BIND[k.spec]
--   end)
--
-- The `or BIND[k.spec]` is the part that matters: a chord that does not match
-- falls back to the second key's own meaning, so a sequence can never lose a
-- keystroke. Without it an armed prefix is a black hole and you would need a
-- visible pending state and a timeout — neither of which exists yet, so the
-- armed prefix is invisible. That is the whole of the caveat.
--
-- Note also that the hint under the input box is built from the two keys Rust
-- binds (`KEY_HELP` in `src/tui/mod.rs`), so nothing in `BIND` appears in it.
-- The agent cannot read this table's shape, and a hint that guessed at it would
-- be wrong more often than not.

-- ===========================================================================
-- 9. WHAT IS NOT IN THIS FILE
-- ===========================================================================
--
-- The rest of the Lua surface is library modules under `lua/lib/`, all
-- auto-required before this script runs and each published on `agent`. You
-- reach them through the names, and none of them need configuring:
--
--   agent.ask      the permission protocol and its trust tables   (ask.lua)
--   agent.bash     the sandboxed shell as a coroutine            (bash.lua)
--   agent.panel    result panels for tool output                  (panel.lua)
--   agent.mcp      the MCP client protocol                        (mcp.lua)
--   agent.http     one HTTP(S) interface, auto-routed            (http.lua)
--   agent.seccomp  reading flags and addresses for a policy      (seccomp.lua)
--   agent.utils    string/table helpers, and `agent.utils.tool`  (utils.lua)
--   agent.mode     the mode registry                              (mode.lua)
--   agent.on_timeout  suspend without blocking the loop          (on_timeout.lua)
--
-- Two conventions worth knowing, both from how the loader works:
--
--   * `require` a sibling rather than reaching for `agent.<name>` at load
--     time. The auto-require runs in alphabetical order, so a module that does
--     `local s = agent.seccomp` at its top level can get `nil` — the sibling it
--     wanted has not published itself yet. `local s = require("seccomp")` is
--     order-independent.
--   * `print` goes to the TUI's status bar, not stdout, because a TUI owns the
--     terminal. Headless it goes to stdout as usual. Either way it is one line:
--     for output meant to be read later, use a panel.
--
-- One more thing that is not in this file, because it is read before this file
-- is: `AGENT_LUA_DIR` names a *different* `lua/` tree to load, replacing the one
-- beside the executable. Since this tree is the whole control plane, pointing it
-- elsewhere is how you run a fork of the agent's behaviour without touching the
-- binary — and, in that arrangement, this file is not even read unless your own
-- tree has one.
--
-- To read further, the sources are the documentation — `lua/lib/*.lua` for the
-- surface above, `lua/policy.lua` for what the sandbox asks about, and
-- `README.md` for the design and its boundaries.
