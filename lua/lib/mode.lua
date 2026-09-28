-- mode.lua — named modes: a system prompt and a set of MCP connections under
-- one name, switched as a pair.
--
--   agent.mode.new("coding", {
--     system_prompt = [[You are a coding agent…]],
--     mcps = { fs = require("fs") },
--   })
--
--   agent.mode.set("coding")   -- overwrite agent.mcps and agent.llm.system_prompt
--   agent.mode.set()           -- back to the state captured before the first switch
--
-- ## What a switch does
--
-- `set(name)` overwrites exactly two things:
--
--   * `agent.mcps` — becomes the mode's connection set. Rust reindexes that
--     table per request, so the new tool set is live on the very next request.
--   * `agent.llm.system_prompt` — becomes the mode's prompt. Rust reads it
--     per request too (`crate::lua::system_prompt`), so no restart and no
--     cache sits in the way.
--
-- Nothing else changes: a mode is a *pair*, not a sandbox. There is no shared
-- policy namespace for a mode to set, either — a sandbox policy is a local
-- table written at the `agent.bash` call site (see `lua/lib/bash.lua`), so a
-- tool that wants a per-mode policy reads `agent.mode.current()` itself.
--
-- ## Three tool sets, not two
--
-- `mcps` may be:
--
--   * a table — the mode's tool set, replacing what is in force (`compact`
--     passes an empty one, so that mode has no tools at all);
--   * the string `"all"` — leave the registry in force and swap only the
--     prompt, so the mode is "whatever tools this session has" (`coding`
--     passes this);
--   * `nil` — the same as an empty table, no tools.
--
-- `"all"` is read at switch time, not at registration, so a connection
-- registered after the mode is still in it. A mode that *listed* every
-- connection instead would have to be written after them all, and one required
-- too early would silently drop a tool.
--
-- ## Connections are shared, the registry is not
--
-- `mcps` holds the connection tables **by reference** — the same ones your
-- config built — and both the mode's registry and the baseline `set()` restores
-- are shallow copies of a registry, so:
--
--   * `agent.mcps.fs == mode.mcps.fs` (same connection: same tools, same
--     lifecycle, `rawequal` true), and
--   * `agent.mcps ~= mode.mcps` (the registry is fresh), so a later
--     `agent.mcps.foo = x` at runtime cannot scribble on the mode's spec, nor
--     on the baseline that `set()` puts back.
--
-- Pass a list instead of a map and each connection is keyed by its own `.name`
-- field: `mcps = { agent.mcp("fs", func) }` is `mcps = { fs = <that conn> }`.
--
-- ## Defaults and the baseline
--
-- A mode need not declare both halves: `system_prompt` defaults to `""` (no
-- system message) and `mcps` to `{}` (no tools). That keeps the invariant the
-- rest of the system relies on — after `set`, `agent.mcps` is a table and
-- `agent.llm.system_prompt` is a string — instead of leaving a nil where
-- Rust expects a registry.
--
-- The first `set` captures what it replaced (`agent.mcps`, the prompt) as the
-- baseline; `agent.mode.set()` with no name puts it back, so a mode is always
-- reversible. Registration survives a `/reload`: this module is cached in
-- `package.loaded`, so re-running a user config *replaces* a mode's spec
-- rather than duplicating it, and re-registering the active mode re-applies it.
--
-- Nothing re-triggers inference: a switch takes effect from the next turn.
-- Call `agent.trigger()` yourself if you want it now.

local M = {}

-- name -> spec. The registry is internal; reach it through the functions below.
--- The `mcps` value that means "this mode does not change the tool set": the
--- registry in force stays exactly as it is, and only the prompt is swapped.
---
--- It exists because the other two options cannot express "all the tools", and
--- both of those are already modes. A mode that *lists* every connection would
--- have to be written after the config registered them all — a user config
--- decides that order, and a mode required one line too early loses a tool. A
--- sentinel is read at switch time instead, so it cannot go stale, and it cannot
--- be got wrong by a connection that is registered later.
local KEEP_TOOLS = "all"

local modes = {}
-- The mode `set` last applied, or nil.
local active = nil
-- What the first `set` replaced, so `set()` can put it back.
local baseline = nil

-- `agent.llm` does not exist yet when this module is loaded (the entry script
-- creates it); every read happens inside a function, at call time.
local function llm()
  agent.llm = agent.llm or {}
  return agent.llm
end

-- The connections a mode declares, as a name -> connection map. A list is keyed
-- by each connection's own `.name`; a map is taken as-is.
local function connections_of(mcps, mode_name)
  local out = {}
  for key, conn in pairs(mcps) do
    if type(key) == "number" then
      if type(conn) ~= "table" or type(conn.name) ~= "string" or conn.name == "" then
        error("agent.mode: " .. mode_name .. " mcps[" .. key ..
              "] has no .name to key it by (use a name -> connection map)", 3)
      end
      out[conn.name] = conn
    else
      if type(conn) ~= "table" or type(conn.tools) ~= "table" then
        error("agent.mode: " .. mode_name .. " mcps." .. tostring(key) ..
              " is not a connection (expected a table with .tools)", 3)
      end
      out[key] = conn
    end
  end
  return out
end

-- Register a mode, or replace it if the name is taken. Returns the spec.
-- Registering the mode that is currently active re-applies it, which is what
-- makes a `/reload` self-healing.
function M.new(name, spec)
  if type(name) ~= "string" or name == "" then
    error("agent.mode.new: name must be a non-empty string, got " .. type(name), 2)
  end
  if type(spec) ~= "table" then
    error("agent.mode.new: " .. name .. " needs a spec table, got " .. type(spec), 2)
  end
  if spec.system_prompt ~= nil and type(spec.system_prompt) ~= "string" then
    error("agent.mode.new: " .. name .. ".system_prompt must be a string or nil, got " ..
          type(spec.system_prompt), 2)
  end
  if spec.description ~= nil and type(spec.description) ~= "string" then
    error("agent.mode.new: " .. name .. ".description must be a string or nil, got " ..
          type(spec.description), 2)
  end
  if spec.mcps ~= nil and type(spec.mcps) ~= "table" and spec.mcps ~= KEEP_TOOLS then
    error("agent.mode.new: " .. name .. ".mcps must be a table, nil, or the " ..
          "string \"" .. KEEP_TOOLS .. "\", got " .. type(spec.mcps), 2)
  end
  local entry = {
    name = name,
    description = spec.description,
    system_prompt = spec.system_prompt or "",
    -- The marker passes through untouched: there is no connection list to
    -- normalize when the mode is not changing the tool set.
    mcps = spec.mcps == KEEP_TOOLS and KEEP_TOOLS
          or connections_of(spec.mcps or {}, name),
  }
  modes[name] = entry
  if active == name then
    M.set(name) -- a reloaded spec takes effect at once
  end
  return entry
end

-- Switch to `name`, overwriting `agent.mcps` and `agent.llm.system_prompt`.
-- No name: restore the baseline captured by the first switch. Returns the
-- applied mode (or nil for the baseline).
function M.set(name)
  if name == nil then
    if baseline == nil then
      return nil -- nothing was ever switched: already the baseline
    end
    local mcps, prompt = baseline.mcps, baseline.system_prompt
    baseline = nil
    active = nil
    llm().system_prompt = prompt
    agent.mcps = mcps
    return nil
  end
  local entry = modes[name]
  if entry == nil then
    error("agent.mode.set: unknown mode " .. tostring(name) .. " (known: " ..
          table.concat(M.names(), ", ") .. ")", 2)
  end
  if baseline == nil then
    -- First switch: remember what we are about to replace.
    --
    -- A *copy* of the registry, for the same reason the mode's own registry is
    -- a copy: `agent.mcps` is live and a tool or a handler can register into it
    -- at any time (`agent.mcps.foo = ...`). Holding the table itself would make
    -- such a registration part of the baseline, so `set()` would hand back a
    -- registry the user never had. A connection added mid-session belongs to
    -- that session.
    local snapshot = {}
    for conn_name, conn in pairs(agent.mcps) do snapshot[conn_name] = conn end
    baseline = { mcps = snapshot, system_prompt = llm().system_prompt }
  end
  active = name
  llm().system_prompt = entry.system_prompt
  if entry.mcps == KEEP_TOOLS then
    -- A prompt-only mode: the registry in force stays, tools and all.
    return entry
  end
  -- A shallow copy of the mode's registry, so the connections are shared (same
  -- tables) while the registry itself is ours to hand to Rust.
  local registry = {}
  for conn_name, conn in pairs(entry.mcps) do registry[conn_name] = conn end
  agent.mcps = registry
  return entry
end

--- The active mode's name, or nil when the baseline is in force.
function M.current()
  return active
end

--- A registered mode's spec (the active one by default), or nil.
function M.get(name)
  return modes[name or active]
end

--- Drop a registered mode. The active one is switched off first, so
--- `current()` is never left naming a mode that no longer exists. `true` when it
--- was registered.
---
--- This exists because modes ship built in (`lua/init.lua` registers `coding` and
--- `compact`), so "I do not want that mode" is a real request and not a way to
--- arrange for one never to have been there.
function M.forget(name)
  if modes[name] == nil then return false end
  if active == name then M.set() end
  modes[name] = nil
  return true
end

--- Drop every registered mode, leaving the prompt and the registry exactly as
--- they are — the "do not touch the state" counterpart to `set`. For a test that
--- wants a neutral `agent`, and for a config that would rather start from nothing
--- than from the built-ins.
function M.forget_all()
  for name in pairs(modes) do modes[name] = nil end
end

--- Every registered mode name, sorted.
function M.names()
  local out = {}
  for name in pairs(modes) do out[#out + 1] = name end
  table.sort(out)
  return out
end

--- The connections in force, or nil for the baseline. A prompt-only mode
--- installed none of its own, so this reports the registry that is actually
--- live rather than the `"all"` marker it carries.
function M.mcps()
  local entry = modes[active]
  if entry == nil then return nil end
  if entry.mcps == KEEP_TOOLS then return agent.mcps end
  return entry.mcps
end

--- The prompt the active mode installed, or nil for the baseline.
function M.prompt()
  local entry = modes[active]
  return entry and entry.system_prompt or nil
end

-- --------------------------------------------------------------------------
-- Self-test: `agent.mode._selftest()` raises on any failure.
--
-- Non-destructive: the registry, the active mode and the baseline are
-- snapshotted first, so running it on a *configured* VM (a user config has
-- already registered modes) leaves every one of them as it found them.
-- --------------------------------------------------------------------------

function M._selftest()
  local saved_prompt = llm().system_prompt
  local saved_mcps = agent.mcps
  local saved_modes, saved_active, saved_baseline = modes, active, baseline
  modes, active, baseline = {}, nil, nil
  local ok, err = pcall(function()
    -- Registration and validation.
    local coding = M.new("coding", {
      description = "edit the repo",
      system_prompt = "CODING",
      mcps = { fs = { name = "fs", tools = { read = true } } },
    })
    assert(coding.system_prompt == "CODING")
    assert(coding.mcps.fs.tools.read == true)
    assert(not pcall(M.new, "", {}), "an empty name is refused")
    assert(not pcall(M.new, "x", "nope"), "a non-table spec is refused")
    assert(not pcall(M.new, "x", { system_prompt = 5 }), "a non-string prompt is refused")
    assert(not pcall(M.new, "x", { mcps = 5 }), "a non-table mcps is refused")
    assert(not pcall(M.new, "x", { mcps = { fs = "not a connection" } }),
           "a non-connection value is refused")

    -- A list is keyed by each connection's own name.
    local listed = M.new("listed", { mcps = { { name = "lone", tools = {} } } })
    assert(listed.mcps.lone ~= nil, "list form keyed by .name")

    -- Both halves default, so `set` never leaves a nil where Rust expects a
    -- registry.
    local bare = M.new("bare", {})
    assert(bare.system_prompt == "" and next(bare.mcps) == nil)

    -- Switching overwrites both, and shares the connections by reference.
    local conn = { name = "fs", tools = {} }
    M.new("wiring", { system_prompt = "W", mcps = { fs = conn } })
    M.set("wiring")
    assert(M.current() == "wiring")
    assert(llm().system_prompt == "W")
    assert(rawequal(agent.mcps.fs, conn), "the connection is shared, not copied")
    assert(not rawequal(agent.mcps, M.get("wiring").mcps),
           "the registry is a fresh copy, so writes cannot leak into the spec")

    -- Re-registering the active mode re-applies it.
    M.new("wiring", { system_prompt = "W2", mcps = { fs = conn } })
    assert(llm().system_prompt == "W2", "a reloaded spec applies at once")

    -- `mcps = "all"` is a prompt-only mode: it swaps the prompt and leaves the
    -- registry exactly as it is, tools and all.
    M.new("keeps", { system_prompt = "K", mcps = "all" })
    local before_keep = agent.mcps
    M.set("keeps")
    assert(llm().system_prompt == "K", "the prompt is applied")
    assert(rawequal(agent.mcps, before_keep),
           "and the registry in force is untouched — every tool still there")
    assert(agent.mcps.fs ~= nil, "including this session's connections")
    assert(rawequal(M.mcps(), agent.mcps),
           "and the accessor reports what is live, not the marker")
    assert(not pcall(M.new, "x", { mcps = "everything" }),
           "a misspelled marker is refused, not taken as a tool set")
    M.set()
    assert(llm().system_prompt == saved_prompt, "back to the baseline prompt")

    -- An unknown name is refused.
    assert(not pcall(M.set, "nope"), "an unknown mode is refused")

    -- Back to the baseline, both halves.
    M.set()
    assert(M.current() == nil)
    -- By *contents*, not identity: the baseline is a shallow copy, so a
    -- connection registered while a mode was in force cannot ride back into it.
    local same_conns = true
    for conn_name, conn in pairs(saved_mcps) do
      if not rawequal(agent.mcps[conn_name], conn) then same_conns = false end
    end
    for conn_name in pairs(agent.mcps) do
      if saved_mcps[conn_name] == nil then same_conns = false end
    end
    assert(same_conns, "the baseline registry is restored")
    assert(llm().system_prompt == saved_prompt, "the baseline prompt is restored")
    -- And a second bare `set` is a no-op, not an error.
    assert(M.set() == nil)
  end)
  -- Restore whatever the VM had, whether the body passed or blew up.
  agent.mcps = saved_mcps
  llm().system_prompt = saved_prompt
  modes, active, baseline = saved_modes, saved_active, saved_baseline
  if not ok then error(err, 0) end
  return true
end

-- The `lua/lib/` convention: publish on `agent`, so `agent.mode` is the
-- mechanism and `require("mode")` is the same table.
agent.mode = M

return M
