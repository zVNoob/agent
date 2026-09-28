-- bash.lua — the sandboxed `agent.bash`: drive a `bash -c` run under a
-- seccomp syscall policy.
--
-- The Rust side (src/seccomp/) owns the engine and exposes *non-blocking*
-- primitives on the bridge; everything that makes a run a coroutine protocol
-- lives here, in Lua, where `coroutine.yield` works:
--
--   local s = agent.bash(cmdline, policy, {
--     on_stdout = function(chunk, stream) ... end,   -- pushed as chunks arrive
--     on_exit   = function(result) ... end,
--   })
--   local result = s:run(on_ask)
--
-- A policy is a table of syscall name -> callback. Its *keys are the
-- interception mask*: only the named syscalls are trapped (plus the engine's
-- always-on fork family, auto-allowed), so anything you leave out runs
-- straight through the kernel without reaching a callback. A callback returns
-- `true` / `false`, or `agent.allow()` / `agent.deny(reason)` for a denial that
-- names itself on the result.
--
-- A callback may *ask* — yield to the user. That is why the drive loop is Lua:
-- a yield cannot cross an mlua call (those are pcall boundaries that reject
-- it), so the callback runs in its own coroutine and the ask is re-yielded raw
-- to whoever resumed the pump, with the next resume's argument delivered back
-- at the yield site. `s:run(on_ask)` wraps that; driving `s.pump` yourself is
-- the same loop as a resumable coroutine (it yields asks and nothing else).
--
-- This module also owns the verdict sum type (`agent.allow` / `agent.deny`),
-- which the ask path decodes too.
--
-- The policy is a *per-call* argument, never ambient state, and this module
-- exports no builder for one: a caller states the policy it wants, in its own
-- closure, as a local table. `lua/policy.lua` (the shipped shell tool's
-- own policy, behind `lua/bash_tool.lua`) is exactly that shape:
--
--   local sc = require("seccomp")
--   local function open() return {} end   -- {} traps nothing
--   local function read_only() return {
--     openat = function(sys)
--       local flags = sc.arg(sys, "openat")
--       if sc.is_tty_probe(flags) then return true end
--       if sc.check("openat", flags, "WRITE") then
--         return agent.deny("read-only policy: write open (" ..
--                           sc.describes("openat", flags) .. ") denied")
--       end
--       return true
--     end,
--   } end
--   local out = agent.bash(args.cmd, read_only()):run()

local M = {}

-- The cadence (ms) a reactor-driven pump suspends for between idle steps —
-- the slice the event loop gets while a handler's bash runs. Bounded,
-- non-busy wakeups: ~50Hz, one timer poke per frame worst case.
local COOP_CADENCE_MS = 20

-- Drive one run to completion, pushing output chunks to the object's
-- `on_stdout`/`on_stderr` callbacks as they arrive and returning the final
-- result table (notifying `on_exit` first). A policy callback's yield — it
-- called a user-asking function — is re-yielded raw to whoever resumed the
-- pump; the verdict they resume with is delivered to the yield site. On a
-- reactor-driven coroutine (an event handler) an *idle* step — nothing ready
-- — instead suspends the pump for a cadence (`COOP_CADENCE_MS`), re-yielded
-- raw by `run`, so the event loop stays live while the sandbox runs.
local function drive(self, policy)
  local h = self.handle
  while true do
    local st = agent.api.step(h)
    if st.kind == "finished" then
      local result = st.result
      -- A policy's `agent.deny(reason)` names the denial: stamp it on the
      -- result before it reaches on_exit/the caller, so the panel status
      -- line and the tool JSON can show `Denied: <reason>`.
      if self.deny_reason then result.denied_reason = self.deny_reason end
      if self.on_exit then self.on_exit(result) end
      return result
    elseif st.kind == "output" then
      local cb = (st.stream == "stdout") and self.on_stdout or self.on_stderr
      if cb then cb(st.data, st.stream) end
    elseif st.kind == "blocked" then
      local sys = st.syscall
      local cb = policy[sys.name]
      local verdict
      if cb == nil then
        -- No policy entry: fail closed. Unreachable from agent.bash — the
        -- mask is derived from the policy's own keys, so every masked
        -- syscall has an entry (the engine's always-on fork family is
        -- auto-allowed without asking) — but it stays as a defensive
        -- default for future raw-driver callers.
        verdict = false
      elseif type(cb) ~= "function" then
        agent.api.kill(h)
        error("agent.bash: policy entry for '" .. sys.name .. "' is a " ..
              type(cb) .. ", not a callback", 0)
      else
        local sub = coroutine.create(cb)
        local ok, v = coroutine.resume(sub, sys)
        while ok and coroutine.status(sub) == "suspended" do
          -- The callback called a user-asking function which yielded: an
          -- ask. Re-yield it raw; the verdict on the next resume is
          -- delivered to the yield site, and the callback runs on.
          v = coroutine.yield(v)
          ok, v = coroutine.resume(sub, v)
        end
        if not ok then
          agent.api.kill(h)
          error("agent.bash: policy callback for '" .. sys.name ..
                "' errored: " .. tostring(v), 0)
        end
        if type(v) == "boolean" then
          verdict = v
        elseif type(v) == "table" and v.__agent_verdict == "deny" then
          -- `agent.deny(reason)`: final like `false`, but remember the reason
          -- so the finished result can carry it (see the finished branch). A
          -- reasonless denial stays reasonless (nil), not an empty string —
          -- `denied_reason` is a string|nil, and "" would render as a bare
          -- "Denied: " on the panel.
          local r = v.reason
          self.deny_reason = (type(r) == "string" and r ~= "") and r or nil
          verdict = false
        elseif type(v) == "table" and v.__agent_verdict == "allow" then
          verdict = true
        else
          agent.api.kill(h)
          error("agent.bash: policy callback for '" .. sys.name ..
                "' must return a boolean or agent.allow()/agent.deny(reason), got " ..
                type(v), 0)
        end
      end
      agent.api.decide(h, verdict)
    elseif agent.__on_reactor then
      -- idle on the reactor: `agent.api.step` polls 0ms, so nothing here blocks;
      -- suspend for a cadence and let the event loop breathe (re-yielded raw
      -- by `run`, answered by the reactor's timer).
      coroutine.yield({ __agent_await = "timeout", ms = COOP_CADENCE_MS })
    end
    -- idle (plain context): nothing ready; step again — the blocking poll
    -- inside `agent.api.step` is the wait there.
  end
end

-- The policy verdict sum type: `Allow | Denied(reason)`. A callback may
-- return these instead of a bare boolean — `agent.allow()` == `true`,
-- `agent.deny(reason)` == `false` plus a reason on the run's result (`drive`
-- decodes the tag; any other table return is an error).
function M.allow()
  return { __agent_verdict = "allow" }
end

function M.deny(reason)
  if reason ~= nil and type(reason) ~= "string" then
    error("agent.deny: reason must be a string or nil, got " .. type(reason), 2)
  end
  return { __agent_verdict = "deny", reason = reason or "" }
end

function M.bash(cmdline, policy, opts)
  if type(cmdline) ~= "string" then
    error("agent.bash: cmdline must be a string, got " .. type(cmdline), 2)
  end
  if type(policy) ~= "table" then
    error("agent.bash: policy must be a table mapping syscall names to callbacks", 2)
  end
  if opts == nil then
    opts = {}
  elseif type(opts) ~= "table" then
    error("agent.bash: opts must be a table (on_stdout/on_stderr/on_exit), got " .. type(opts), 2)
  end
  for _, k in ipairs({ "on_stdout", "on_stderr", "on_exit" }) do
    local v = opts[k]
    if v ~= nil and type(v) ~= "function" then
      error("agent.bash: opts." .. k .. " must be a function or nil, got " .. type(v), 2)
    end
  end

  -- The syscall-name keys of the policy are the interception mask: only
  -- those syscalls are trapped — everything un-listed runs straight through
  -- the kernel, never reaching a callback. The engine always additionally
  -- traps the fork family and auto-allows those not named here (pid
  -- bookkeeping). `agent.api.spawn(cmdline, names)`.
  local names = {}
  for k in pairs(policy) do
    if type(k) == "string" then
      names[#names + 1] = k
    end
  end

  local self = {
    handle = agent.api.spawn(cmdline, names),
    on_stdout = opts.on_stdout,
    on_stderr = opts.on_stderr,
    on_exit = opts.on_exit,
  }

  -- The pump: resume it to drive the run. It yields asks — raw values from
  -- user-asking functions, answered by the next resume's argument — and, on a
  -- reactor-driven coroutine, cooperative cadence waits (idle steps) that
  -- `run` re-yields raw, so the event loop stays live. It returns the final
  -- result table when the run completes. Output goes through the callbacks,
  -- never yielded, so resumes stay few.
  self.pump = coroutine.create(function()
    return drive(self, policy)
  end)

  function self:write_stdin(data)
    agent.api.write(self.handle, data)
  end

  function self:close_stdin()
    agent.api.close_stdin(self.handle)
  end

  function self:kill()
    agent.api.kill(self.handle)
  end

  -- Drive to completion, answering asks via on_ask(ask) -> boolean (or a
  -- verdict object — `agent.allow()` / `agent.deny(reason)` — so the denial
  -- can carry a reason, exactly like a policy return). With a plain
  -- allow/deny policy (no asks) pass nothing and the final result table is
  -- returned directly. Errors (policy, ask-without-handler, ...) raise.
  --
  -- On a reactor-driven coroutine (an event handler) `run` additionally
  -- re-yields the pump's cooperative cadence waits (idle steps) so the event
  -- loop stays live for the whole run, and — since a background handler has
  -- no ask UI — an ask with no `on_ask` *auto-denies* (like headless runs),
  -- so an asking policy can never hang a handler. Plain contexts keep the
  -- historical behavior: no cadence awaits, and an ask without `on_ask`
  -- raises.
  function self:run(on_ask)
    if on_ask ~= nil and type(on_ask) ~= "function" then
      error("agent.bash: on_ask must be a function, got " .. type(on_ask), 0)
    end
    local pending
    while true do
      local ok, ev = coroutine.resume(self.pump, pending)
      pending = nil
      if not ok then error(ev, 0) end
      if coroutine.status(self.pump) == "dead" then
        return ev
      end
      -- The pump yielded: a cooperative cadence wait (reactor only — the
      -- sandbox is idle, no work to do) or an ask from a user-asking function.
      if agent.__on_reactor and type(ev) == "table" and ev.__agent_await == "timeout" then
        -- Re-yield the wait to the event coroutine; the reactor resumes us
        -- when its timer fires, and the pump steps again with no verdict.
        coroutine.yield(ev)
      elseif agent.__on_reactor and on_ask == nil then
        -- A background run with no ask handler: auto-deny, so an asking
        -- policy terminates instead of hanging the handler.
        pending = false
      elseif on_ask == nil then
        error("agent.bash: policy asked but no on_ask handler was given " ..
              "(drive s.pump directly instead)", 0)
      else
        local verdict = on_ask(ev)
        if type(verdict) == "table" then
          -- A verdict object (`agent.allow()` / `agent.deny(reason)`): resumed
          -- into the asking callback like a boolean, so `Denied(reason)` flows
          -- through the ask path too (decoded in `drive`).
          if verdict.__agent_verdict ~= "allow" and verdict.__agent_verdict ~= "deny" then
            error("agent.bash: on_ask must return a boolean or " ..
                  "agent.allow()/agent.deny(reason), got a '" ..
                  tostring(verdict.__agent_verdict) .. "' verdict", 0)
          end
        elseif type(verdict) ~= "boolean" then
          error("agent.bash: on_ask must return a boolean or " ..
                "agent.allow()/agent.deny(reason), got " .. type(verdict), 0)
        end
        pending = verdict
      end
    end
  end

  return self
end

-- The lib-module convention: publish on `agent`, so `agent.bash` and
-- `require("bash").bash` are the same function (and likewise the verdicts).
agent.bash = M.bash
agent.allow = M.allow
agent.deny = M.deny

return M
