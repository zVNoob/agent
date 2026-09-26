-- on_timeout.lua — the cooperative wait: `agent.on_timeout(ms, fn)`.
--
-- The last piece of the old driver to reach `lua/lib/`. It is the one primitive
-- the runtime cannot express as a one-shot call: a wait that *suspends* the
-- current coroutine instead of blocking the thread, so a long sandboxed run, a
-- streaming HTTP response, or an event handler keeps the agent's single thread
-- live while it waits.
--
--   agent.on_timeout(20)                  -- wait 20ms
--   agent.on_timeout(1000, fn)            -- wait 1s, then run fn
--
-- On a *reactor-driven* coroutine — a `turn_completed` event handler running on
-- the agent's single thread — the wait yields `{ __agent_await = "timeout" }`
-- and the reactor resumes it when its timer fires, so nothing else freezes.
-- Anywhere else (a tool thread, the config VM, a test) it falls back to a real
-- thread sleep through `agent.api.sleep`, then runs `fn`.
--
-- Returns true when it suspended, false when it slept: which path it took.
-- The streaming pumps use it as their idle cadence; a user handler can use it
-- to wait without blocking the loop.

local M = {}

-- Timers: `agent.on_timeout(ms, fn)` — the cooperative replacement for the
-- old blocking `agent.api.sleep(ms)`. `fn` runs after `ms` milliseconds; pass
-- `nil` for a plain wait (the pumps' cadence).
--
-- On a *reactor-driven* coroutine — a `turn_completed` event handler running
-- on the agent's single thread (see `EventRun` in Rust) — the wait suspends
-- the handler coroutine until the reactor's timer fires, so the loop stays
-- live the whole time (strictly single-threaded; nothing else freezes), then
-- `fn` runs and the handler continues. The yield carries a
-- `{ __agent_await = "timeout", ms = ms }` request that the reactor answers;
-- user code that calls `coroutine.yield` directly with other values is an
-- error.
--
-- Outside a reactor coroutine (tool threads, top-level config, tests) the
-- wait falls back to a real thread sleep via `agent.api.sleep` (the historical
-- behavior) and then runs `fn` — same timing, no coroutine involved.

function M.on_timeout(ms, fn)
  if type(ms) ~= "number" or ms < 0 or ms % 1 ~= 0 then
    error("agent.on_timeout: ms must be a non-negative integer, got " .. tostring(ms), 2)
  end
  if fn ~= nil and type(fn) ~= "function" then
    error("agent.on_timeout: fn must be a function or nil, got " .. type(fn), 2)
  end
  if agent.__on_reactor then
    -- Inside the reactor-driven handler coroutine: suspend until the timer
    -- fires, then run fn. The reactor resumes with `true` back at the yield.
    coroutine.yield({ __agent_await = "timeout", ms = ms })
    if type(fn) == "function" then fn() end
    return true
  end
  -- Plain context: block the current thread (the old `agent.api.sleep`), then fn.
  agent.api.sleep(ms)
  if type(fn) == "function" then fn() end
  return false
end

-- The lib-module convention: publish on `agent`, so `agent.on_timeout` and
-- `require("on_timeout")` are the same function.
agent.on_timeout = M.on_timeout

return M.on_timeout
