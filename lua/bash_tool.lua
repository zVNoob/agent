-- bash_tool.lua — the `bash` tool, as a connection: the agent's shell.
--
-- This is what the built-in tool used to be: a ToolDef Rust assembled by hand
-- and executed in C. It is now a Lua connection like any other, so the registry
-- is the single source of truth for what the agent can do — and a mode that
-- lists no connections has no shell at all (`agent.mode.set`, see
-- `lua/lib/mode.lua`). Register it with one line:
--
--   agent.mcps.bash = require("bash_tool")
--
-- Which is also how you get it *back*: leave the line out and the model is never
-- offered a shell.
--
-- The run itself is `agent.bash` (lua/lib/bash.lua) under the default policy in
-- `lua/policy.lua` — a table of syscall name -> callback whose keys are the
-- sandbox's interception mask. That policy traps `openat`, `connect`, `bind` and
-- `sendto`, and **asks** about each rather than deciding: the question is shown
-- as an overlay on the result panel, the answer is handed back to the frozen
-- syscall, and an "always" remembers the path or the endpoint so the next
-- command does not ask. The working directory is trusted outright
-- (`lua/init.lua`), so work in this repository asks for nothing and everything
-- outside it does. With no ask handler — headless, the tests, the probe — the ask
-- auto-denies, so a sandboxed run there reaches nothing it was not already
-- trusted for.
--
-- The result is the MCP shape. `result` is always present (stdout, stderr,
-- exit_code / exit_signal, syscalls, denied, denied_reason) so the model sees
-- the full outcome; `ok = false` means the tool itself did not complete — a
-- missing `cmdline`, or a write the user refused (which arrives as
-- `denied_reason`). A command that merely exits non-zero is `ok = true` with its
-- exit status: it ran, and its output is the answer.
--
-- The result panel is created before the sandbox spawns, each stdout chunk is
-- appended as it arrives, and a status line finishes it — so the TUI shows the
-- command's output *streaming* instead of hanging until the run completes.

local M = { name = "bash", tools = {} }

-- The run itself. The policy is the default one, `lua/policy.lua` — a module
-- that *returns* a table, required here and handed to `agent.bash` per call. A
-- policy is a per-call argument and never ambient state, so a caller that wants
-- different rules passes its own table; that is all a policy is.
local function run(args)
  if type(args.cmdline) ~= "string" or args.cmdline == "" then
    return { ok = false, error = "bash: 'cmdline' is required and must be a non-empty string" }
  end

  -- One panel for the whole run: the stream, the ask overlay, and the status.
  local p = agent.panel("bash result", { boxed = true, conceal_box = false })
  local s = agent.bash(args.cmdline, require("policy"), {
    on_stdout = function(chunk)
      -- A panel append is a bridge call; a tool that loses its panel must not
      -- take the run down with it, so the append is guarded.
      pcall(function() p:append(chunk) end)
    end,
  })
  -- The ask handler: an asking policy re-yields the question here. Show it as an
  -- overlay inside the panel box, put it to the user, and clear the overlay
  -- before the sandbox resumes.
  --
  -- How the question reaches the user depends on who is driving this tool call.
  -- On the reactor — the TUI, which runs the whole call as a coroutine and
  -- resumes it — the ask is *yielded* up: the driver owns the prompt, and
  -- blocking on `agent.api.ask_user` here would block the very loop that has to
  -- draw it. Anywhere else (the probe, the tests) there is no driver, so ask
  -- directly and block for the answer, exactly as before.
  --
  -- The ask's own `always` flag is what decides whether the prompt offers
  -- `[a]lways` beside yes and no: a question with a path to remember offers it
  -- (the `for_syscall` shape the shipped policy asks), and one without does
  -- not. The overlay names the choices the user actually has.
  local r = s:run(function(a)
    local text, always
    if type(a) == "table" then
      text = type(a.description) == "string" and a.description or tostring(a.description)
      always = a.always == true
    else
      text = tostring(a)
    end
    p:overlay(text .. (always and "\n\n[y]es  [n]o  [a]lways" or "\n\n[y]es  [n]o"))
    -- Yield the ask itself, not the text: the driver reads `description` and
    -- `always` off it and shows the same wording this overlay does.
    local verdict = agent.__on_reactor
        and coroutine.yield(type(a) == "table" and a or { description = text })
        or agent.api.ask_user(text, always)
    p:clear_overlay()
    return verdict
  end)

  local exit = r.exit or {}
  local result = {
    stdout = r.stdout or "",
    stderr = r.stderr or "",
    exit_code = exit.code,
    exit_signal = exit.signal,
    syscalls = r.syscalls or 0,
    denied = r.denied or 0,
    denied_reason = r.denied_reason,
  }
  local status
  if (r.denied or 0) > 0 then
    status = (type(r.denied_reason) == "string" and r.denied_reason ~= "")
        and ("Denied: " .. r.denied_reason) or "Denied"
  else
    status = "exited with exit code " .. tostring(exit.code or exit.signal or 0)
  end
  -- Finish the stream panel: the last line is the status, on its own line.
  local so_far = result.stdout
  if so_far ~= "" and not so_far:match("\n$") then
    p:append("\n" .. status)
  else
    p:append(status)
  end

  if (r.denied or 0) > 0 then
    return {
      ok = false,
      error = "denied: " .. ((type(r.denied_reason) == "string" and r.denied_reason ~= "")
        and r.denied_reason or "the sandbox policy refused a syscall"),
      result = result,
    }
  end
  return { ok = true, result = result }
  end

M.tools.bash = agent.utils.tool(
  "Run a shell command (`bash -c`) through the seccomp sandbox under a Lua syscall "
  .. "policy. Reading and writing files, and reaching the network, ask the user "
  .. "first — shown as an overlay on the result panel, and \"always\" makes that "
  .. "path or endpoint stop asking. The working directory is already trusted, so "
  .. "work there is silent (headless runs deny every ask). Returns stdout/stderr, "
  .. "the exit status, and the syscall/denied counters.",
  {
    type = "object",
    properties = {
      cmdline = {
        type = "string",
        description = "the shell command to run (bash -c '<cmdline>')",
      },
    },
    required = { "cmdline" },
  },
  run)

return M
