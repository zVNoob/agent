-- panel.lua — the transcript panel sugar over the `agent.api.panel_*` bridge.
--
-- A panel is a titled box in the transcript that a policy or tool writes into
-- while it runs. `agent.panel(title, opts)` returns a handle:
--
--   local p = agent.panel("syscall log", { boxed = true })
--   p:append("openat denied\n")
--   p:highlight(0, 11, "bold.red")
--   local ok = p:ask("The process want to read /etc/hostname", true)
--
-- `agent.split_panel(title, panes)` returns the same kind of handle over
-- side-by-side numbered panes, each with its own caption, language and
-- highlights — the shape a before/after diff view wants.
--
-- Ops buffer in the round's panel sink and the TUI applies them each frame, so
-- a long command's output fills the box live. A run with no sink (headless, the
-- probe, a test) makes every call a graceful no-op.

local M = {}

-- `M.panel(title, opts)` -> a handle for appending text to the
-- transcript and styling byte regions, usable from a policy or MCP tool:
--   local p = agent.panel("syscall log", { boxed = true })
--   p:append("openat denied\n")
--   p:highlight(0, 11, "bold.red")
--   local ok = p:ask("The process want to read /etc/hostname", true)
-- The handle is a thin driver over the `agent.api.panel_*` primitives; ops
-- buffer in the round's panel sink and the TUI applies them (headless runs
-- with no sink: graceful no-ops).
function M.panel(title, opts)
  local id = agent.api.panel_create(title, opts or {})
  local h = { id = id }
  function h:append(text) agent.api.panel_append(self.id, text) end
  function h:set(text) agent.api.panel_set(self.id, text) end
  function h:highlight(start, finish, style) agent.api.panel_highlight(self.id, start, finish, style) end
  function h:clear_regions() agent.api.panel_clear_regions(self.id) end
  function h:overlay(text, always) agent.api.panel_overlay(self.id, text, always) end
  function h:clear_overlay() agent.api.panel_overlay(self.id, nil) end

  --- Ask the user something, as a dialog at the bottom of *this* panel, and
  --- return their answer: `true`, `false`, or a verdict table.
  ---
  --- This is the ask a tool should use. A question belongs to the thing that
  --- raised it, so it is asked on the panel that raised it and nowhere else —
  --- there is no searching for "the panel this is probably in", and the answer
  --- cannot land on a neighbouring message.
  ---
  --- `always` says whether the answer is one the agent can act on: a question
  --- with a path or an endpoint to remember offers `[a]lways` beside yes and
  --- no, and one without does not, because "always" would be a promise nothing
  --- can keep.
  ---
  --- On the reactor — the TUI, which runs a tool call as a coroutine and
  --- resumes it — the ask is *yielded*, not blocked on: the yield is what hands
  --- the question to the loop that has to draw it. Blocking here would block
  --- the very thing that would answer. Anywhere else (the probe, the tests)
  --- there is no driver, so it asks directly and blocks, exactly as before.
  function h:ask(text, always)
    if type(text) ~= "string" or text == "" then
      error("panel:ask: text must be a non-empty string, got " .. type(text), 2)
    end
    self:overlay(text, always == true)
    local ok, verdict = pcall(function()
      if agent.__on_reactor then
        return coroutine.yield({ description = text, always = always == true })
      end
      return agent.api.ask_user(text, always == true)
    end)
    -- Cleared whatever happened: a tool that raised mid-question must not leave
    -- its dialog on screen for the rest of the session.
    self:clear_overlay()
    if not ok then error(verdict, 0) end
    return verdict
  end

  return h
end

-- Split panels: `agent.split_panel(title, panes)` -> a handle for driving one
-- titled box that shows several regions side by side, each with its own text
-- and — crucially — its own declared highlighting language. The sibling of
-- `agent.panel` for the patch tool: both sides of an applied diff render as
-- real code, tree-sitter-highlighted independently (a single diff panel can't
-- run a code grammar over `+`/`-`-prefixed lines).
--   local p = agent.split_panel("apply_patch", {
--     { caption = "before", lang = "bash" },
--     { caption = "after",  lang = "bash" },
--   })
--   p:set(1, "echo old")
--   p:set(2, "echo new")
--   p:highlight(2, 5, 8, "bold.green")
--   p:lang(1, "json")               -- re-declare a pane's language later
--   p:clear_regions(2)
--   p:overlay("applying…")          -- the ask/status seam, like agent.panel
-- `panes` is an array; each entry is either a string (the pane's caption) or
-- a table `{ caption = "", lang = "" }` (`lang` optional — panes without one
-- render plain). Pane indexes in the methods are 1-based, matching Lua.
function M.split_panel(title, panes)
  if type(panes) ~= "table" then
    error("agent.split_panel: panes must be a table, got " .. type(panes), 2)
  end
  local id = agent.api.panel_split(title, panes)
  local h = { id = id }
  function h:set(pane, text) agent.api.panel_pane_set(self.id, pane, text) end
  function h:lang(pane, lang) agent.api.panel_pane_lang(self.id, pane, lang) end
  function h:highlight(pane, start, finish, style) agent.api.panel_pane_highlight(self.id, pane, start, finish, style) end
  function h:clear_regions(pane) agent.api.panel_pane_clear_regions(self.id, pane) end
  -- The overlay belongs to the *panel*, not to a pane, so a split handle has
  -- exactly the same ask seam a plain one does — including the `always` flag,
  -- which without it could never offer `[a]lways` and so could never remember
  -- a path. `apply_patch` is the caller: it asks before it patches, on the same
  -- panel it is about to fill with the before/after.
  function h:overlay(text, always) agent.api.panel_overlay(self.id, text, always == true) end
  function h:clear_overlay() agent.api.panel_overlay(self.id, nil) end

  --- Ask the user something, as a dialog at the bottom of *this* panel — the
  --- same contract as `agent.panel`'s `h:ask`, and for the same reason: the
  --- overlay is per-panel, so a split is no harder to ask on than a single box.
  function h:ask(text, always)
    if type(text) ~= "string" or text == "" then
      error("split_panel:ask: text must be a non-empty string, got " .. type(text), 2)
    end
    self:overlay(text, always)
    local ok, verdict = pcall(function()
      if agent.__on_reactor then
        return coroutine.yield({ description = text, always = always == true })
      end
      return agent.api.ask_user(text, always == true)
    end)
    -- Cleared whatever happened, exactly as the plain handle does: a tool that
    -- raised mid-question must not leave its dialog on screen.
    self:clear_overlay()
    if not ok then error(verdict, 0) end
    return verdict
  end
  return h
end

-- The lib-module convention: publish on `agent`, so `agent.panel` and
-- `require("panel").panel` are the same function.
agent.panel = M.panel
agent.split_panel = M.split_panel

return M
