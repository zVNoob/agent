-- panel.lua — the transcript panel sugar over the `agent.api.panel_*` bridge.
--
-- A panel is a titled box in the transcript that a policy or tool writes into
-- while it runs. `agent.panel(title, opts)` returns a handle:
--
--   local p = agent.panel("syscall log", { boxed = true })
--   p:append("openat denied\n")
--   p:highlight(0, 11, "bold.red")
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
  function h:overlay(text) agent.api.panel_overlay(self.id, text) end
  function h:clear_overlay() agent.api.panel_overlay(self.id, nil) end
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
  function h:overlay(text) agent.api.panel_overlay(self.id, text) end
  function h:clear_overlay() agent.api.panel_overlay(self.id, nil) end
  return h
end

-- The lib-module convention: publish on `agent`, so `agent.panel` and
-- `require("panel").panel` are the same function.
agent.panel = M.panel
agent.split_panel = M.split_panel

return M
