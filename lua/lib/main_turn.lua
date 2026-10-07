-- main_turn.lua — the main conversation's turn handler.
--
-- `turn.lua` (`agent.turn`) is the *mechanism*: one request as a drivable stream,
-- for any conversation. This file is the *main* conversation's driver — the
-- handler the loop fires when the user submits a line, when a tool round needs
-- the model again, and when `agent.trigger` forces an inference. One mechanism,
-- both halves: a subagent calls `agent.turn` itself; the main turn runs here.
--
-- The loop (Rust) still owns everything around the request: the history the
-- request reads, the tool loop the answer feeds, the archiving. This handler's
-- part is the middle — drive the request, draw the stream, hand the assembled
-- turn back as its return value:
--
--   agent.on_event("turn", agent.main_turn)   -- wired in init.lua §7
--
-- The event is a *request*, the third kind after "turn_completed" (a
-- notification) and "key" (a question): the return value is the answer. Rust
-- decodes it (`turn_from_lua`) into the same `Turn` its own stream used to
-- build, so the two paths are indistinguishable from the tool loop down.
--
-- What it draws is what the loop used to draw: reasoning streams into a
-- borderless "reasoning" block (dimmed), the answer into a "response" block.
-- Those titles are not decoration — `is_borderless_box` in the panel renderer
-- matches on them, which is what keeps a panel-driven block looking exactly
-- like a loop-driven one. Panels drawn here are *not* archived to the log
-- (the loop drains the turn's sink without logging it): on resume, reasoning
-- is reconstructed from the archived reasoning records and the answer from the
-- assistant message, as it always was.

local M = {}

---Drive one request on the loop's conversation and return the assembled turn.
---`ev.history` is the in-memory history, user message already appended.
function M.turn(ev)
  local history = (type(ev) == "table" and type(ev.history) == "table")
      and ev.history or {}

  -- The panels are created on the first chunk of their kind, not up front: a
  -- model that answers without reasoning must not leave an empty dimmed block
  -- behind, and the response block must come *after* the reasoning one in the
  -- transcript, which "created on first use" gets for free.
  local reasoning, response
  local stream = agent.turn({ messages = history })
  return stream:run(function(e)
    if e.kind == "reasoning" and e.text ~= "" then
      reasoning = reasoning or agent.panel("reasoning")
      reasoning:append(e.text)
    elseif e.kind == "content" then
      response = response or agent.panel("response")
      response:append(e.text)
    end
  end)
end

agent.main_turn = M.turn
