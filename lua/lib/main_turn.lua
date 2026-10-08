-- main_turn.lua — the main conversation's turn handler.
--
-- `turn.lua` (`agent.turn`) is the *mechanism*: one request as a drivable stream,
-- for any conversation. This file is the *main* conversation's driver — the
-- handler the loop fires when the user submits a line and when `agent.trigger`
-- forces an inference. One mechanism, both halves: a subagent calls
-- `agent.turn` itself; the main turn runs here.
--
-- The handler owns the *whole* turn, tool loop included:
--
--   while the model keeps asking for tools:
--     drive one request, drawing the stream
--     hand the assembled turn to the loop with `agent.await_tools(turn)`
--     extend the local history with the round's results
--   return the final turn
--
-- What stays in Rust is everything mechanical: the history the requests read,
-- the folding of each round into it (in the protocol's order), the tool
-- coroutines themselves — asks, panels, Ctrl+C — and the archiving. The await
-- is the seam: the handler suspends on it, the loop runs the round exactly as
-- it always has, and resumes the handler with `{ results, stopped }`. Handler
-- and tool coroutines never run nested; the loop alternates them.
--
-- The event is a *request*, the third kind after "turn_completed" (a
-- notification) and "key" (a question): the return value is the answer. The
-- final turn comes back as the assembled-turn table; an interrupted round
-- comes back `stopped = true`, and the handler ends the turn by returning the
-- same sentinel — everything about it is folded already, and returning the
-- last turn instead would fold it twice.
--
-- What it draws is what the loop used to draw: reasoning streams into a
-- borderless "reasoning" block (dimmed), the answer into a "response" block —
-- fresh panels *each round*, so one round's stream never flows into the last
-- round's block. Those titles are not decoration — `is_borderless_box` in the
-- panel renderer matches on them, which is what keeps a panel-driven block
-- looking exactly like a loop-driven one. Panels drawn here are *not*
-- archived to the log (the loop drains the turn's sink without logging it):
-- on resume, reasoning is reconstructed from the archived reasoning records
-- and the answer from the assistant message, as it always was.

local M = {}

---Suspend until the loop has run this turn's tool round, then answer with
---`{ results = { { id, content }, … }, stopped = bool }`. The yield carries
---the assembled turn so the loop can fold it first — which is why only the
---`turn` handler may call this: anywhere else there is no round to run.
local function await_tools(turn)
  return coroutine.yield({ __agent_await = "tools", turn = turn })
end
agent.await_tools = await_tools

---Drive the whole turn on the loop's conversation and return the final
---assembled turn. `ev.history` is the in-memory history, user message already
---appended.
function M.turn(ev)
  -- A local copy to extend: the requests read it, and the rounds grow it.
  -- The loop's own history grows by the same messages, folded by Rust at each
  -- await — the two cannot disagree, because both are built from the same
  -- turns and the same results, in the same order.
  local history = {}
  for i, m in ipairs(type(ev) == "table" and ev.history or {}) do
    history[i] = m
  end

  while true do
    -- The panels are created on the first chunk of their kind, each round: a
    -- model that answers without reasoning must not leave an empty dimmed
    -- block behind, and a round's blocks must come *after* the previous
    -- round's in the transcript, which "created on first use" gets for free.
    local reasoning, response
    local stream = agent.turn({ messages = history })
    local turn = stream:run(function(e)
      if e.kind == "reasoning" and e.text ~= "" then
        reasoning = reasoning or agent.panel("reasoning")
        reasoning:append(e.text)
      elseif e.kind == "content" then
        response = response or agent.panel("response")
        response:append(e.text)
      end
    end)

    if #turn.tool_calls == 0 then
      return turn
    end

    local round = await_tools(turn)
    if round.stopped then
      return { stopped = true }
    end

    -- Extend the local history for the next request, in the protocol's order:
    -- what the model said, then what it asked for, then one result per call.
    -- (`function` is a Lua keyword, so the wire shape spells it with brackets.)
    if turn.content ~= "" then
      history[#history + 1] = { role = "assistant", content = turn.content }
    end
    local calls = {}
    for i, c in ipairs(turn.tool_calls) do
      calls[i] = {
        id = c.id,
        type = "function",
        ["function"] = { name = c.name, arguments = c.arguments },
      }
    end
    history[#history + 1] = { role = "assistant", tool_calls = calls }
    for _, r in ipairs(round.results) do
      history[#history + 1] = { role = "tool", tool_call_id = r.id, content = r.content }
    end
  end
end

agent.main_turn = M.turn
