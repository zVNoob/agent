-- main_turn.lua — the main conversation's turn handler.
--
-- `turn.lua` (`agent.turn`) is the *mechanism*: one request as a drivable stream,
-- for any conversation. This file is the *main* conversation's driver — the
-- handler the loop fires when the user submits a line and when `agent.trigger`
-- forces an inference. One mechanism, both halves: a subagent calls
-- `agent.turn` itself; the main turn runs here.
--
-- The handler owns the *whole* turn, tool loop and conversation both:
--
--   while the model keeps asking for tools:
--     drive one request, drawing the stream
--     hand the assembled turn to the loop with `agent.await_tools(turn)`
--     extend `agent.history` with the round's results
--   return the final turn
--
-- **`agent.history` is the conversation.** Every message that joins it does so
-- through `agent.api.history_append`, which appends to the table and archives
-- to the log in one step — so "in the conversation" and "in the log" cannot
-- disagree, and a resumed session is seeded from the same records this turn
-- wrote. Nothing else may add a message: Rust holds no history to add one to.
--
-- Compaction is the one thing that is *not* an append: it assigns
-- `agent.history` a fresh list, because the messages it drops are already
-- archived and the summary replacing them must not be written twice. See §7 of
-- `init.lua` for the shipped policy.
--
-- What stays in Rust is the mechanics: the tool coroutines themselves — asks,
-- panels, Ctrl+C — and the panel archiving. The await is the seam: the handler
-- suspends on it, the loop runs the round exactly as it always has, and resumes
-- the handler with `{ results, stopped }`. Handler and tool coroutines never run
-- nested; the loop alternates them.
--
-- The event is a *request*, the third kind after "turn_completed" (a
-- notification) and "key" (a question): the return value is the answer. `ev.text`
-- is the user's line, or nil for a turn nobody asked for. The final turn comes
-- back as the assembled-turn table; an interrupted round comes back
-- `stopped = true`, and the handler ends the turn by returning the same
-- sentinel — everything about it is appended already, and returning the last
-- turn instead would append it twice.
--
-- What it draws is what the loop used to draw: reasoning streams into a
-- borderless "reasoning" block (dimmed), the answer into a "response" block —
-- fresh panels *each round*, so one round's stream never flows into the last
-- round's block. Those titles are not decoration — `is_borderless_box` in the
-- panel renderer matches on them, which is what keeps a panel-driven block
-- looking exactly like a loop-driven one. Panels drawn here are *not* archived
-- to the log (the loop drains the turn's sink without logging it): on resume,
-- reasoning is reconstructed from the archived reasoning records and the answer
-- from the assistant message, as it always was.

local M = {}

---Suspend until the loop has run this turn's tool round, then answer with
---`{ results = { { id, content }, … }, stopped = bool }`. The yield carries
---the assembled turn so the loop knows what it is about to run. Only the `turn`
---handler may call this: anywhere else there is no round to run.
local function await_tools(turn)
  return coroutine.yield({ __agent_await = "tools", turn = turn })
end
agent.await_tools = await_tools

---Append the turn's own words to the conversation, in the protocol's order:
---the text first, then the calls. They are one turn the model produced
---together, and the calls message carries `content: null` — so they are two
---messages, and the protocol only accepts them in this order:
---
---    assistant: "I'll start by looking at the README."
---    assistant: tool_calls=[read(README), read(Makefile)]
---    tool: …        <- one per call, immediately after
---
---The other order puts an assistant message *between* a call and its answers —
---the model's next turn arriving before the group it opened has been answered,
---which a server rejects (`400 incomplete_parallel_tool_calls`).
local function append_turn(history, turn)
  if turn.content ~= "" then
    agent.api.history_append({ role = "assistant", content = turn.content })
  end
  if #turn.tool_calls > 0 then
    -- `function` is a Lua keyword, so the wire shape spells it with brackets.
    local calls = {}
    for i, c in ipairs(turn.tool_calls) do
      calls[i] = {
        id = c.id,
        type = "function",
        ["function"] = { name = c.name, arguments = c.arguments },
      }
    end
    agent.api.history_append({ role = "assistant", tool_calls = calls })
  end
end

---Drive the whole turn on `agent.history` and return the final assembled turn.
---`ev.text` is the user's line (nil for a forced turn), and it enters the
---conversation here — the loop only echoed it to the transcript.
function M.turn(ev)
  local text = (type(ev) == "table") and ev.text or nil
  if type(text) == "string" and text ~= "" then
    agent.api.history_append({ role = "user", content = text })
  end

  while true do
    -- The panels are created on the first chunk of their kind, each round: a
    -- model that answers without reasoning must not leave an empty dimmed block
    -- behind, and a round's blocks must come *after* the previous round's in the
    -- transcript, which "created on first use" gets for free.
    local reasoning, response
    local stream = agent.turn({ messages = agent.history })
    local turn = stream:run(function(e)
      if e.kind == "reasoning" and e.text ~= "" then
        reasoning = reasoning or agent.panel("reasoning")
        reasoning:append(e.text)
      elseif e.kind == "content" then
        response = response or agent.panel("response")
        response:append(e.text)
      end
    end)

    -- What the model said enters the conversation before anything else: the
    -- loop is about to run the calls, and a server rejects a request whose
    -- history has calls the model never announced.
    append_turn(agent.history, turn)

    if #turn.tool_calls == 0 then
      return turn
    end

    local round = await_tools(turn)
    -- Interrupted: the calls were run and answered, so the conversation is
    -- whole; passing the sentinel back tells the loop the turn is closed
    -- without appending the turn a second time.
    if round.stopped then
      return { stopped = true }
    end

    for _, r in ipairs(round.results) do
      agent.api.history_append({
        role = "tool",
        tool_call_id = r.id,
        content = r.content,
      })
    end
  end
end

agent.main_turn = M.turn