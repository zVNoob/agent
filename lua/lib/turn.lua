-- turn.lua — `agent.turn(opts)`: one model request as a drivable stream.
--
-- The friendly half of the nested-turn substrate (`agent.api.turn`). The bridge
-- primitive takes everything as arguments; this route is where defaults live, and
-- whose defaults they are is decided *here*, not inside a primitive that would then
-- be a second source of truth next to `agent.llm`.
--
--   local s = agent.turn({ messages = { … } })
--   local result = s:run(function(ev) … draw each event into a panel … end)
--   -- result = { content = "...", reasoning = "...",
--   --            tool_calls = { { id, name, arguments }, … },
--   --            usage = { prompt = n, completion = n }, timings = {...} }
--
-- (`s:iter()` is the lower-level shape — one event per iteration, terminal event
-- as the iterator's second return — for a caller that needs the loop, not the
-- accumulation.)
--
-- What it is for: running a conversation *off to the side* — a subagent, a
-- summarizer, a reviewer — on its own messages, its own tools, its own model, without
-- touching the main turn's history. The tool loop is *not* here: this route makes a
-- request and assembles the answer. "The model asked for a tool, run it, ask again"
-- is the caller's loop to write, and that is deliberate — it is the part that decides
-- what a subagent may do, and it should be Lua you can read.
--
-- ## Params and where they come from
--
-- Everything optional but `messages`. Omitted fields are read from the conventions,
-- **in this order and no other**, so there is exactly one answer to "whose
-- credentials?":
--
--   model     -> opts.model, else agent.llm.model
--   base_url  -> opts.base_url, else agent.llm.base_url
--   api_key   -> opts.api_key, else agent.llm.api_key
--   system    -> opts.system (prepend a system message), else agent.llm.system_prompt
--                when the caller did not supply a `system` entry at all
--   tools     -> opts.tools (flat shape, see below), else the active `agent.mcps`
--
-- `agent.llm` and `agent.mcps` are *conventions* — tables the configuration owns, and
-- read only when they exist. A missing one is not an error here: `model`/`base_url`
-- missing and un-overridable is the bridge's error to give, because it is the one
-- that actually needs them.
--
-- ## The tools shape
--
-- `opts.tools` is the bridge's flat shape: `{ name, description, parameters? }` —
-- and `description` is **required**, because it is how the model knows it may call
-- the tool. When omitted, the tools come from `agent.mcps` and are flattened from the
-- registry's connection shape for you: each `conn.tool` becomes
-- `{ name = "conn.tool", description, parameters = tool.signature }`, so a subagent
-- on the same model gets the same tool *names* the main turn advertises.

local M = {}

-- conn.tool, the same qualification the main turn's request uses (`split_qualified`
-- in the Rust registry reads it back by the same rule).
local function qualified(conn, name) return conn .. "." .. name end

-- The flat tool list the bridge wants, from the registry's connection shape.
local function tools_from_registry(mcps)
  local out = {}
  if type(mcps) ~= "table" then return out end
  for conn, c in pairs(mcps) do
    if type(c) == "table" and type(c.tools) == "table" then
      for name, tool in pairs(c.tools) do
        if type(tool) == "table" then
          out[#out + 1] = {
            name = qualified(conn, name),
            description = tool.description or "",
            parameters = tool.signature or { type = "object", properties = {} },
          }
        end
      end
    end
  end
  return out
end

local function resolve(opts)
  local llm = type(agent.llm) == "table" and agent.llm or nil
  local base_url = opts.base_url or (llm and llm.base_url)
  local api_key = opts.api_key or (llm and llm.api_key)
  local model = opts.model or (llm and llm.model)
  -- A system message: the caller's `system` wins, and *their* empty string silences
  -- the convention's prompt — "" and absent are different answers, so this looks at
  -- the key, not the value.
  local system = opts.system
  if system == nil then system = llm and llm.system_prompt end

  -- The conversation: the caller's `messages`, or — absent — `agent.history`,
  -- which is the main conversation. A subagent that owns its own transcript
  -- passes `messages` and never touches the history; the main turn passes
  -- nothing and gets the conversation it is part of.
  --
  -- Copied, not aliased: the bridge encodes it into the request immediately, and
  -- a caller mid-turn must be able to append the round's results afterwards
  -- without reaching into a table the request already used.
  local messages = opts.messages
  if messages == nil then messages = agent.history end
  if type(messages) ~= "table" then
    error(
      "agent.turn: `messages` must be an array of OpenAI messages " ..
      "(absent means agent.history, which is not a table)",
      2
    )
  end
  local copy = {}
  for i, m in ipairs(messages) do copy[i] = m end
  messages = copy
  if system ~= nil and system ~= "" then
    local with_system = { { role = "system", content = system } }
    for i, m in ipairs(messages) do with_system[i + 1] = m end
    messages = with_system
  end

  local tools = opts.tools
  if tools == nil then
    tools = tools_from_registry(agent.mcps)
  else
    -- The caller supplied the flat shape; it goes through untouched, so the
    -- bridge's own error — a nameless or undescribed tool — reaches them verbatim.
  end

  return base_url, api_key, model, messages, tools
end

---agent.turn(opts) -> a turn stream object
function M.turn(opts)
  local base_url, api_key, model, messages, tools = resolve(opts or {})
  local handle = agent.api.turn(base_url or "", api_key or "", model or "", messages, tools)

  local s = { handle = handle }

  ---The next event, or nil when nothing has arrived. The caller waits on
  ---`agent.on_timeout` between steps, as every pump in the tree does.
  function s:step()
    return agent.api.turn_step(self.handle)
  end

  ---Iterate events until the stream ends: `for ev in s:iter() do ... end`. Each
  ---iteration is one event (content, reasoning, tool_call, usage, timings), and the
  ---loop ends on done or error, which :run() also returns.
  function s:iter()
    return function()
      local ev = self:step()
      if ev == nil then
        agent.on_timeout(5)
        return false -- not nil: the iterator must not stop on "nothing yet"
      end
      if ev.kind == "done" or ev.kind == "error" then
        return nil, ev
      end
      return ev
    end
  end

  ---Drive the stream to its terminal event and return the assembled turn.
  ---`draw`, when given, sees each non-terminal event as it arrives (content,
  ---reasoning, tool_call, usage, timings) — the main-loop handler draws the
  ---stream live through it. The accumulation itself is done by Rust
  ---(`TurnBuilder`), so the route does not grow a second one.
  function s:run(draw)
    while true do
      local ev = self:step()
      if ev == nil then
        agent.on_timeout(5)
      elseif ev.kind == "done" then
        return {
          content = ev.content or "",
          reasoning = ev.reasoning or "",
          tool_calls = ev.tool_calls or {},
          usage = ev.usage,
          timings = ev.timings,
        }
      elseif ev.kind == "error" then
        error("agent.turn: " .. tostring(ev.message), 0)
      elseif draw then
        draw(ev)
      end
    end
  end

  ---Abort the request and drop the queue. Prompt: the task notices before its next
  ---event, so this does not wait out a running timeout.
  function s:close()
    agent.api.turn_close(self.handle)
  end

  return s
end

agent.turn = M.turn
