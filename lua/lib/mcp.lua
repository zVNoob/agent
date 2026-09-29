-- mcp.lua — the Model Context Protocol client (protocol only, in pure Lua).
--
-- `agent.mcp(name, func, opts)` opens a connection to an MCP server and returns
-- it ready to call: the handshake (initialize -> notifications/initialized ->
-- tools/list) has already happened, and every advertised tool is a callable
-- object on the connection. This module is that client; like every other module
-- in `lua/lib/` it publishes itself on `agent`, so `require("mcp")` and
-- `agent.mcp` are the same function.
--
-- The transport is injected, which is the whole point: `func(request_json,
-- on_streaming_response_json)` sends one serialized JSON-RPC request and
-- streams back the replies. It may be a stdio MCP server spawned with
-- `agent.bash`, an HTTPS endpoint reached through `agent.http` (which routes
-- itself to a request or an event stream), an in-process stub, or a test
-- mock — the protocol code never changes.
--
-- Registering a connection is one line, and the connection is the same shape a
-- hand-built one has (compare `lua/fs.lua`):
--
--     agent.mcps["my-server"] = agent.mcp("my-server", func)
--     local r = agent.mcps["my-server"].read({ path = "/etc/hostname" })
--     -- r = { ok, result, error, denied }
--
-- Nothing here touches the filesystem or the sandbox; the sandbox policy for
-- `func`-backed transports is the caller's business, stated as a local table
-- at the `agent.bash` call site (see `lua/lib/bash.lua`).
--
-- -- What an MCP tool call looks like ------------------------------------------
--
-- A tool call says nothing in the transcript: no arguments, no result, no
-- error. A tool is in charge of its own reporting, and a *local* tool can be —
-- it is Lua on this VM, so it calls `agent.panel` itself.
--
-- An MCP tool cannot be. Its code is on the other side of the wire, and nothing
-- of ours runs while `tools/call` is in flight, so there is no arrangement in
-- which it could ever draw. **So this module draws for it:** every wire call
-- gets a panel titled `{connection}.{tool}`, opened before the request so a
-- slow call is visibly in flight, filled with the result's text blocks, with
-- `notifications/progress` appended as they arrive.
--
--     agent.mcps.mine = agent.mcp("mine", func)                  -- draws
--     agent.mcps.mine = agent.mcp("mine", func, { draw = false }) -- silent
--
-- `draw = false` is the way to make an MCP call quiet, and it is exact: the
-- callopts then go through untouched, so the request on the wire is byte for
-- byte what it was, `_meta.progressToken` included.


agent.mcps = agent.mcps or {}

local function mcp_fail(msg, level)
  error("agent.mcp: " .. tostring(msg), level or 3)
end

-- Indented JSON, for the one place in this module that has to show a
-- structured value as text: a tool result carrying no text block. The bridge's
-- `json_encode` takes a value and nothing else, and a nested result on one
-- wrapped line is exactly the unreadable wall this is here to avoid — so this
-- is the small pretty-printer, not an option the primitive does not have.
--
-- A table is an array when its keys are exactly 1..n; anything else is an
-- object. `json_decode` cannot tell an empty `{}` from an empty `[]`, so an
-- empty table prints as `{}` — the only guess in here, and the harmless one.
-- Object keys are sorted so the same result always renders the same way.
local function json_pretty(value, indent)
  indent = indent or ""
  local t = type(value)
  if t == "nil" then return "null" end
  if t == "boolean" or t == "number" then return tostring(value) end
  if t == "string" then
    local ok, enc = pcall(agent.api.json_encode, value)
    return ok and enc or ('"' .. value .. '"')
  end
  if t ~= "table" then return tostring(value) end
  local count, max = 0, 0
  for k in pairs(value) do
    count = count + 1
    if type(k) == "number" and k >= 1 and k % 1 == 0 and k > max then max = k end
  end
  local is_array = count > 0 and max == count
  local inner, parts, i = indent .. "  ", {}, 0
  if is_array then
    for _, v in ipairs(value) do
      i = i + 1
      parts[i] = inner .. json_pretty(v, inner)
    end
  else
    for k, v in pairs(value) do
      i = i + 1
      local ok, kenc = pcall(agent.api.json_encode, tostring(k))
      parts[i] = inner .. (ok and kenc or tostring(k)) .. ": " .. json_pretty(v, inner)
    end
    table.sort(parts)
  end
  if i == 0 then return is_array and "[]" or "{}" end
  return (is_array and "[\n" or "{\n") .. table.concat(parts, ",\n")
         .. "\n" .. indent .. (is_array and "]" or "}")
end

-- Per-call streaming callbacks, validated where they are supplied. Hoisted out
-- of `conn:request` because the drawing path *rewrites* the callopts it is
-- given — and a rewrite must not launder a bad value past the check.
local function check_callopts(callopts)
  if callopts == nil then return end
  if type(callopts) ~= "table" then
    error("agent.mcp: callopts must be a table or nil, got " .. type(callopts), 2)
  end
  for _, k in ipairs({ "on_progress", "on_message" }) do
    local v = callopts[k]
    if v ~= nil and type(v) ~= "function" then
      error("agent.mcp: callopts." .. k .. " must be a function or nil, got " .. type(v), 2)
    end
  end
end

local function connect(name, func, opts)
  if type(name) ~= "string" then
    error("agent.mcp: name must be a string, got " .. type(name), 2)
  end
  if type(func) ~= "function" then
    error("agent.mcp: func must be a function(request_json, on_streaming_response_json), " ..
          "got " .. type(func), 2)
  end
  if opts == nil then
    opts = {}
  elseif type(opts) ~= "table" then
    error("agent.mcp: opts must be a table", 2)
  end
  if opts.protocolVersion ~= nil and type(opts.protocolVersion) ~= "string" then
    error("agent.mcp: opts.protocolVersion must be a string", 2)
  end
  if opts.draw ~= nil and type(opts.draw) ~= "boolean" then
    error("agent.mcp: opts.draw must be a boolean or nil", 2)
  end
  for _, k in ipairs({ "on_message", "on_badline", "on_close" }) do
    local v = opts[k]
    if v ~= nil and type(v) ~= "function" then
      error("agent.mcp: opts." .. k .. " must be a function or nil, got " .. type(v), 2)
    end
  end

  local conn = {
    name = name,
    func = func,
    opts = opts,
    id = 0,     -- next request id (sequential; correlation in Lua)
    tools = {}, -- toolname -> tool object
    alive = true,
  }

  -- The streaming-response dispatcher: decode one delivered JSON-RPC message
  -- and route it. Returns the message table when it is the pending response
  -- (id matches `pending_id`); otherwise nil — id-less messages are
  -- notifications, malformed text and stray ids go to opts.on_badline. During
  -- a request that carries `callopts` (per-call streaming), a
  -- `notifications/progress` message goes to callopts.on_progress and every
  -- other inbound notification goes to callopts.on_message — *winning* over
  -- the global opts.on_message for that round — so the round's stream is
  -- observable from the call site in order. Requests are strictly sequential,
  -- so any response whose id is not the pending one is a protocol violation.
  function conn:_ingest(text, pending_id, callopts)
    local ok, msg = pcall(agent.api.json_decode, text)
    if not ok then
      if self.opts.on_badline then self.opts.on_badline(text, msg) end
      return nil
    end
    if type(msg) ~= "table" or msg.jsonrpc ~= "2.0" then
      if self.opts.on_badline then
        self.opts.on_badline(text, "not a JSON-RPC message")
      end
      return nil
    end
    if msg.id ~= nil then
      if pending_id ~= nil and msg.id == pending_id then
        return msg
      end
      if self.opts.on_badline then
        self.opts.on_badline(text, "response for unknown id " .. tostring(msg.id))
      end
      return nil
    end
    if callopts ~= nil and callopts.on_progress ~= nil and
       msg.method == "notifications/progress" then
      callopts.on_progress(msg)
      return nil
    end
    if callopts ~= nil and callopts.on_message ~= nil then
      callopts.on_message(msg)
      return nil
    end
    if self.opts.on_message then self.opts.on_message(msg) end
    return nil
  end

  -- JSON-RPC request: send it through func once; the response settles the
  -- pending id via the streaming callback. Returns (response, err). func's
  -- own raise becomes a transport error and a returned-without-response
  -- round is a protocol error — both surface as (nil, err).
  --
  -- `callopts` (nil or { on_progress, on_message }) opts the round into
  -- *per-call streaming*: when on_progress is set the request params carry
  -- `_meta.progressToken` (MCP's progress opt-in); notifications streamed
  -- back during the round are routed to the per-call callbacks instead of
  -- the global opts.on_message. Params are shallow-copied on the way through
  -- — the caller's table is never mutated.
  function conn:request(method, params, callopts)
    if not self.alive then return nil, "connection '" .. self.name .. "' is closed" end
    check_callopts(callopts)
    self.id = self.id + 1
    local id = self.id
    local pbody = params or {}
    if callopts ~= nil and callopts.on_progress ~= nil then
      pbody = {}
      for k, v in pairs(params or {}) do pbody[k] = v end
      local meta = {}
      if type(pbody._meta) == "table" then
        for k, v in pairs(pbody._meta) do meta[k] = v end
      end
      meta.progressToken = "agent-" .. id
      pbody._meta = meta
    end
    local ok_enc, enc = pcall(agent.api.json_encode,
                              { jsonrpc = "2.0", id = id, method = method, params = pbody })
    if not ok_enc then return nil, "cannot encode request: " .. tostring(enc) end
    local resolved
    local ok_call, terr = pcall(self.func, enc, function(text)
      local hit = self:_ingest(text, id, callopts)
      if hit ~= nil then resolved = hit end
    end)
    if not ok_call then
      return nil, "transport error: " .. tostring(terr)
    end
    if resolved == nil then
      return nil, "no response for id " .. id ..
                  " (func returned without streaming the response)"
    end
    return resolved, nil
  end

  -- JSON-RPC notification: fire and forget — func still runs (it must carry
  -- the notification over the wire) and anything it streams back is
  -- dispatched; no response is expected.
  function conn:notify(method, params)
    if not self.alive then return false end
    local ok_enc, enc = pcall(agent.api.json_encode,
                              { jsonrpc = "2.0", method = method, params = params or {} })
    if not ok_enc then return false, "cannot encode notification: " .. tostring(enc) end
    local ok_call, terr = pcall(self.func, enc, function(text)
      conn:_ingest(text, nil)
    end)
    if not ok_call then return false, "transport error: " .. tostring(terr) end
    return true
  end

  -- End the connection: mark it dead, give the transport a chance to release
  -- its resources (opts.on_close), and unregister from `agent.mcps`.
  function conn:close()
    if self.alive then
      self.alive = false
      if self.opts.on_close then self.opts.on_close() end
    end
    if agent.mcps[self.name] == self then agent.mcps[self.name] = nil end
  end

  -- Hard stop (no opts.on_close): a dead connection fails subsequent calls.
  function conn:kill()
    self.alive = false
    if agent.mcps[self.name] == self then agent.mcps[self.name] = nil end
  end

  -- The panel an MCP tool call draws for itself.
  --
  -- A local tool calls `agent.panel` directly, because it is Lua running on
  -- this VM. An MCP tool cannot: its code is on the other side of the wire, and
  -- nothing of ours runs while `tools/call` is in flight. So with a tool call
  -- saying nothing by itself, an MCP call would be *permanently* invisible —
  -- there is no arrangement in which it could ever report. The connection
  -- therefore draws on the tool's behalf: the same panel a local tool gets by
  -- asking for one, arrived at from the other direction.
  --
  -- `{ draw = false }` on the connection opts out. That escape hatch is the
  -- point rather than an afterthought — a tool call is silent by default now,
  -- so without it there would be no way to make an MCP call quiet too.
  local function draw_call(tname)
    if opts.draw == false then return nil end
    -- Titled the way tools are named everywhere else, `{connection}.{tool}`.
    local p = agent.panel(conn.name .. "." .. tname, { boxed = true })
    local self = {}
    -- Every append is guarded: a panel is a convenience, and a tool call that
    -- loses its panel must not lose its result with it. Same reasoning as
    -- `lua/bash_tool.lua`.
    function self:say(text)
      if text == nil or text == "" then return end
      pcall(function() p:append(tostring(text) .. "\n") end)
    end
    -- `notifications/progress`, appended as it arrives so a slow call is
    -- visibly slow rather than apparently hung. Servers send these only because
    -- `on_progress` below puts `_meta.progressToken` in the request.
    function self:progress(msg)
      local params = (type(msg) == "table" and msg.params) or nil
      if type(params) ~= "table" then return end
      local text = params.message
      if type(text) ~= "string" or text == "" then
        if params.progress == nil then return end
        text = tostring(params.progress)
        if params.total ~= nil then text = text .. "/" .. tostring(params.total) end
      end
      self:say(text)
    end
    return self
  end

  -- The text of an MCP tool result. Servers answer with
  -- `{ content = [ { type = "text", text = "…" }, … ] }`, and the text is the
  -- point; the envelope around it is not. A result carrying no text block at
  -- all is shown as indented JSON instead, so nothing is ever reduced to
  -- nothing.
  --
  -- A result *mixing* text and non-text blocks shows the text and drops the
  -- rest. An image or an embedded resource has no text form, and printing its
  -- JSON into the middle of prose is the noise this exists to avoid — a real
  -- loss, and a deliberate one. Say so here rather than discovering it later.
  local function result_text(result)
    if type(result) ~= "table" then return tostring(result) end
    if type(result.content) == "table" then
      local out, n = {}, 0
      for _, block in ipairs(result.content) do
        if type(block) == "table" and block.type == "text"
           and type(block.text) == "string" then
          n = n + 1
          out[n] = block.text
        end
      end
      if n > 0 then return table.concat(out, "\n") end
    end
    return json_pretty(result)
  end

  -- Single tool-invocation path, shared by the callable tool object and the
  -- public conn:invoke streaming entry point. `callopts` (nil or
  -- { on_progress, on_message }) forward to conn:request for per-call
  -- streaming; policy/callback handling is identical for both routes.
  local function invoke_tool(tname, args, callopts)
    local tool = conn.tools[tname]
    if tool == nil then
      return { ok = false, error = "unknown tool '" .. tostring(tname) .. "'" }
    end
    -- Only a tool that goes over the wire gets a panel. One with a Lua
    -- `callback` is running here and can ask for its own, and drawing for it
    -- would be the double output this is meant to prevent.
    local panel = nil
    if tool.callback == nil then panel = draw_call(tname) end
    if tool.policy ~= nil then
      if type(tool.policy) ~= "function" then
        return { ok = false, denied = true,
                 error = "tool policy for '" .. tname .. "' is a " .. type(tool.policy) }
      end
      local verdict = tool.policy(args)
      if type(verdict) ~= "boolean" then
        return { ok = false, denied = true,
                 error = "tool policy for '" .. tname .. "' must return a boolean" }
      end
      if not verdict then
        -- The user's own refusal, reported in the call's panel: a tool call is
        -- silent otherwise, and a refusal with no trace is the one failure the
        -- user caused rather than discovered.
        if panel then panel:say("denied by policy") end
        return { ok = false, denied = true,
                 error = "tool call to '" .. tname .. "' denied by policy" }
      end
    end
    if tool.callback ~= nil then
      local r = tool.callback(args)
      if r == false then
        return { ok = false, denied = true,
                 error = "tool call to '" .. tname .. "' stopped by callback" }
      end
      return { ok = true, result = r, denied = false }
    end
    if not conn.alive then
      if panel then panel:say("connection '" .. conn.name .. "' is closed") end
      return { ok = false, error = "connection '" .. conn.name .. "' is closed" }
    end
    -- Per-round streaming, *chained* rather than replaced: a caller that passed
    -- its own callbacks still gets them, and the panel gets the same stream.
    -- Setting `on_progress` is also what puts `_meta.progressToken` in the
    -- request — MCP's opt-in, so the server is being asked for progress it is
    -- free to ignore. With `draw = false` the callopts go through untouched and
    -- the bytes on the wire are exactly what they were.
    local streaming = callopts
    if panel then
      -- The rewrite below would hide a bad `on_progress` behind a real
      -- function, deferring the error to whenever a progress notification
      -- happened to arrive — after the call was already half over the wire.
      -- Checked here so the contract holds on this path too.
      check_callopts(callopts)
      streaming = {
        on_progress = function(msg)
          if callopts and callopts.on_progress then callopts.on_progress(msg) end
          panel:progress(msg)
        end,
        on_message = callopts and callopts.on_message or nil,
      }
    end
    local resp, err = conn:request("tools/call",
                                   { name = tname, arguments = args or {} },
                                   streaming)
    if err then
      if panel then panel:say("error: " .. tostring(err)) end
      return { ok = false, error = err }
    end
    if resp.error ~= nil then
      if panel then panel:say("error: " .. json_pretty(resp.error)) end
      return { ok = false, error = resp.error }
    end
    if panel then
      -- `isError` is how MCP says a tool failed while the call itself
      -- succeeded, and a real server puts only a generic sentence in the
      -- content ("Error executing tool boom") — the actual reason goes
      -- elsewhere. Left unmarked, a failed call renders exactly like a
      -- successful one, which is the one thing this panel must not do: the
      -- model still gets the untouched result either way.
      local failed = type(resp.result) == "table" and resp.result.isError
      panel:say((failed and "error: " or "") .. result_text(resp.result))
    end
    return { ok = true, result = resp.result, denied = false }
  end

  -- Public streaming tool-call entry point: same shape as `tool(args)`, with
  -- per-round streaming callbacks — `conn:invoke(name, args, callopts)`.
  -- A tool named "invoke" would shadow this method, because `conn` is a table
  -- holding the tools and a metatable whose `__index` is this function.
  function conn:invoke(tname, args, callopts)
    return invoke_tool(tname, args, callopts)
  end

  -- Tool object constructor: a *callable table* with the fields documented
  -- above. LuaJIT (unlike Lua 5.1) rejects setting fields on function
  -- values, so the tool is a table whose `__call` metamethod invokes it.
  local function make_tool(info)
    local tname = info.name
    local tool = {}
    tool.signature = info.inputSchema
    tool.description = info.description
    tool.callback = nil
    tool.policy = nil
    setmetatable(tool, { __call = function(_, args) return conn:invoke(tname, args) end })
    return tool
  end

  -- Handshake: initialize -> notifications/initialized -> tools/list.
  local init, ierr = conn:request("initialize", {
    protocolVersion = opts.protocolVersion or "2025-03-26",
    capabilities = {},
    clientInfo = { name = "agent", version = "0.1.0" },
  })
  if ierr then mcp_fail("initialize for '" .. name .. "' failed: " .. ierr) end
  if init.error ~= nil then
    mcp_fail("initialize for '" .. name .. "' errored: " ..
             tostring(init.error.message or init.error))
  end
  conn:notify("notifications/initialized", {})
  conn.serverInfo = (init.result and init.result.serverInfo) or nil
  conn.protocolVersion = (init.result and init.result.protocolVersion) or nil

  local list, lerr = conn:request("tools/list", {})
  if lerr then mcp_fail("tools/list for '" .. name .. "' failed: " .. lerr) end
  if list.error ~= nil then
    mcp_fail("tools/list for '" .. name .. "' errored: " ..
             tostring(list.error.message or list.error))
  end
  local tools = (list.result and list.result.tools) or {}
  for _, info in ipairs(tools) do
    local tname = info.name
    local tool = make_tool(info)
    conn.tools[tname] = tool
    conn[tname] = tool -- agent.mcps[name][tname] direct access
  end

  return conn
end

-- The lib-module convention: publish on `agent`, so `agent.mcp` and
-- `require("mcp")` are the same function.
agent.mcp = connect

return connect
