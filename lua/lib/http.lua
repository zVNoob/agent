-- http.lua — the HTTP(S) transport: one `agent.http` that routes itself.
--
-- Rust (src/mcp.rs) owns TLS, HTTP framing and the transport threads; Lua
-- pumps the buffered event queues and fans them out to callbacks. What used
-- to be two interfaces (`agent.http` and `agent.sse`) is one, and the route is
-- chosen for you:
--
--   local s = agent.http("POST", "https://…/mcp", {
--     body    = '{"jsonrpc":"2.0","id":1,"method":"initialize"}',
--     headers = { ["content-type"] = "application/json" },
--     on_chunk  = function(c) ... end,   -- response body, streamed as it arrives
--     on_event  = function(ev, data) ... end, -- decoded SSE events (optional)
--     on_done   = function(o) ... end,   -- o = { status = <int>, headers = {...} }
--     on_error  = function(e, status) ... end,
--   })
--   s:run()   -- drive to completion; returns the stream object
--   s:close() -- abort + release
--
-- ## How the route is chosen
--
-- 1. **No request, events wanted** — `on_event` set and no body/method to
--    speak of (a plain `GET`, or `method = "STREAM"`) opens a Server-Sent-Events
--    *stream* over `agent.api.sse_*`: Rust parses the frames and each one
--    arrives at `on_event`.
-- 2. **Otherwise a request** goes out over `agent.api.http_req` and the body
--    streams to `on_chunk`.
-- 3. **The response can still upgrade itself.** When the response headers say
--    `content-type: text/event-stream` and you asked for `on_event`, the body
--    is not treated as an opaque byte stream: it is fed through the SSE frame
--    parser below and each event is delivered to `on_event(event, data)`. This
--    is the MCP streamable-HTTP case — one POST endpoint that answers with
--    either JSON or an event stream, and the client must handle both without
--    knowing in advance. `on_chunk` still sees the raw bytes, so a caller can
--    watch both.
--
-- `opts.sse` overrides the decision: `false` forces a request, `true` forces
-- the stream transport.
--
-- A non-2xx status is **not** a transport error: the status arrives in
-- `on_done` (as `o.status`) and the body still streams; `on_error` fires only
-- for transport-level failures (unreachable host, timeout, ...). Requests carry
-- an overall timeout (`opts.timeout_ms`, default 30000; `0` disables it).

local M = {}

-- The idle slice between transport polls: the event loop's turn while a long
-- response streams. ~50Hz, one timer poke per frame worst case.
local CADENCE_MS = 20

-- ==========================================================================
-- SSE frame parsing (only for a request whose *response* is an event stream;
-- the stream transport's own parser lives in Rust).
--
-- A frame is a run of `field: value` lines ended by a blank line; `data:`
-- lines accumulate with newlines, `event:` names the event, `:` starts a
-- comment, and an unterminated trailing frame is held until it completes.
-- ==========================================================================

local function new_parser()
  return { event = nil, data = {}, len = 0 }
end

-- Feed one body chunk; returns the events it completed, in order.
local function parser_push(p, chunk)
  local out = {}
  local function dispatch()
    if p.len == 0 then
      p.event = nil
      return
    end
    out[#out + 1] = { event = p.event, data = table.concat(p.data, "\n") }
    p.event = nil
    p.data = {}
    p.len = 0
  end
  p.buffer = (p.buffer or "") .. chunk
  while true do
    local nl = p.buffer:find("\n", 1, true)
    if not nl then return out end
    local line = p.buffer:sub(1, nl - 1)
    p.buffer = p.buffer:sub(nl + 1)
    if line:sub(-1) == "\r" then line = line:sub(1, -2) end
    if line == "" then
      dispatch()
    elseif line:sub(1, 1) == ":" then
      -- comment / keep-alive
    else
      local field, value = line:match("^([^:]*):?(.*)$")
      if field == "event" then
        p.event = (value:gsub("^ ", ""))
      elseif field == "data" then
        p.data[#p.data + 1] = (value:gsub("^ ", ""))
        p.len = p.len + 1
      end
      -- id / retry and unknown fields are accepted and ignored
    end
  end
end

-- The frame still being built when the body ended, if any.
local function parser_flush(p)
  if p.buffer ~= nil and p.buffer ~= "" then
    p.buffer = p.buffer .. "\n"
    return parser_push(p, "")
  end
  return {}
end

-- Is this response an event stream?
local function is_event_stream(headers)
  for name, value in pairs(headers or {}) do
    if type(name) == "string" and name:lower() == "content-type" then
      if type(value) == "string" and value:lower():find("text/event%-stream", 1, false) then
        return true
      end
    end
  end
  return false
end

-- ==========================================================================
-- The one interface
-- ==========================================================================

--- `agent.http(method, url, opts)` -> a stream object.
---
--- `method` may be `"GET"`, `"POST"`, ..., or `"STREAM"` (or nil) to open a
--- bare event stream. The object exposes `s:step()`, `s:run()`, `s:close()` and
--- the `status` / `headers` seen so far.
function M.http(method, url, opts)
  if type(method) ~= "string" then
    error("agent.http: method must be a string, got " .. type(method), 2)
  end
  if type(url) ~= "string" then
    error("agent.http: url must be a string, got " .. type(url), 2)
  end
  if not url:match("^https?://") then
    error("agent.http: url must be http(s)://, got '" .. url .. "'", 2)
  end
  if opts == nil then
    opts = {}
  elseif type(opts) ~= "table" then
    error("agent.http: opts must be a table", 2)
  end
  if opts.headers ~= nil and type(opts.headers) ~= "table" then
    error("agent.http: opts.headers must be a table", 2)
  end
  if opts.body ~= nil and type(opts.body) ~= "string" then
    error("agent.http: opts.body must be a string", 2)
  end
  if opts.timeout_ms ~= nil and type(opts.timeout_ms) ~= "number" then
    error("agent.http: opts.timeout_ms must be a number", 2)
  end
  for _, k in ipairs({ "on_chunk", "on_event", "on_done", "on_error" }) do
    local v = opts[k]
    if v ~= nil and type(v) ~= "function" then
      error("agent.http: opts." .. k .. " must be a function or nil, got " .. type(v), 2)
    end
  end

  local self = {
    on_chunk = opts.on_chunk,
    on_event = opts.on_event,
    on_done = opts.on_done,
    on_error = opts.on_error,
    status = nil,
    headers = nil,
    error = nil,
    done = false,
    events = 0,
  }

  -- Route: a bare event stream (no body, events wanted) takes the SSE
  -- transport; everything else is a request, which may still upgrade itself
  -- when the response turns out to be an event stream.
  local wants_events = opts.on_event ~= nil
  local stream_route = opts.sse
  if stream_route == nil then
    stream_route = wants_events and (opts.body == nil or method == "STREAM")
  end
  self.route = stream_route and "stream" or "request"

  local function deliver(event_name, data)
    self.events = self.events + 1
    if self.on_event then self.on_event(event_name, data) end
  end

  -- Drive to completion, handing the event loop a slice between polls (both
  -- routes share it; only `step` differs).
  function self:run()
    while not self.done do
      self:step()
      if not self.done then agent.on_timeout(CADENCE_MS) end
    end
    return self
  end

  if self.route == "stream" then
    self.handle = agent.api.sse_open(url, opts.headers or {})
    function self:step()
      while true do
        local ev = agent.api.sse_step(self.handle)
        if ev == nil then return end
        if ev.kind == "event" then
          deliver(ev.event, ev.data)
        elseif ev.kind == "done" then
          self.done = true
          if self.on_done then
            self.on_done({ status = self.status, headers = self.headers,
                          events = self.events })
          end
          return
        elseif ev.kind == "error" then
          self.done = true
          self.error = ev.message
          if self.on_error then self.on_error(ev.message, self.status) end
          return
        end
      end
    end
    function self:close()
      if self.handle ~= nil then
        agent.api.sse_close(self.handle)
        self.handle = nil
      end
    end
    return self
  end

  -- The request route.
  self.handle = agent.api.http_req(method, url, opts.headers or {}, opts.body or "",
                                   opts.timeout_ms or 30000)
  self.parser = new_parser()

  function self:step()
    while true do
      local ev = agent.api.http_step(self.handle)
      if ev == nil then return end
      if ev.kind == "headers" then
        self.status = ev.status
        self.headers = ev.headers
        -- The response may be an event stream: decide once, here, where the
        -- content-type is known.
        self.event_stream = self.on_event ~= nil and is_event_stream(ev.headers)
      elseif ev.kind == "chunk" then
        if self.on_chunk then self.on_chunk(ev.data) end
        if self.event_stream then
          for _, e in ipairs(parser_push(self.parser, ev.data)) do deliver(e.event, e.data) end
        end
      elseif ev.kind == "done" then
        if self.event_stream then
          for _, e in ipairs(parser_flush(self.parser)) do deliver(e.event, e.data) end
        end
        self.done = true
        if self.on_done then
            self.on_done({ status = self.status, headers = self.headers,
                          events = self.events })
          end
        return
      elseif ev.kind == "error" then
        self.done = true
        self.error = ev.message
        if self.on_error then self.on_error(ev.message, self.status) end
        return
      end
    end
  end

  function self:close()
    if self.handle ~= nil then
      agent.api.http_close(self.handle)
      self.handle = nil
    end
  end

  return self
end

-- The lib-module convention: publish on `agent`. There is no `agent.sse`
-- anymore — `agent.http` routes itself.
agent.http = M.http

return M
