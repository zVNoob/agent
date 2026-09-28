-- api.lua — annotations for `agent.api`, the Rust↔Lua bridge.
--
-- `agent.api` is the substrate: every primitive Rust exposes to Lua, under its
-- bare name, in one **read-only** table. The friendly API is built on top of
-- it (`agent.bash`, `agent.panel`, `agent.mcp`, `agent.http`, …) — prefer those;
-- reach for the bridge when you are writing something at that level, like a tool
-- that has to block on the user (`ask_user`).
--
-- This file documents that surface. The entry script (`lua/init.lua`) requires
-- it and publishes the result as `agent.api_docs`, and the loader refuses to
-- build a VM when the two disagree — a primitive without an entry here, or an
-- entry naming a primitive that no longer exists, is a startup error, not
-- folklore:
--
--   for name, entry in pairs(agent.api_docs) do
--     print(name, entry.summary)
--     for _, arg in ipairs(entry.args or {}) do print("  ", arg.name, arg.doc) end
--   end
--
-- Each entry is:
--
--   summary  string   one line: what it does
--   args     table    ordered { { name, type, doc }, … } — nil when the call
--                     takes no arguments
--   returns  string   what comes back
--   see      string   the friendly wrapper to use instead, when there is one
--
-- Conventions shared by every entry: the sandbox handle is an opaque userdata
-- you only pass back to `step` / `decide` / `kill` / `write` / `close_stdin` (its
-- destructor SIGKILLs the tree); a `policy` argument is the seccomp table
-- described in `agent.bash`; and JSON boundary values follow the mapping in
-- `json_encode` below.

return {
  -- ===================== the sandbox engine ==============================

  spawn = {
    summary = "Spawn a sandboxed `bash -c <cmdline>` and return its handle.",
    args = {
      { "cmdline", "string", "the command line, run as `bash -c`" },
      { "mask", "table|nil", "syscall names to trap; nil traps nothing" },
    },
    returns = "handle (userdata) for step/decide/diag/kill/write/close_stdin",
    see = "agent.bash",
  },

  step = {
    summary = "Advance the run by one non-blocking step and report what happened.",
    args = {
      { "handle", "handle", "a live sandbox handle" },
    },
    returns = "{ kind = \"output\"|\"blocked\"|\"idle\"|\"finished\", ... }",
    see = "the pump loop inside agent.bash (s.pump / s:run)",
  },

  decide = {
    summary = "Answer the syscall the run is blocked on.",
    args = {
      { "handle", "handle", "a handle blocked on a syscall" },
      { "allow", "boolean", "true allows it, false denies it" },
    },
    returns = "nothing (raises when the run is not blocked)",
  },

  kill = {
    summary = "SIGKILL the whole process tree and release the handle.",
    args = {
      { "handle", "handle", "a live sandbox handle" },
    },
    returns = "nothing",
    see = "s:kill() on the stream object",
  },

  write = {
    summary = "Feed bytes to the tracee's stdin (non-blocking, queued).",
    args = {
      { "handle", "handle", "a live sandbox handle" },
      { "data", "string", "bytes to write" },
    },
    returns = "nothing",
    see = "s:write_stdin(data)",
  },

  close_stdin = {
    summary = "Send EOF on the tracee's stdin.",
    args = {
      { "handle", "handle", "a live sandbox handle" },
    },
    returns = "nothing",
    see = "s:close_stdin()",
  },

  -- ===================== the agent loop ==============================

  trigger = {
    summary = "Queue a command for the agent loop: run again, or replace the history.",
    args = {
      { "...", "any", "a string (as a user message) or an array of messages (a replacement history)" },
    },
    returns = "true when queued, false when no loop is attached",
    see = "agent.trigger",
  },

  -- ===================== asking the user ==============================

  ask_user = {
    summary = "Put a question to the user and block for the verdict.",
    args = {
      { "text", "string", "the question, shown as an overlay on the tool's panel" },
      { "always", "boolean|nil", "offer an \"always\" answer beside yes and no; true only when the question has something to remember (its `path`)" },
    },
    returns = "true (allowed), false (denied, no reason), a deny verdict carrying one, or an allow verdict that also asks the asking side to remember",
    see = "agent.ask (yield-based, for policies driven from the event loop)",
  },

  -- ===================== the conversation log ==============================

  memory_path = {
    summary = "Path of the open conversation log, or nil when none is open.",
    returns = "string|nil",
    see = "agent.memory.path()",
  },

  memory_append = {
    summary = "Append one message to the conversation log.",
    args = {
      { "message", "table|string", "a { role, content } table or its JSON text" },
    },
    returns = "the message's sequence number",
    see = "agent.memory.append(message)",
  },

  memory_latest = {
    summary = "The newest messages of the conversation log, as JSON strings.",
    args = {
      { "n", "number", "how many, newest last" },
    },
    returns = "array of JSON strings",
    see = "agent.memory.latest(n)",
  },

  memory_flush = {
    summary = "Seal the buffered messages now (harmless when nothing is open).",
    returns = "nothing",
    see = "agent.memory.flush()",
  },

  -- ===================== panels ==============================

  panel_create = {
    summary = "Create a panel and return its id.",
    args = {
      { "title", "string", "the panel's title" },
      { "opts", "table|nil", "{ boxed = bool, conceal_box = bool }" },
    },
    returns = "id (number)",
    see = "agent.panel(title, opts)",
  },

  panel_append = {
    summary = "Append text to a panel.",
    args = {
      { "id", "number", "a panel id" },
      { "text", "string", "the text to append" },
    },
    returns = "nothing",
    see = "p:append(text)",
  },

  panel_set = {
    summary = "Replace a panel's whole content.",
    args = {
      { "id", "number", "a panel id" },
      { "text", "string", "the new content" },
    },
    returns = "nothing",
  },

  panel_highlight = {
    summary = "Add a styled byte region to a panel's content.",
    args = {
      { "id", "number", "a panel id" },
      { "start", "number", "first byte (0-based)" },
      { "finish", "number", "end byte (exclusive)" },
      { "style", "string", "a style spec like \"bold\" or \"bold.cyan\"" },
    },
    returns = "nothing",
    see = "p:highlight(start, finish, style)",
  },

  panel_clear_regions = {
    summary = "Drop every styled region of a panel.",
    args = {
      { "id", "number", "a panel id" },
    },
    returns = "nothing",
    see = "p:clear_regions()",
  },

  panel_overlay = {
    summary = "Set or clear a panel's dialog: the ask seam, drawn at the \
      bottom of the panel's own box.",
    args = {
      { "id", "number", "a panel id" },
      { "text", "string", "the question; nil clears the dialog" },
      { "always", "boolean", "whether the answer is one to remember, which is \
        what offers [a]lways in the key prompt" },
    },
    returns = "nothing",
  },

  panel_split = {
    summary = "Create a panel with numbered side-by-side panes; returns its id.",
    args = {
      { "title", "string", "the panel's title" },
      { "panes", "table", "array of { text = string, lang = string|nil }" },
    },
    returns = "id (number)",
    see = "agent.split_panel(title, panes)",
  },

  panel_pane_set = {
    summary = "Replace one pane's content.",
    args = {
      { "id", "number", "a split panel's id" },
      { "pane", "number", "1-based pane number" },
      { "text", "string", "the new content" },
    },
    returns = "nothing",
    see = "p:set_pane(pane, text)",
  },

  panel_pane_lang = {
    summary = "Declare a pane's highlighting language (nil renders it plain).",
    args = {
      { "id", "number", "a split panel's id" },
      { "pane", "number", "1-based pane number" },
      { "lang", "string|nil", "a language name the highlighter knows" },
    },
    returns = "nothing",
    see = "p:set_pane_lang(pane, lang)",
  },

  panel_pane_highlight = {
    summary = "Add a styled byte region inside one pane.",
    args = {
      { "id", "number", "a split panel's id" },
      { "pane", "number", "1-based pane number" },
      { "start", "number", "first byte (0-based)" },
      { "finish", "number", "end byte (exclusive)" },
      { "style", "string", "a style spec like \"bold.green\"" },
    },
    returns = "nothing",
  },

  panel_pane_clear_regions = {
    summary = "Drop every styled region of one pane.",
    args = {
      { "id", "number", "a split panel's id" },
      { "pane", "number", "1-based pane number" },
    },
    returns = "nothing",
  },

  -- ===================== the JSON boundary ==============================

  json_encode = {
    summary = "Encode a Lua value as JSON text.",
    args = {
      { "value", "any", "the value to encode" },
    },
    returns = "string (the JSON text)",
    see = "the JSON-RPC framing inside agent.mcp",
  },

  json_decode = {
    summary = "Decode JSON text into a Lua value.",
    args = {
      { "text", "string", "the JSON text" },
    },
    returns = "the decoded value (nil for a JSON null)",
  },

  -- ===================== the HTTP(S) transport ==============================

  reverse_dns = {
    summary = "Reverse-resolve a literal IP address to a hostname.",
    args = {
      { "ip", "string", "a literal IPv4 or IPv6 address" },
    },
    returns = "hostname (string) or nil when the address has no name",
    see = "agent.seccomp.host_of(sys) — the name a connect question shows",
  },

  http_req = {
    summary = "Start an HTTP(S) request; returns its transport handle.",
    args = {
      { "method", "string", "the HTTP method" },
      { "url", "string", "the absolute URL" },
      { "headers", "table|nil", "request headers" },
      { "body", "string|nil", "the request body" },
      { "timeout_ms", "number|nil", "overall timeout; 0 disables it" },
    },
    returns = "handle (userdata) for http_step / http_close",
    see = "agent.http(method, url, opts) — the request route",
  },

  http_step = {
    summary = "Poll an HTTP request for its next event (non-blocking).",
    args = {
      { "handle", "handle", "a request handle" },
    },
    returns = "{ kind = \"headers\"|\"chunk\"|\"done\"|\"error\", ... } or nil",
  },

  http_close = {
    summary = "Abort an HTTP request and release its handle.",
    args = {
      { "handle", "handle", "a request handle" },
    },
    returns = "nothing",
  },

  sse_open = {
    summary = "Open an SSE stream; returns its transport handle.",
    args = {
      { "url", "string", "the absolute URL" },
      { "headers", "table|nil", "request headers" },
    },
    returns = "handle (userdata) for sse_step / sse_close",
    see = "agent.http(url, { on_event = fn }) — the stream route",
  },

  sse_step = {
    summary = "Poll an SSE stream for its next event (non-blocking).",
    args = {
      { "handle", "handle", "a stream handle" },
    },
    returns = "{ kind = \"event\"|\"done\"|\"error\", ... } or nil",
  },

  sse_close = {
    summary = "Abort an SSE stream and release its handle.",
    args = {
      { "handle", "handle", "a stream handle" },
    },
    returns = "nothing",
  },

  -- ===================== timers ==============================

  sleep = {
    summary = "Block the current thread for ms milliseconds.",
    args = {
      { "ms", "number", "how long to sleep; <= 0 returns immediately" },
    },
    returns = "nothing",
    see = "agent.on_timeout(ms, fn)",
  },
}
