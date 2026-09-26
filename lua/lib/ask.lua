-- ask.lua — asking the user from a policy, in one call, and remembering the
-- answer.
--
-- A sandbox policy decides syscalls. Sometimes the right answer is not knowable
-- from the call alone — a write to a config file, an outbound call — so a
-- policy *asks*, the question reaches the user, and their yes/no becomes the
-- verdict. That round trip is a coroutine yield, and the raw protocol is four
-- things a policy author had to know:
--
--   1. the ask is `coroutine.yield(<anything>)`, which only works because the
--      policy callback runs in its own coroutine;
--   2. the shape `{ description = "…" }` is a convention — nothing enforces
--      it, and only the built-in handler knows to read `.description`;
--   3. what comes back must be a boolean or a verdict object, or the run dies;
--   4. an ask with no handler *raises* (plain context) or silently denies
--      (a background handler) — context you usually do not control.
--
-- This module owns all four. One call asks, and answers with a verdict the
-- driver accepts, reason included:
--
--   local sc, ask = agent.seccomp, agent.ask
--
--   policy.openat = function(sys)
--     local flags = sc.arg(sys, "openat")
--     if sc.is_tty_probe(flags) then return true end
--     if sc.check("openat", flags, "WRITE") then
--       return ask(ask.for_syscall(sys, "write", sc.describes("openat", flags)))
--     end
--     return true
--   end
--
-- `ask` returns `true` (allowed) or `agent.deny(reason)` (refused, and the
-- reason reaches the panel status line and the tool JSON exactly like a flat
-- policy denial does). The other entry points exist for the two ends of the
-- protocol:
--
--   ask.for_syscall(sys, "write", "O_RDWR")  -- the canonical ask
--   ask.of(verdict) -> allowed, reason        -- normalize any answer
--   ask.denied(verdict) -> boolean            -- just the yes/no
--   ask.drive(stream, handler?)               -- run it, never raise on a
--                                               forgotten handler (see below)
--   ask.ask_trust_read(path, "msg")           -- trusted? ask once, remember
--   ask.ask_trust_write(path, "msg")          -- ...the same, for a write
--
-- ## The no-handler case
--
-- The dangerous part of the raw protocol is #4: `stream:run()` with no
-- `on_ask` raises *mid-run*, after the sandbox has already spawned. Use
--
--   ask.drive(s)                 -- an unanswered ask denies and says so
--   ask.drive(s, my_handler)     -- ...or answer it yourself
--
-- and a forgotten handler becomes `denied_reason = "no ask handler: <the
-- question>"` on the result instead of an exception that takes the tree down.
-- `s:run()` itself is untouched: asking for the raise is still one call away.
--
-- ## Ask once, remember afterwards
--
-- A sandboxed command opens the same file over and over; asking about each open
-- is the difference between one question and twenty. Two trust tables hold what
-- the user has vouched for, and they answer two different questions:
--
--   agent.ask.trust("~/src/vendor")        -- may the agent be here at all?
--   agent.ask.trust_write("/tmp/scratch")  -- and may it *write* here?
--   agent.ask.is_trusted(p)                -- the general table only
--   agent.ask.is_write_trusted(p)          -- the write table only
--
-- `trust_write` records in **both** tables, because writing implies being
-- allowed to touch: a path you may write is a path you may touch. So a
-- write-only reader is the strictly narrower question, which is what makes the
-- narrow revocation worth having:
--
--   agent.ask.forget_write("/tmp/scratch") -- "you may write here" goes away
--   agent.ask.is_trusted("/tmp/scratch")   -- ...and "you may read here" stays
--   agent.ask.forget("/tmp/scratch")       -- forget takes back both
--
-- An ask that carries a `path` (which is what `ask.for_syscall` builds) is
-- answered from the table instead of the question, so a trusted path is silent
-- from then on.
--
-- The three of those steps compose into one call, for a policy that wants the
-- whole decision rather than the pieces:
--
--   policy.openat = function(sys)
--     local flags = sc.arg(sys, "openat")
--     if sc.is_tty_probe(flags) then return true end
--     if sc.check("openat", flags, "WRITE") then
--       return ask.ask_trust_write(sc.path(sys), sc.describes("openat", flags))
--     end
--     return true
--   end
--
-- `ask_trust_read` and `ask_trust_write` check, and ask if the answer is not
-- already known — with "always" on offer, and the path remembered *only* on
-- that answer. A plain yes is for this time; that is the difference between the
-- three answers, and the reason these two helpers exist rather than a bare
-- `ask`. Unlike `ask`, they raise the question *unconditionally* once the path is
-- not trusted, because "may I write here" is a narrower question than the one
-- `ask`'s own short-circuit answers ("may I be here at all"). A path trusted for
-- reading is therefore still asked about before it is written.
--
-- Trusting is otherwise the *handler's* call — when the user answers "always
-- allow this", the answer carries the instruction (`AskAnswer::AllowAndTrust` on
-- the Rust side) and the asking side does the recording, because it is the only
-- side that knows the path. An ask built from a bare string has no path to match
-- and is always asked.
--
-- Like every module in `lua/lib/`, this one publishes itself as `agent.ask`.

local M = {}

-- The path a syscall is about, or nil. Read at *call* time (never at load
-- time), so this module keeps no sibling upvalue — the same reason `denial`
-- below looks `agent.deny` up when it is called.
local function sc_path(sys)
  local sc = package.loaded["seccomp"] or agent.seccomp
  if type(sc) == "table" and type(sc.path) == "function" then
    local ok, path = pcall(sc.path, sys)
    if ok and type(path) == "string" and path ~= "" then return path end
  end
  return nil
end

-- ==========================================================================
-- Trust: two tables, one set of rules
--
-- `path -> { path = <absolute>, dir = <bool> }`. A *file* entry matches that one
-- path; a *dir* entry matches that path **and every file inside it** — so a file
-- under a trusted folder is trusted automatically, in whichever table the folder
-- was trusted in, without the tree being walked. That is what a directory entry
-- is for, and it is why `dir` is recorded rather than assumed: trusting a *file*
-- trusts only itself, and never reaches past it.
--
-- Matching is on the resolved absolute path, on a `/` boundary, so trusting
-- `/srv/app` does not trust `/srv/application`, and `/srv/app/x` does not
-- become a trust of `/srv/app/x` + `/srv/app/x/y` by accident.
--
-- `general` is what the user declared, or what an "always allow this" answer
-- recorded. `write` is the narrower one: paths vouched for *writing*. It is a
-- subset in practice — `trust_write` writes both — so each reader reads the one
-- table that answers its own question and nothing else: `is_trusted` asks
-- "trusted at all?", `is_write_trusted` asks "writable?".
--
-- The tables live on the agent's own VM, and a tool call runs *on* that VM (as
-- a coroutine the event loop drives, see `agent.ask.drive_tool`'s replacement
-- `ToolRun` in `src/lua.rs`), so a path trusted while answering one question is
-- remembered by every later call. They are still per *process*, not per session:
-- they do not outlive the agent, and `/reload` does not clear them (it reloads
-- the config on the same VM).
-- ==========================================================================
local trust_tables = {
  general = {},
  write = {},
}

-- The home directory, for a leading `~`.
local function home()
  local dir = os.getenv("HOME") or os.getenv("USERPROFILE")
  if type(dir) ~= "string" or dir == "" then
    error("agent.ask.trust: cannot expand '~' — neither $HOME nor $USERPROFILE is set", 3)
  end
  return (dir:gsub("/+$", ""))
end

-- The working directory relative paths resolve against.
local function cwd()
  -- $PWD is the shell's answer, and the agent never chdir's, so it is the
  -- process's directory in practice. There is no stdlib getcwd, and the other
  -- way to get one (`io.popen` — a shell) is not worth a shell.
  local dir = os.getenv("PWD")
  if type(dir) ~= "string" or dir == "" then
    error("agent.ask.trust: cannot resolve a relative path — $PWD is not set, " ..
          "so pass an absolute path or one starting with '~'", 3)
  end
  return (dir:gsub("/+$", ""))
end

-- Lexically resolve `.`, `..` and duplicate slashes. This is a *textual*
-- normalization: it does not follow symlinks, so a trusted path is trusted
-- under its own name rather than under whatever it points at.
local function tidy(path)
  local absolute = path:sub(1, 1) == "/"
  local parts = {}
  for piece in path:gmatch("[^/]+") do
    if piece == ".." then
      if #parts > 0 and parts[#parts] ~= ".." then
        parts[#parts] = nil
      elseif not absolute then
        parts[#parts + 1] = ".."
      end
    elseif piece ~= "." then
      parts[#parts + 1] = piece
    end
  end
  local joined = table.concat(parts, "/")
  if absolute then return "/" .. joined end
  return joined == "" and "." or joined
end

-- A user-supplied path as an absolute, tidied one: `~` expanded, relative
-- paths made absolute, `.`/`..` resolved.
local function resolve(path, who)
  local from = "agent.ask." .. (who or "trust")
  if type(path) ~= "string" or path == "" then
    error(from .. ": a path is required, got " .. type(path), 3)
  end
  if path == "~" then
    return tidy(home())
  elseif path:sub(1, 2) == "~/" then
    return tidy(home() .. path:sub(2))
  elseif path:sub(1, 1) ~= "/" then
    return tidy(cwd() .. "/" .. path)
  end
  return tidy(path)
end

-- Is `path` there at all? `os.rename(p, p)` is the stdlib's existence test:
-- POSIX makes it succeed when the path resolves to an existing entry, whatever
-- that entry is, and fail otherwise. (Cheap: one `rename`, no subprocess.)
local function exists(path)
  return os.rename(path, path) and true or false
end

-- Directory or file? `io.open` succeeds on a directory too, so it cannot answer
-- this alone — but *reading* from it cannot: `f:read(0)` returns the empty
-- string for a readable file and nil for a directory (the read fails with
-- EISDIR). An entry we cannot classify counts as a file, the narrow reading: an
-- exact-match rule trusts less than a subtree rule.
local function is_dir(path)
  local handle = io.open(path, "r")
  if not handle then return false end
  local zero = handle:read(0)
  handle:close()
  return zero == nil
end

-- Record `path` in one table. Returns the absolute path it resolved to, so a
-- caller can see what it actually trusted.
--
-- A path that is *not there* is trusted too, as a single file — which is not a
-- corner case but the point: the write a policy asks about is usually the
-- creation of the file, so the path is asked about precisely because it does
-- not exist yet. With nothing to look at, the narrow reading is the honest one;
-- a directory that does not exist yet is trusted by trusting its parent.
local function record(into, path)
  local full = resolve(path)
  into[full] = { path = full, dir = exists(full) and is_dir(full) }
  return full
end

-- Is `path` in this one table? Accepts the same shapes as `trust`, and does
-- not require the path to exist: it answers for the path as given, which is
-- what a policy callback holding a syscall's path needs.
local function in_one(into, path)
  if type(path) ~= "string" or path == "" then return false end
  local full = resolve(path)
  if into[full] then return true end
  for known, entry in pairs(into) do
    -- A directory trusts its subtree, on a `/` boundary — never a sibling whose
    -- name merely starts with it.
    if entry.dir and full:sub(1, #known + 1) == known .. "/" then
      return true
    end
  end
  return false
end

-- Remove `path` from one table. `true` when something was there.
local function drop(into, path)
  if type(path) ~= "string" or path == "" then return false end
  local full = resolve(path)
  if into[full] == nil then return false end
  into[full] = nil
  return true
end

-- One table, listed: `{ { path = ..., dir = ... }, … }`, sorted by path.
local function listing(into)
  local out = {}
  for _, entry in pairs(into) do
    out[#out + 1] = { path = entry.path, dir = entry.dir }
  end
  table.sort(out, function(a, b) return a.path < b.path end)
  return out
end

--- The path a caller *means*, as the one both sides of a trust comparison agree
--- on: `~` expanded, relative paths made absolute against the working
--- directory, `.`/`..` tidied. Useful on its own for showing the user which path
--- a question is really about before asking it.
---
--- Note what this does *not* do: it is a textual normalization, not a symlink
--- resolution, because the standard library cannot resolve one. So a path that is
--- a symlink resolves to itself, and is trusted under its own name.
function M.resolve(path)
  return resolve(path, "resolve")
end

--- Trust a path: a file, or a directory (which trusts everything under it), in
--- the general table. Returns the absolute path it resolved to.
function M.trust(path)
  return record(trust_tables.general, path)
end

--- Trust a path for *writing* — which implies trusting it, so this records it
--- in both tables. Returns the absolute path it resolved to.
function M.trust_write(path)
  local full = record(trust_tables.write, path)
  record(trust_tables.general, path)
  return full
end

--- May the agent be at this path at all? The general table only — which is what
--- an ask consults, and what a policy asks when the mode bits are not the point.
function M.is_trusted(path)
  return in_one(trust_tables.general, path)
end

--- May the agent *write* here? The write table only — a strictly narrower
--- question, which is why it is a separate reader.
function M.is_write_trusted(path)
  return in_one(trust_tables.write, path)
end

--- Stop trusting a path, in both tables. `true` when either had it.
function M.forget(path)
  local hit = drop(trust_tables.general, path)
  return drop(trust_tables.write, path) or hit
end

--- Stop trusting a path as a write, leaving the general trust alone: the narrow
--- revocation. (A path trusted with `trust_write` keeps its general entry,
--- because it was given both.)
function M.forget_write(path)
  return drop(trust_tables.write, path)
end

--- The general table, listed: `{ { path = ..., dir = ... }, … }`, sorted. The
--- tables stay private, so nothing can corrupt them behind `trust`'s back.
function M.trusted_paths()
  return listing(trust_tables.general)
end

--- The write table, listed: `{ { path = ..., dir = ... }, … }`, sorted.
function M.trusted_write_paths()
  return listing(trust_tables.write)
end

--- Forget everything, both tables (a test hook, and an escape hatch).
function M.forget_all()
  for _, into in pairs(trust_tables) do
    for key in pairs(into) do into[key] = nil end
  end
end

-- The verdict wire shape. `agent.deny` (lua/lib/bash.lua) owns it; this is the
-- same one-field table, used only when that is not loaded — so a policy can ask
-- before/without the engine half. Ask at *call* time, never at load time.
-- A nil/empty reason stays nil: the driver treats that as a reasonless denial
-- (`denied_reason = nil`, a bare "Denied" on the panel), exactly like a flat
-- `return false`.
local function denial(reason)
  if reason == nil or reason == "" then
    if type(agent.deny) == "function" then return agent.deny(nil) end
    return { __agent_verdict = "deny" }
  end
  if type(agent.deny) == "function" then return agent.deny(reason) end
  return { __agent_verdict = "deny", reason = reason }
end

M.deny = denial

-- The canonical ask table. A string is the description; a table is used as-is
-- (so a custom handler can carry whatever it likes); `extra` is merged in.
--
-- `always` is the flag that offers the user a *third* answer — "always", beside
-- yes and no — which arrives back as `agent.ask`'s remembering verdict (the
-- path the question carried is recorded, so it is not asked about again in this
-- run). A tool hands it to Rust with `agent.api.ask_user(text, ask.always)`, and
-- the prompt only shows `[a]lways` when it is set: there is nothing to remember
-- without a `path`, so an ask without one must not offer it. `for_syscall` sets
-- it, because it is the ask that has a path.
function M.build(what, extra)
  local ask = {}
  if type(what) == "string" then
    ask.description = what
  elseif type(what) == "table" then
    for k, v in pairs(what) do ask[k] = v end
  else
    error("agent.ask: the question must be a string or a table, got " .. type(what), 3)
  end
  if extra ~= nil then
    if type(extra) ~= "table" then
      error("agent.ask: extra must be a table, got " .. type(extra), 3)
    end
    for k, v in pairs(extra) do ask[k] = v end
  end
  if type(ask.description) ~= "string" or ask.description == "" then
    error("agent.ask: the ask needs a non-empty 'description'", 3)
  end
  return ask
end

-- Normalize any answer into `allowed, reason`. Accepts exactly what the driver
-- accepts — a boolean or a verdict object — and names the ask when it does not,
-- so the failure reads as "the handler answered this question wrongly" rather
-- than "policy callback returned a table".
function M.of(verdict, question)
  local what = question or "the ask"
  if type(verdict) == "boolean" then
    -- A bare `false` carries no reason — it was not given one, so do not
    -- invent one. `ask.drive`'s default handler, which *does* know why, sends an
    -- explicit denial instead.
    return verdict, nil
  end
  if type(verdict) == "table" then
    if verdict.__agent_verdict == "allow" then return true, nil end
    if verdict.__agent_verdict == "deny" then
      local reason = verdict.reason
      if type(reason) ~= "string" or reason == "" then return false, nil end
      return false, reason
    end
  end
  error("agent.ask: " .. what .. " was answered with a " .. type(verdict) ..
        ", expected a boolean or agent.allow()/agent.deny(reason)", 2)
end

-- Just the yes/no of an answer.
function M.denied(verdict)
  return not (M.of(verdict))
end

-- The reason a denial carried, or nil.
function M.reason(verdict)
  local _, reason = M.of(verdict)
  return reason
end

-- The canonical ask for a syscall decision — a table, which is what `M.build`
-- takes, so `ask(ask.for_syscall(sys, "write", flags))` is the whole call:
--
--   { description = "openat (pid 42) requests write: O_RDWR|O_CREAT [cat > f]",
--     path        = "f" }
--
-- The caller's own /proc cmdline rides along in the description, so the user
-- sees *who* is asking and not just what.
--
-- `path` is what makes the ask *matchable*: `ask` answers it from the trust
-- tables instead of putting the question to the user. It is the path the tracee
-- passed, which may be relative — and both sides of a trust comparison resolve
-- it the same way (against the working directory), so trusting `/srv/app` covers
-- a tracee that opened `app/x` from there.
--
-- `always` is set, because there is a path here to remember: the user is
-- offered `[a]lways` beside yes and no, and choosing it records this path for
-- the rest of the run. Set `a.always = false` on the returned table to ask a
-- plain yes/no question instead.
function M.for_syscall(sys, what, detail)
  if type(sys) ~= "table" or type(sys.name) ~= "string" then
    error("agent.ask.for_syscall: expected the syscall table", 2)
  end
  if type(what) ~= "string" or what == "" then
    error("agent.ask.for_syscall: 'what' must be a non-empty string", 2)
  end
  local text = string.format("%s (pid %d) requests %s", sys.name, sys.pid or 0, what)
  if type(detail) == "string" and detail ~= "" then
    text = text .. ": " .. detail
  end
  local cmdline = sys.cmdline
  if type(cmdline) == "string" and cmdline ~= "" then
    text = text .. " [" .. cmdline .. "]"
  end
  return { description = text, path = sc_path(sys), always = true }
end

-- Raise an ask, unconditionally, and hand back the raw verdict. This is the
-- wire half of the ask protocol, kept separate so a caller can decide for
-- itself whether the question is worth asking: `ask()` short-circuits on a
-- trusted path, and `ask_trust_write()` must not, because "may I write here" is
-- a narrower question than "may I be here".
--
-- Must be called from inside a coroutine: one `agent.bash` creates for a policy
-- callback, or one `ask.drive_tool` creates for a tool callback. Anywhere else
-- the yield is refused and this says so.
local function raise_ask(ask)
  -- LuaJIT lets a yield cross a pcall boundary, so wrapping it buys a clear
  -- error for the "asked from the wrong context" case.
  local ok, verdict = pcall(coroutine.yield, ask)
  if not ok then
    error("agent.ask: cannot ask from here — an ask needs the coroutine " ..
          "`agent.bash` runs a policy callback in, or the agent's `ToolRun` " ..
          "runs a tool callback in. " .. tostring(verdict), 2)
  end
  return verdict
end

-- ==========================================================================
-- The trustworthy-server table
-- ==========================================================================
--
-- Paths answer "may the agent touch this file". A *server* answers a different
-- question — "may the agent **reach** this endpoint" — and it is deliberately a
-- separate table rather than a path-shaped entry, because the two must not be
-- confusable: a trusted file is not a trusted network peer, and forgetting one
-- must never forget the other.
--
-- A server is keyed by the name the *user was shown*. The policy names an
-- endpoint by its reverse-resolved hostname when it has one and by its address
-- otherwise, and that string is what a "always" records — so a trust decision
-- matches what the user actually read on screen. A hostname entry covers every
-- port on that host (a port is a service, not a host); a `host:port` entry
-- covers only that port. The narrower reading is always the one that was asked
-- about, and the broader one has to be granted on its own.
local server_tables = { trusted = {} }

-- Normalize a host the way a question would have shown it: case is not
-- significant in a hostname, and an IPv6 literal arrives bracketed once a port
-- is appended to it.
local function server_host(host)
  if type(host) ~= "string" or host == "" then
    error("agent.ask.trust_server: host must be a non-empty string, got " ..
          type(host), 3)
  end
  local h = host:gsub("^%[", ""):gsub("%]$", "")
  return (h:lower())
end

-- A port is a number, or nil for "every port on this host". A numeric string is
-- accepted because it is what a policy has when it read one off the wire.
local function server_port(port)
  if port == nil or port == "" then return nil end
  local n = tonumber(port)
  if n == nil or n % 1 ~= 0 or n < 0 or n > 65535 then
    error("agent.ask.trust_server: port must be an integer 0-65535 or nil, got " ..
          tostring(port), 3)
  end
  return n
end

-- The table key. An IPv6 host is bracketed when a port is part of it, so
-- `::1` and `[::1]:80` cannot collide.
local function server_key(host, port)
  if port == nil then return host end
  if host:find(":", 1, true) then return "[" .. host .. "]:" .. port end
  return host .. ":" .. port
end

--- Trust a server: a host (every port) or one `host:port`. Returns the key it
--- was recorded under, so a caller can see what it actually trusted.
function M.trust_server(host, port)
  local h, p = server_host(host), server_port(port)
  local key = server_key(h, p)
  server_tables.trusted[key] = { host = h, port = p }
  return key
end

--- May the agent reach this server? A `host:port` entry is an exact match; a
--- host entry (no port) covers every port on that host. Nothing else counts:
--- a different host, or a different port with no host-wide entry, is not trusted.
function M.is_server_trusted(host, port)
  if type(host) ~= "string" or host == "" then return false end
  local h, p = server_host(host), server_port(port)
  if p ~= nil and server_tables.trusted[server_key(h, p)] then return true end
  -- A host-wide entry, and only a host-wide one, covers a port that was not
  -- named: the broad grant has to have been made on its own. Asked about a host
  -- with no port at all, only a host-wide entry counts — never "trivially yes",
  -- which would make an endpoint the engine could not read trusted by accident.
  return server_tables.trusted[h] ~= nil
end

--- Stop trusting a server. With no port, every entry for that host goes (both
--- the host-wide grant and each named port). `true` when anything was there.
function M.forget_server(host, port)
  if type(host) ~= "string" or host == "" then return false end
  local h, p = server_host(host), server_port(port)
  local hit = false
  if p == nil then
    -- Every entry for this host, at any port.
    for key, entry in pairs(server_tables.trusted) do
      if entry.host == h then
        server_tables.trusted[key] = nil
        hit = true
      end
    end
    return hit
  end
  local key = server_key(h, p)
  if server_tables.trusted[key] then
    server_tables.trusted[key] = nil
    hit = true
  end
  -- A host-wide grant still stands, and it still covers this port: forget the
  -- port so the user can see why, rather than silently under-trusting.
  if server_tables.trusted[h] then
    server_tables.trusted[server_key(h, p)] =
        { host = h, port = p, covered_by = h }
    hit = true
  end
  return hit
end

--- The trustworthy servers, listed: `{ { host = ..., port = ...|nil }, ... }`,
--- sorted by key. The tables stay private, so nothing can corrupt them behind
--- `trust_server`'s back — the same shape as the path tables.
function M.trusted_servers()
  local out = {}
  for _, entry in pairs(server_tables.trusted) do
    out[#out + 1] = { host = entry.host, port = entry.port,
                      covered_by = entry.covered_by }
  end
  table.sort(out, function(a, b)
    return server_key(a.host, a.port) < server_key(b.host, b.port)
  end)
  return out
end

--- May the agent reach this server? Already trusted, it is allowed silently.
--- Otherwise the question is asked with `[a]lways` on offer, and the server is
--- remembered **only** on "always" — a plain yes allows this one connection,
--- which is the whole difference between the three answers.
---
--- `msg` is the question (a default naming the endpoint is used when it is
--- missing). Returns `true`, or a denial carrying its reason — so a policy can
--- `return` it straight from a callback, exactly like `ask_trust_write`.
function M.ask_server(host, port, msg)
  if type(host) ~= "string" or host == "" then
    error("agent.ask.ask_server: host must be a non-empty string, got " ..
          type(host), 2)
  end
  local h, p = server_host(host), server_port(port)
  if M.is_server_trusted(h, p) then return true end
  local text = msg
  if type(text) ~= "string" or text == "" then
    text = "allow connecting to " .. (p and (h .. ":" .. p) or h)
  end
  -- `always` is on offer: there is a server here, and remembering it is what the
  -- third answer means.
  local verdict = raise_ask(M.build({ description = text, always = true }))
  local allowed, reason = M.of(verdict, text)
  if not allowed then return denial(reason) end
  if type(verdict) == "table" and verdict.trust then
    M.trust_server(h, p)
  end
  return true
end

--- Forget every trusted server, without touching the path tables: a server trust
--- and a file trust are separate decisions and are withdrawn separately.
function M.forget_all_servers()
  for key in pairs(server_tables.trusted) do server_tables.trusted[key] = nil end
end

-- Ask the user. Yields the ask table and returns the verdict the driver
-- accepts: `true`, or a denial carrying its reason.
--
-- Must be called from inside a policy callback — see `raise_ask`.
function M.ask(what, extra)
  local ask = M.build(what, extra)
  -- A trusted path answers itself: the user has already vouched for it, in this
  -- config or in an earlier question this same run asked them. Write-trust
  -- counts — it implies the general trust that `trust_write` also records.
  if ask.path and M.is_trusted(ask.path) then return true end
  local verdict = raise_ask(ask)
  -- "Always allow this": the answer carries the instruction to remember, and
  -- the asking side is the only one that knows the path — so the remembering
  -- happens here, where the ask table still has it. A verdict that says to
  -- trust an ask *without* a path has nothing to record, and is just an allow.
  if type(verdict) == "table" and verdict.trust and ask.path then
    pcall(M.trust, ask.path)
  end
  local allowed, reason = M.of(verdict, ask.description)
  if allowed then return true end
  return denial(reason)
end

-- One call for a trust decision: is this path already trusted, and if not, ask.
-- The path is recorded **only when the user answers "always"** — a plain yes is
-- for this time, which is the whole difference between the two answers and the
-- reason this helper offers the third one. `write` picks the table that answers
-- "already" and the one that records: a read is answered by the general table, a
-- write by the write table, and a write is remembered in both (`trust_write`
-- writes both, because writing implies being allowed to touch).
--
-- The ask is raised *unconditionally* once the answer is "not yet trusted", so
-- the write variant really does ask when a path is trusted for reading only.
local function ask_maybe_remember(path, msg, what, write)
  local full = resolve(path, write and "ask_trust_write" or "ask_trust_read")
  -- Which table answers is the whole difference between the two questions, so
  -- this is an if and not `write and a or b`: with the `and/or` idiom a *write*
  -- whose path is not write-trusted fell through to the general table and was
  -- allowed on read-trust alone — the opposite of what `ask_trust_write` says
  -- ("a path trusted for reading is still asked about"), and it made
  -- `forget_write` a no-op for the question it exists to revoke.
  local already
  if write then
    already = M.is_write_trusted(full)
  else
    already = M.is_trusted(full)
  end
  if already then return true end
  local text = msg
  if type(text) ~= "string" or text == "" then
    text = (write and "allow writing " or "allow reading ") .. full
  end
  -- `always` is on offer: there is a path here, and remembering it is what the
  -- third answer means.
  local ask = M.build({ description = text, path = full, always = true })
  local verdict = raise_ask(ask)
  local allowed, reason = M.of(verdict, text)
  if not allowed then return denial(reason) end
  if type(verdict) == "table" and verdict.trust then
    if write then
      M.trust_write(full)
    else
      M.trust(full)
    end
  end
  return true
end

--- May the agent read this path? Already trusted, it is allowed silently.
--- Otherwise the question is asked with `[y]es  [n]o  [a]lways` on offer, and the
--- path is remembered **only** on "always" — a plain yes allows this once, which
--- is the whole difference between the three answers. `path` may be relative or
--- start with `~`; `msg` is the question (a default naming the path is used when
--- it is missing). Returns `true`, or a denial carrying its reason — so a
--- policy can `return` it straight from a callback, exactly like `ask`.
function M.ask_trust_read(path, msg)
  return ask_maybe_remember(path, msg, "reading", false)
end

--- The same, for *writing* — a narrower question, so a path trusted for reading
--- is still asked about. An "always" here is remembered as write-trust, in both
--- tables, and can be taken back on its own with `forget_write`.
function M.ask_trust_write(path, msg)
  return ask_maybe_remember(path, msg, "writing", true)
end

-- Drive a stream to completion, answering its asks. Without a handler an
-- unanswered ask is a self-describing denial rather than the mid-run exception
-- `s:run()` raises (see the header).
function M.drive(stream, handler)
  if type(stream) ~= "table" or type(stream.run) ~= "function" then
    error("agent.ask.drive: expected a stream object from agent.bash", 2)
  end
  if handler == nil then
    handler = function(ask_table)
      local question = (type(ask_table) == "table" and ask_table.description)
                       or tostring(ask_table)
      return denial("no ask handler: " .. question)
    end
  elseif type(handler) ~= "function" then
    error("agent.ask.drive: handler must be a function or nil, got " ..
          type(handler), 2)
  end
  return stream:run(handler)
end

-- --------------------------------------------------------------------------
-- The lib-module convention: publish on `agent` as a *callable* table, so
-- `agent.ask("question")` is the ask and `agent.ask.of` / `.drive` / `.denied`
-- are its helpers. A plain table would make `agent.ask(...)` a call on a table;
-- a plain function could not carry the helpers (LuaJIT rejects fields on
-- function values) — the same reasoning the MCP tool objects use.
-- --------------------------------------------------------------------------

setmetatable(M, {
  __call = function(_, what, extra)
    return M.ask(what, extra)
  end,
})

agent.ask = M

-- --------------------------------------------------------------------------
-- Self-test: `agent.ask._selftest()` raises on any failure. The pure halves
-- only — the yield itself needs a live sandbox, which the Rust tests drive.
-- --------------------------------------------------------------------------

function M._selftest()
  -- Verdict shapes are literals here, not agent.deny/agent.allow, so the
  -- self-test does not depend on module load order.
  local ok, failure = pcall(function()
    local ALLOW = { __agent_verdict = "allow" }
    local DENY = { __agent_verdict = "deny", reason = "because" }
    local BARE_DENY = { __agent_verdict = "deny" }

    -- build: a string is the description; a table is used as-is; extra merges.
    assert(M.build("q").description == "q")
    assert(M.build({ description = "q", id = 7 }).id == 7)
    assert(M.build({ description = "q" }, { id = 8 }).id == 8)
    assert(not pcall(M.build, nil), "a nil question is refused")
    assert(not pcall(M.build, 42), "a number question is refused")
    assert(not pcall(M.build, {}), "a question with no description is refused")

    -- of: every answer shape the driver accepts, normalized.
    local allowed, reason = M.of(true)
    assert(allowed == true and reason == nil)
    allowed, reason = M.of(ALLOW)
    assert(allowed == true and reason == nil)
    -- The "always allow this" answer is an allow with a flag attached, so `of`
    -- normalizes it like any other allow.
    allowed, reason = M.of({ __agent_verdict = "allow", trust = true })
    assert(allowed == true and reason == nil, "trust is still an allow")
    -- A bare false carries no reason (none was given, and none is invented).
    allowed, reason = M.of(false)
    assert(allowed == false and reason == nil)
    allowed, reason = M.of(DENY)
    assert(allowed == false and reason == "because")
    allowed, reason = M.of(BARE_DENY)               -- a deny with no reason
    assert(allowed == false and reason == nil)
    assert(M.denied(false) and not M.denied(true))
    assert(M.reason(DENY) == "because")
    -- A malformed answer is refused, and the message names the question.
    local bad, err = pcall(M.of, 42, "the write open")
    assert(not bad and tostring(err):find("the write open", 1, true), tostring(err))

    -- for_syscall: the shape the built-in policy used to build by hand. It is
    -- an ask *table*, so it goes straight back into `ask`; its `path` is what a
    -- trust table matches on, and is nil when the syscall carries no path.
    local syscall_ask = M.for_syscall({ name = "openat", pid = 42, cmdline = "cat > x" },
                                      "write", "O_RDWR|O_CREAT")
    assert(syscall_ask.description ==
             "openat (pid 42) requests write: O_RDWR|O_CREAT [cat > x]",
           syscall_ask.description)
    syscall_ask = M.for_syscall({ name = "execve", pid = 7 }, "exec", "/bin/sh")
    assert(syscall_ask.description == "execve (pid 7) requests exec: /bin/sh",
           syscall_ask.description)
    assert(syscall_ask.path == nil, "a syscall with no path string has no path")
    assert(not pcall(M.for_syscall, { name = "x" }, ""))
    -- `always` is the flag that offers the user a third answer, and it rides on
    -- the ask: a question with a path to remember sets it, a plain one does not
    -- (there would be nothing to remember).
    assert(syscall_ask.always == true, "a syscall ask offers always")
    assert(M.build("just a question").always == nil, "a bare ask does not")
    assert(M.build({ description = "q", always = false }).always == false,
           "and a policy can turn it off on an ask that has one")

    ------------------------------------------------------------------ trust
    -- This self-test runs on every VM — at load, and again on demand — so it
    -- leaves the tables exactly as it found them and asserts about its *own*
    -- entries by path rather than by position.
    local kept = #M.trusted_paths()
    local kept_write = #M.trusted_write_paths()

    -- A file: that one path, and nothing else.
    local file = os.tmpname()
    local handle = assert(io.open(file, "w"))
    handle:write("x")
    handle:close()
    local full = M.trust(file)
    assert(full == file, "an absolute path resolves to itself: " .. tostring(full))
    assert(M.is_trusted(file), "the file is trusted")
    assert(not M.is_trusted(file .. ".other"), "and nothing else is")
    assert(#M.trusted_paths() == kept + 1, "one entry added")
    -- Looked up by path, not by index: this self-test also runs on a *configured*
    -- VM (anything may already be trusted — the working directory is, by
    -- `lua/init.lua`), so "the first entry" is not this test's entry.
    local recorded_as_file
    for _, entry in ipairs(M.trusted_paths()) do
      if entry.path == full then recorded_as_file = entry.dir end
    end
    assert(recorded_as_file == false, "recorded as a file")
    assert(not M.is_write_trusted(file), "and it is not write-trust")
    assert(M.forget(file), "forget reports it removed one")
    assert(not M.is_trusted(file), "and it is no longer trusted")
    assert(not M.forget(file), "forgetting twice is not an error")
    os.remove(file)

    -- A directory: its whole subtree, on a `/` boundary.
    assert(M.trust("/tmp") == "/tmp", "/tmp resolves to itself")
    assert(M.is_trusted("/tmp"), "the directory itself")
    assert(M.is_trusted("/tmp/trust-probe/deep/file.txt"), "a file inside it")
    assert(M.is_trusted("/tmp/./a/../b/c.txt"), "a tidied path inside it")
    assert(not M.is_trusted("/tmpfoo"), "but not a sibling sharing the prefix")
    local recorded_as_dir
    for _, entry in ipairs(M.trusted_paths()) do
      if entry.path == "/tmp" then recorded_as_dir = entry.dir end
    end
    assert(recorded_as_dir == true, "recorded as a directory")
    M.forget("/tmp")

    -- The two tables answer two different questions, and each reader reads
    -- exactly one of them. Declared trust is general; write-trust implies it.
    -- (Paths that do not nest, so a trusted directory cannot cover the rest.)
    M.trust("/etc/hostname")
    assert(M.is_trusted("/etc/hostname"), "declared trust: trusted at all")
    assert(not M.is_write_trusted("/etc/hostname"),
           "but not writable — each reader reads one table")
    M.trust_write("/opt/scratch")
    assert(M.is_write_trusted("/opt/scratch"), "write-trust: writable")
    assert(M.is_trusted("/opt/scratch"),
           "and trusted at all, because trust_write writes both tables")
    assert(not M.is_write_trusted("/opt/scratch/under"),
           "and a file is not a subtree, in either table")
    assert(#M.trusted_write_paths() == kept_write + 1,
           "the write table holds one entry more than it did")
    assert(#M.trusted_paths() == kept + 2, "and the general one holds both of those")
    -- The narrow revocation: the write goes, the general trust stays.
    assert(M.forget_write("/opt/scratch"), "forget_write reports the removal")
    assert(not M.is_write_trusted("/opt/scratch"), "no longer writable")
    assert(M.is_trusted("/opt/scratch"), "but still trusted — only the write was")
    -- `forget` takes back both tables at once.
    assert(M.forget("/opt/scratch"), "forget clears the general entry")
    assert(not M.is_trusted("/opt/scratch"), "so nothing trusts it now")
    assert(M.forget("/etc/hostname"), "and the declared one")
    assert(#M.trusted_paths() == kept and #M.trusted_write_paths() == kept_write,
           "both tables are back to what they were")
    -- A trusted *directory* is a subtree, in both tables.
    M.trust_write("/etc")
    assert(M.is_write_trusted("/etc/anything/at/all"), "a write-trusted dir is a subtree")
    assert(M.is_trusted("/etc/anything/at/all"), "and trusted in general, too")
    assert(not M.is_trusted("/etcfoo"), "the boundary still holds")
    assert(M.forget_write("/etc"), "forget_write takes the subtree back")
    assert(not M.is_write_trusted("/etc/anything"), "write-trust is gone")
    assert(M.is_trusted("/etc/anything"), "while the general trust stays")
    M.forget_all()
    -- General trust does not make a path writable.
    M.trust("/opt/read-only")
    assert(not M.is_write_trusted("/opt/read-only"),
           "trusting a path is not trusting a write to it")
    M.forget_all()

    -- Resolution: `~`, a relative path, and `.`/`..` tidied away.
    local home = os.getenv("HOME")
    if type(home) == "string" and home ~= "" then
      M.trust("~")
      assert(M.is_trusted(home), "a tilde resolves to $HOME")
      assert(M.is_trusted("~/."), "and so does a tidied tilde")
      M.forget("~")
    end
    local dir_now = os.getenv("PWD")
    if type(dir_now) == "string" and dir_now ~= "" then
      local here = M.trust("lua")
      assert(here:sub(1, 1) == "/", "a relative path is made absolute: " .. here)
      assert(not here:find("%.%."), "and tidied: " .. here)
      -- A path that is not there is trusted as a single file — the narrow
      -- reading, and what makes "always allow this write" work at all, since
      -- the write being asked about is usually the file's creation.
      assert(M.trust("definitely/not/here") == dir_now .. "/definitely/not/here",
             "a missing path resolves like any other")
      assert(M.is_trusted("definitely/not/here"), "and is trusted")
      assert(not M.is_trusted("definitely/not/here/under"),
             "as a file, not as a subtree")
      M.forget("definitely/not/here")
    end

    -- The composed helpers: a trusted path answers itself, with no question at
    -- all. (That they *ask* otherwise needs a live coroutine, so the Rust tests
    -- drive those through a real sandbox.)
    M.trust("/etc/hostname")
    assert(M.ask_trust_read("/etc/hostname") == true, "a trusted read is silent")
    assert(not pcall(M.ask_trust_read, ""), "and a bad path is still refused")
    assert(not pcall(M.ask_trust_write, 42), "the write helper refuses it too")
    -- A read-answered path is not write-answered — which is the whole difference
    -- between the two helpers, and the reason the write one asks anyway.
    assert(M.is_trusted("/etc/hostname") and not M.is_write_trusted("/etc/hostname"),
           "declared trust is not write trust")
    -- Asking from outside a policy callback is refused, exactly as `ask` is.
    assert(not pcall(M.ask_trust_write, "/etc/hosts", "write it?"),
           "an ask outside a policy callback is refused")
    M.forget("/etc/hostname")

    -- The composed helpers, driven the way a policy callback drives them: a
    -- coroutine, resumed with the user's answer. Allowed remembers (and the
    -- next call is silent); refused remembers nothing (so it asks again).
    local function ask_once(fn, verdict)
      local raised, verdict_out = nil, nil
      local co = coroutine.create(fn)
      local ok, value = coroutine.resume(co)
      assert(ok, "the helper ran: " .. tostring(value))
      assert(coroutine.status(co) == "suspended", "it asked: " .. tostring(value))
      raised = value
      local done, result = coroutine.resume(co, verdict)
      assert(done, "the helper returned: " .. tostring(result))
      assert(coroutine.status(co) == "dead", "and finished")
      return raised, result
    end

    M.forget_all()
    -- A plain yes allows this once and remembers nothing: the difference
    -- between "yes" and "always" is the whole point of the third answer.
    local asked, verdict = ask_once(function()
      return M.ask_trust_write("/opt/selftest", "may I write there?")
    end, true)
    assert(asked.description == "may I write there?", "the message is the question")
    assert(asked.path == "/opt/selftest", "and the ask carries the resolved path")
    assert(asked.always == true, "and it offers always — there is a path to remember")
    assert(verdict == true, "an allow is an allow")
    assert(not M.is_write_trusted("/opt/selftest"),
           "but a plain yes is for this time only")
    assert(not M.is_trusted("/opt/selftest"), "in either table")

    -- "Always" allows and remembers — write-trust, which implies the general.
    local _, remembered = ask_once(function()
      return M.ask_trust_write("/opt/selftest", "may I write there?")
    end, { __agent_verdict = "allow", trust = true })
    assert(remembered == true, "always is an allow")
    assert(M.is_write_trusted("/opt/selftest"), "and is remembered as write-trust")
    assert(M.is_trusted("/opt/selftest"), "which implies the general trust too")
    -- Remembered means silent: no question this time, and no coroutine at all.
    assert(M.ask_trust_write("/opt/selftest", "again?") == true,
           "a remembered write does not ask")
    M.forget_all()

    -- A default message when none is given, naming the path. An "always" here
    -- is remembered as general trust, not write-trust.
    local asked_default = ask_once(function()
      return M.ask_trust_read("/opt/selftest-read")
    end, { __agent_verdict = "allow", trust = true })
    assert(asked_default.description == "allow reading /opt/selftest-read",
           "a default message names the path: " .. asked_default.description)
    assert(M.is_trusted("/opt/selftest-read"), "an always is remembered as trust")
    assert(not M.is_write_trusted("/opt/selftest-read"),
           "and not as write-trust")

    -- Refused: nothing is remembered either, so the same question is asked
    -- again — a denial that stuck would be a hole, not a convenience.
    local _, denied = ask_once(function()
      return M.ask_trust_read("/opt/selftest-refused", "may I?")
    end, false)
    assert(M.denied(denied), "a refusal is a denial: " .. tostring(type(denied)))
    assert(not M.is_trusted("/opt/selftest-refused"), "and nothing was remembered")
    local asked_again = ask_once(function()
      return M.ask_trust_read("/opt/selftest-refused", "may I?")
    end, true)
    assert(asked_again.description == "may I?", "so the same question is asked again")
    M.forget_all()

    -- `resolve` is the path both sides of a comparison agree on.
    local dir_now = os.getenv("PWD")
    if type(dir_now) == "string" and dir_now ~= "" then
      assert(M.resolve("lua") == dir_now .. "/lua", "a relative path resolves")
      assert(M.resolve("lua/./lib/../fs.lua") == dir_now .. "/lua/fs.lua",
             "and tidies")
      assert(M.resolve("/already/absolute") == "/already/absolute", "absolute stays")
      assert(not pcall(M.resolve, ""), "an empty path cannot be resolved")
    end

    -- The trustworthy-server table: exact port, host-wide coverage, and the
    -- narrow reading everywhere else.
    M.forget_all_servers()
    assert(not M.is_server_trusted("example.com", 80), "nothing is trusted yet")
    M.trust_server("Example.COM", 443)
    assert(M.is_server_trusted("example.com", 443), "case is not significant")
    assert(M.is_server_trusted("EXAMPLE.com", 443), "nor is the host's spelling")
    assert(not M.is_server_trusted("example.com", 80),
           "a named port does not trust another port")
    assert(not M.is_server_trusted("example.org", 443),
           "nor does it trust another host")
    -- A host-wide grant covers every port, and only because it was made.
    assert(not M.is_server_trusted("example.com"),
           "a host with no port is not trusted by a port-only entry")
    M.trust_server("api.internal")
    assert(M.is_server_trusted("api.internal", 1), "a host grant covers a low port")
    assert(M.is_server_trusted("api.internal", 9999), "and a high one")
    assert(M.is_server_trusted("api.internal"),
           "and the host itself, which is what the entry was for")
    -- An IPv6 literal is bracketed once a port is part of the key, so the two
    -- forms cannot collide.
    M.trust_server("::1", 8080)
    assert(M.is_server_trusted("::1", 8080), "an IPv6 host:port entry")
    assert(not M.is_server_trusted("[::1]", 9090), "and not another port")
    -- The listing is sorted, and a port forgotten under a host-wide grant is
    -- recorded as still covered — so the user can see why.
    local listed = M.trusted_servers()
    for i = 2, #listed do
      assert(listed[i - 1].host <= listed[i].host, "the listing is sorted")
    end
    assert(not M.is_server_trusted("unreadable-endpoint"),
           "an endpoint nothing was recorded for is not trusted")
    assert(M.forget_server("api.internal"), "a host can be forgotten")
    assert(not M.is_server_trusted("api.internal", 80), "and then it is untrusted")
    assert(M.forget_server("example.com", 443), "a host:port can be forgotten")
    assert(not M.is_server_trusted("example.com", 443), "and then it is untrusted")
    assert(not M.forget_server("example.com", 443), "forgetting twice reports false")
    -- Refusals: an empty host, and a port that is not a port.
    assert(not pcall(M.trust_server, ""), "an empty host is refused")
    assert(not pcall(M.trust_server, "h", 70000), "an out-of-range port is refused")
    assert(not pcall(M.trust_server, "h", "http"), "a non-numeric port is refused")
    M.forget_all_servers()
    assert(#M.trusted_servers() == 0, "and forget_all_servers empties the table")

    -- Refusals, and the empty-path cases that must never match.
    assert(not pcall(M.trust, ""), "an empty path is refused")
    assert(not pcall(M.trust, 42), "a non-string path is refused")
    assert(not pcall(M.trust, nil), "a nil path is refused")
    assert(not pcall(M.trust_write, ""), "and the write table refuses it too")
    assert(not M.is_trusted(""), "an empty path is never trusted")
    assert(not M.is_write_trusted(""), "nor write-trusted")
  end)

  -- The trust tables are per-VM state, so clean them up either way: a failure
  -- must not leave paths trusted for whatever runs next.
  M.forget_all()
  if not ok then error(failure, 0) end
  return true
end

return M
